defmodule Triage.Cases do
  @moduledoc """
  Local case management over the read-only scanner inventory.

  A case is opened explicitly from one finding occurrence within one explicit
  owner + environment scope. Evidence is captured into append-only frozen
  snapshots, reviews are recorded with optimistic case-revision binding, and
  every operation appends a server-generated audit event.

  This is the local, synthetic-data demo slice: the actor is always the
  server-owned literal `local-operator`; nothing here contacts a security API,
  and no operation writes to inventory tables. Saving a review never
  activates suppression or claims remediation.

  Inventory stays untouched: `Triage.Inventory.fetch_finding/2` is the single
  active AND-scope gate, and its private `normalize/1` semantics are mirrored
  locally here (valid UTF-8, no NUL/C0/DEL on the raw binary) rather than
  refactored or exported.
  """

  import Ecto.Query
  alias Ecto.Changeset
  alias Triage.Cases.{CaseEvent, EvidenceSnapshot, Review, ReviewCase}
  alias Triage.Inventory
  alias Triage.Repo

  @actor "local-operator"
  @payload_source "synthetic_local_inventory"
  @payload_schema_version 1

  # Deterministic content hashing: fixed domain markers plus a canonical
  # encoder (sorted maps, length-tagged scalars) — never Jason map iteration
  # order and never unchecked string concatenation of untrusted delimiters.
  @hash_domain "triage.cases.evidence.v1"
  @request_hash_domain "triage.cases.review_request.v1"

  # Scope rules for cases are stricter than display filters: both owner and
  # environment must be explicit nonblank scalar strings (blank is the
  # intentional All/unscoped state and is NOT a review scope), raw valid
  # UTF-8, no NUL/C0/DEL even where trimming would remove them, and at most
  # 120 characters after trimming.
  @unsafe_scope ~r/[\x00-\x1F\x7F]/
  @scope_max 120
  @scope_absence "all"

  # int8 max is exactly 2^63 - 1: every integer is checked against positive
  # bigint bounds before any query, mirroring Inventory's id guard.
  @max_id Integer.pow(2, 63) - 1

  @event_kinds ~w(case_opened evidence_captured review_saved)

  @coverage %{
    "kind" => "local_synthetic_only",
    "warning" =>
      "Evidence was captured from the local synthetic inventory only. " <>
        "Production coverage is unknown and this snapshot is not a completeness assertion."
  }

  @doc """
  Opens — or converges on — the case for one finding occurrence in an
  explicit scope.

  Returns `{:ok, %{case: case, snapshot: snapshot, created?: boolean}}` or
  `{:error, :invalid_scope | :out_of_scope | :not_found | :invalid_request}`.

  Requires both `owner` and `environment` as explicit nonblank scope strings;
  the source must currently have an active placement in that exact scope
  (`Inventory.fetch_finding/2` is the AND-gate). Concurrent or repeated opens
  converge on one case, its initial snapshot and its opening event: opening an
  existing case never refreshes evidence or erases review history. A committed
  case is never exposed without its snapshot — the temporary NULL
  `current_snapshot_id` pointer lives only inside the atomic creation
  transaction.
  """
  def open_case(finding_id, opts) do
    with {:ok, scope} <- scope_from_opts(opts),
         :ok <- validate_id(finding_id),
         {:ok, data} <- fetch_scoped(finding_id, scope) do
      create_or_join_case(finding_id, scope, data)
    end
  end

  @doc """
  Loads one case with its current snapshot, full history and derived status.

  Returns
  `{:ok, %{case: case, snapshot: snapshot, snapshots: snapshots, reviews: reviews, events: events, evidence_status: status}}`
  or `{:error, :not_found | :invalid_request}`.

  This is a pure read: nothing is created or refreshed. `status` is derived
  read-only against the current scoped local inventory:

    * `:current` — source content matches the current snapshot hash
    * `:changed` — source content changed since the current snapshot
    * `:source_out_of_scope` — no active placement remains in the case scope
    * `:source_missing` — the source finding no longer exists

  History stays readable when a scoped placement retires; only new opens,
  refreshes and submissions fail closed.
  """
  def get_case(case_id) do
    with :ok <- validate_id(case_id),
         %ReviewCase{} = cse <- Repo.get(ReviewCase, case_id) do
      snapshots = list_snapshots(case_id)

      reviews =
        Repo.all(
          from r in Review,
            where: r.case_id == ^case_id,
            order_by: [asc: r.inserted_at, asc: r.id]
        )

      events =
        Repo.all(
          from e in CaseEvent,
            where: e.case_id == ^case_id,
            order_by: [asc: e.inserted_at, asc: e.id]
        )

      current = Enum.find(snapshots, &(&1.id == cse.current_snapshot_id))

      {:ok,
       %{
         case: cse,
         snapshot: current,
         snapshots: snapshots,
         reviews: reviews,
         events: events,
         evidence_status: evidence_status(cse, current)
       }}
    else
      {:error, :invalid_request} = invalid -> invalid
      nil -> {:error, :not_found}
    end
  end

  # PR 3 read-only Review Queue. Fixed page size; one extra sentinel row
  # decides has_more?. The read-side scope validator is deliberately NOT the
  # strict write validate_scope/1: blank means the All/unrestricted filter and
  # a team literally named "all" is an ordinary team name here.
  @queue_page_size 25
  @queue_fetch_limit @queue_page_size + 1
  @queue_opt_keys [:owner, :environment, :before_id]

  @doc """
  Lists saved review cases for the read-only queue, newest opened first.

  Returns `{:ok, %{rows: rows, has_more?: boolean, next_before_id: id | nil}}`
  or `{:error, :invalid_request | :invalid_scope | :queue_unavailable}`.

  `opts` is a keyword list accepting only the optional `:owner`,
  `:environment` and `:before_id` keys; every other request shape (non-lists,
  non-keyword lists, maps, structs, unknown or duplicate keys) is rejected
  with `{:error, :invalid_request}` before any query. Scope values are
  nil/blank-after-trim (no restriction) or a plain valid-UTF-8 binary with
  no raw NUL/C0/DEL and at most 120 characters after trimming; anything else
  is `{:error, :invalid_scope}` before any query. `before_id` is nil or a
  positive bigint cursor; no coercion of floats, booleans or strings.

  Rows are plain projection maps: case identity, frozen finding/image
  display text from the current snapshot payload, current snapshot metadata,
  the latest review by `(inserted_at DESC, id DESC)` and the two derived
  status axes. Idempotency tokens, request hashes, full histories and
  rationales never reach the queue. `review_cases` has no reliable
  last-activity clock, so order is strictly case `id DESC` ("newest opened
  first"). Pure read: no locks, no writes, no changesets; a read or assembly
  failure surfaces as `{:error, :queue_unavailable}`, never as a
  trustworthy-looking status.
  """
  def list_cases(opts \\ []) do
    with {:ok, queue_opts} <- validate_queue_opts(opts) do
      queue_load(queue_opts)
    end
  end

  @doc """
  Batched saved-case state for advisory action rows, using the queue's existing
  source/evidence comparison. Does not open cases or change scanner inventory.
  Only positive bigint finding IDs are accepted; empty input performs no query.
  """
  def states_for_findings([]), do: []

  def states_for_findings(finding_ids) when is_list(finding_ids) do
    if Enum.all?(finding_ids, &(is_integer(&1) and &1 > 0 and &1 <= @max_id)) do
      Repo.all(
        from c in ReviewCase,
          where: c.finding_id in ^finding_ids,
          left_join: s in EvidenceSnapshot,
          on: s.id == c.current_snapshot_id,
          select: {c, s, nil}
      )
      |> queue_rows()
    else
      raise ArgumentError, "finding ids must be positive bigints"
    end
  end

  @doc """
  Sorted distinct nonblank owner and environment values from saved cases.

  Queue filter options come from `review_cases` only — independent of the
  current active inventory — so retired teams and environments remain
  selectable. Pure read; no status counters.
  """
  def case_filter_options do
    %{
      owners: distinct_nonblank_scopes(ReviewCase, :owner),
      environments: distinct_nonblank_scopes(ReviewCase, :environment)
    }
  end

  @doc """
  Validation changeset for the four manual review fields.

  Normal Ecto/Phoenix form handling: forged actor/case/scope/hash keys in
  `attrs` are ignored, never cast. Only string-keyed maps are accepted: any
  other attrs shape (list, keyword list, nil, binary, atom/mixed-key map)
  returns the documented changeset shape marked invalid with a form-level
  error instead of raising.
  """
  def change_review(attrs \\ %{}) do
    case manual_changeset(attrs) do
      {:ok, changeset} ->
        changeset

      {:error, :invalid_request} ->
        # Malformed attrs shapes (lists, keyword lists, nil, binaries, structs
        # or atom/mixed-key maps) keep the documented changeset return shape,
        # marked invalid with a form-level error instead of raising
        # Ecto.CastError. Decision: the public contract documents a changeset
        # return, so the shape is kept rather than switching to a tuple.
        Review.changeset(%Review{}, %{})
        |> Changeset.add_error(
          :rationale,
          "malformed request: manual review parameters must be a string-keyed map"
        )
    end
  end

  @doc """
  Records one manual review of one case against one frozen snapshot.

  Returns `{:ok, %{case: case, review: review, replayed?: boolean}}`,
  `{:error, :conflict | :evidence_stale | :source_out_of_scope | :not_found | :invalid_request | :token_reuse}`
  or `{:error, changeset}`.

  Runs inside one row-locked transaction with this exact ordering: validate
  request shape, find the case, inspect the existing token first (an exact
  retry — same token, same normalized manual payload and same original
  revision/snapshot binding — returns the original review with no writes,
  even after later revisions; a reused token with different content or
  binding returns `:token_reuse` and never silently replays), then check
  expected revision and same-case current snapshot, then recompute the source
  fingerprint and active scope, and only then insert review + bump revision +
  append event atomically. A failure in the final event insert rolls the
  review and revision back with it.
  """
  def submit_review(case_id, expected_revision, expected_snapshot_id, idempotency_token, attrs) do
    with :ok <- validate_id(case_id),
         :ok <- validate_positive_integer(expected_revision),
         :ok <- validate_id(expected_snapshot_id),
         {:ok, token} <- validate_token(idempotency_token),
         {:ok, changeset} <- manual_changeset(attrs),
         :ok <- ensure_valid(changeset) do
      save_review(case_id, expected_revision, expected_snapshot_id, token, changeset)
    else
      {:error, :invalid_request} = invalid -> invalid
      {:error, %Changeset{} = changeset} -> {:error, changeset}
    end
  end

  @doc """
  Explicitly recaptures evidence for one case.

  Returns `{:ok, %{case: case, snapshot: snapshot, changed?: boolean}}` or
  `{:error, :conflict | :source_out_of_scope | :not_found | :invalid_request}`.

  Unchanged content causes no new snapshot, event or revision. Changed content
  appends a snapshot and an `evidence_captured` event and increments the case
  revision atomically; older evidence and reviews are never modified. A case
  whose scoped placement retired returns `:source_out_of_scope` without
  taking an unscoped snapshot.
  """
  def refresh_evidence(case_id, expected_revision, expected_snapshot_id) do
    with :ok <- validate_id(case_id),
         :ok <- validate_positive_integer(expected_revision),
         :ok <- validate_id(expected_snapshot_id),
         %ReviewCase{} <- Repo.get(ReviewCase, case_id) do
      recapture(case_id, expected_revision, expected_snapshot_id)
    else
      {:error, :invalid_request} = invalid -> invalid
      nil -> {:error, :not_found}
    end
  end

  ## Open

  defp create_or_join_case(finding_id, %{owner: owner, environment: environment}, data) do
    Repo.transaction(fn ->
      {:ok, inserted} =
        %ReviewCase{finding_id: finding_id, owner: owner, environment: environment, revision: 1}
        |> Repo.insert(
          on_conflict: :nothing,
          conflict_target: [:finding_id, :owner, :environment],
          returning: true
        )

      case inserted do
        # Lost the create race: converge on the winner's case without
        # refreshing its evidence or touching its history.
        %ReviewCase{id: nil} ->
          existing = find_case!(finding_id, owner, environment)
          {existing, current_snapshot!(existing), false}

        %ReviewCase{} = created ->
          {built, hash} = build_snapshot(created, data)
          snapshot = insert_snapshot!(created, built, hash, 1)

          append_event!(created, "case_opened", 1,
            snapshot_id: snapshot.id,
            detail: %{"finding_id" => finding_id}
          )

          created =
            created
            |> Changeset.change(current_snapshot_id: snapshot.id)
            |> Repo.update!()

          {created, snapshot, true}
      end
    end)
    |> case do
      {:ok, {cse, snapshot, created?}} ->
        {:ok, %{case: cse, snapshot: snapshot, created?: created?}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp find_case!(finding_id, owner, environment) do
    Repo.one!(
      from c in ReviewCase,
        where: c.finding_id == ^finding_id and c.owner == ^owner and c.environment == ^environment
    )
  end

  ## Submit

  defp save_review(case_id, expected_revision, expected_snapshot_id, token, changeset) do
    manual = manual_payload(changeset)
    request_hash = request_hash(manual, expected_revision, expected_snapshot_id)

    case Repo.get(ReviewCase, case_id) do
      nil ->
        {:error, :not_found}

      %ReviewCase{} ->
        Repo.transaction(fn ->
          cse = lock_case!(case_id)

          case Repo.one(
                 from r in Review,
                   where: r.case_id == ^case_id and r.idempotency_token == ^token
               ) do
            %Review{} = replay ->
              # Token inspection comes first: an exact retry of the same
              # normalized payload against the original binding replays the
              # stored review with no writes at all.
              if replay.request_hash == request_hash and
                   replay.expected_revision == expected_revision and
                   replay.snapshot_id == expected_snapshot_id do
                {cse, replay, true}
              else
                Repo.rollback(:token_reuse)
              end

            nil ->
              save_new_review(
                cse,
                manual,
                request_hash,
                expected_revision,
                expected_snapshot_id,
                token
              )
          end
        end)
        |> case do
          {:ok, {cse, review, replayed?}} ->
            {:ok, %{case: cse, review: review, replayed?: replayed?}}

          # Unique (case_id, idempotency_token) backup for a lost race: the
          # same token can only ever mean reuse, never a second review.
          {:error, %Postgrex.Error{postgres: %{code: :unique_violation}}} ->
            {:error, :token_reuse}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp save_new_review(cse, manual, request_hash, expected_revision, expected_snapshot_id, token) do
    if cse.revision != expected_revision do
      Repo.rollback(:conflict)
    else
      if cse.current_snapshot_id != expected_snapshot_id do
        Repo.rollback(:evidence_stale)
      else
        case fetch_finding_for_case(cse) do
          :missing ->
            Repo.rollback(:source_out_of_scope)

          :out_of_scope ->
            Repo.rollback(:source_out_of_scope)

          {:ok, data} ->
            {_built, hash} = build_snapshot(cse, data)

            if hash != current_snapshot!(cse).payload_hash do
              # Source content drifted from the expected snapshot: recapture
              # before recording an assessment against stale evidence.
              Repo.rollback(:evidence_stale)
            else
              review =
                %Review{}
                |> Changeset.change(
                  case_id: cse.id,
                  snapshot_id: expected_snapshot_id,
                  expected_revision: expected_revision,
                  idempotency_token: token,
                  request_hash: request_hash,
                  actor: @actor,
                  applicability: manual["applicability"],
                  priority: manual["priority"],
                  next_action: manual["next_action"],
                  rationale: manual["rationale"]
                )
                |> Repo.insert!()

              bump_revision!(cse)

              append_review_saved_event!(cse, expected_snapshot_id, review, manual)

              {Repo.get!(ReviewCase, cse.id), review, false}
            end
        end
      end
    end
  end

  ## Refresh

  defp recapture(case_id, expected_revision, expected_snapshot_id) do
    Repo.transaction(fn ->
      cse = lock_case!(case_id)

      if cse.revision != expected_revision do
        Repo.rollback(:conflict)
      else
        if cse.current_snapshot_id != expected_snapshot_id do
          Repo.rollback(:conflict)
        else
          case fetch_finding_for_case(cse) do
            :missing ->
              Repo.rollback(:source_out_of_scope)

            :out_of_scope ->
              Repo.rollback(:source_out_of_scope)

            {:ok, data} ->
              current = current_snapshot!(cse)
              {built, hash} = build_snapshot(cse, data)

              if hash == current.payload_hash do
                {cse, current, false}
              else
                snapshot = insert_snapshot!(cse, built, hash, current.version + 1)

                {1, _} =
                  Repo.update_all(
                    from(c in ReviewCase, where: c.id == ^cse.id),
                    inc: [revision: 1],
                    set: [current_snapshot_id: snapshot.id]
                  )

                append_event!(cse, "evidence_captured", cse.revision + 1,
                  snapshot_id: snapshot.id,
                  detail: %{"version" => snapshot.version, "payload_hash" => hash}
                )

                {Repo.get!(ReviewCase, case_id), snapshot, true}
              end
          end
        end
      end
    end)
    |> case do
      {:ok, {cse, snapshot, changed?}} ->
        {:ok, %{case: cse, snapshot: snapshot, changed?: changed?}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  ## Shared helpers

  defp list_snapshots(case_id) do
    Repo.all(
      from s in EvidenceSnapshot,
        where: s.case_id == ^case_id,
        order_by: [asc: s.version, asc: s.id]
    )
  end

  defp lock_case!(case_id) do
    Repo.one!(from c in ReviewCase, where: c.id == ^case_id, lock: "FOR UPDATE")
  end

  defp current_snapshot!(%ReviewCase{current_snapshot_id: snapshot_id}) do
    Repo.one!(from s in EvidenceSnapshot, where: s.id == ^snapshot_id)
  end

  # Appends one frozen snapshot: insert-only, version is the per-case counter
  # and captured_at is snapshot metadata kept out of the content hash.
  defp insert_snapshot!(%ReviewCase{id: case_id}, payload, hash, version) do
    %EvidenceSnapshot{}
    |> Changeset.change(
      case_id: case_id,
      version: version,
      payload: payload,
      payload_hash: hash,
      captured_at: DateTime.utc_now() |> DateTime.truncate(:second)
    )
    |> Repo.insert!()
  end

  # The audit append is the final atomicity gate: a failure here (a database
  # constraint or trigger refusal) rolls the review and the revision bump back
  # with it and surfaces as a controlled error, never a half-committed save.
  defp append_review_saved_event!(cse, snapshot_id, review, manual) do
    append_event!(cse, "review_saved", cse.revision + 1,
      snapshot_id: snapshot_id,
      review_id: review.id,
      detail: %{
        "applicability" => manual["applicability"],
        "priority" => manual["priority"],
        "next_action" => manual["next_action"]
      }
    )
  rescue
    e in Postgrex.Error -> Repo.rollback(e)
    e in Ecto.ConstraintError -> Repo.rollback(e)
  end

  defp bump_revision!(%ReviewCase{id: id}) do
    {1, _} = Repo.update_all(from(c in ReviewCase, where: c.id == ^id), inc: [revision: 1])
    :ok
  end

  defp append_event!(%ReviewCase{id: case_id}, kind, case_revision, opts)
       when kind in @event_kinds do
    %CaseEvent{}
    |> Changeset.change(
      case_id: case_id,
      kind: kind,
      case_revision: case_revision,
      snapshot_id: Keyword.get(opts, :snapshot_id),
      review_id: Keyword.get(opts, :review_id),
      actor: @actor,
      detail: Keyword.get(opts, :detail, %{})
    )
    |> Repo.insert!()
  end

  defp evidence_status(_cse, nil), do: :source_missing

  defp evidence_status(%ReviewCase{} = cse, %EvidenceSnapshot{} = snapshot) do
    case fetch_finding_for_case(cse) do
      :missing ->
        :source_missing

      :out_of_scope ->
        :source_out_of_scope

      {:ok, data} ->
        {_built, hash} = build_snapshot(cse, data)

        if hash == snapshot.payload_hash, do: :current, else: :changed
    end
  end

  defp fetch_finding_for_case(%ReviewCase{
         finding_id: finding_id,
         owner: owner,
         environment: environment
       }) do
    case Inventory.fetch_finding(finding_id, owner: owner, environment: environment) do
      :error -> :missing
      {:error, :out_of_scope} -> :out_of_scope
      {:ok, data} -> {:ok, data}
    end
  end

  defp fetch_scoped(finding_id, %{owner: owner, environment: environment}) do
    case Inventory.fetch_finding(finding_id, owner: owner, environment: environment) do
      :error -> {:error, :not_found}
      {:error, :out_of_scope} -> {:error, :out_of_scope}
      {:ok, data} -> {:ok, data}
    end
  end

  ## Scope and request validation

  # Local mirror of Inventory's private normalize/1 semantics (raw-binary
  # UTF-8 and control-character checks before trimming) with the stricter
  # case rules: blank/All is rejected outright and the trimmed value must fit
  # 120 characters. Inventory is not refactored or extended for this.
  defp scope_from_opts(opts) when is_list(opts) or is_map(opts) do
    with {:ok, owner} <- validate_scope(fetch_opt(opts, :owner)),
         {:ok, environment} <- validate_scope(fetch_opt(opts, :environment)) do
      {:ok, %{owner: owner, environment: environment}}
    end
  end

  defp scope_from_opts(_opts), do: {:error, :invalid_request}

  # A malformed list (not a keyword list) is treated as a missing value
  # instead of raising inside Keyword.get/3.
  defp fetch_opt(opts, key) when is_list(opts) do
    if Keyword.keyword?(opts), do: Keyword.get(opts, key), else: nil
  end

  defp fetch_opt(opts, key) when is_map(opts) do
    case Map.get(opts, key) do
      nil -> Map.get(opts, Atom.to_string(key))
      value -> value
    end
  end

  defp validate_scope(value) when not is_binary(value), do: {:error, :invalid_scope}

  defp validate_scope(value) do
    cond do
      not String.valid?(value) ->
        {:error, :invalid_scope}

      Regex.match?(@unsafe_scope, value) ->
        {:error, :invalid_scope}

      true ->
        case String.trim(value) do
          "" -> {:error, :invalid_scope}
          trimmed -> validate_trimmed_scope(trimmed)
        end
    end
  end

  defp validate_trimmed_scope(trimmed) do
    cond do
      String.downcase(trimmed) == @scope_absence -> {:error, :invalid_scope}
      String.length(trimmed) > @scope_max -> {:error, :invalid_scope}
      true -> {:ok, trimmed}
    end
  end

  # Positive bigint bounds are checked before any cast or query, so malformed
  # ids and types fail predictably instead of raising in PostgreSQL.
  defp validate_id(id) do
    if valid_positive_integer?(id), do: :ok, else: {:error, :invalid_request}
  end

  defp validate_positive_integer(value) do
    if valid_positive_integer?(value), do: :ok, else: {:error, :invalid_request}
  end

  defp valid_positive_integer?(value) do
    is_integer(value) and not is_boolean(value) and value > 0 and value <= @max_id
  end

  # The idempotency token is always generated by the server with
  # Ecto.UUID.generate/0: anything else — empty, non-binary, overlong,
  # NUL-containing, otherwise malformed — is forged and rejected BEFORE any
  # database access, so a hostile token can never reach an insert and raise
  # Postgrex 22021.
  defp validate_token(token) when is_binary(token) do
    case Ecto.UUID.cast(token) do
      {:ok, _uuid} -> {:ok, token}
      :error -> {:error, :invalid_request}
    end
  end

  defp validate_token(_other), do: {:error, :invalid_request}

  # Total request-shape validation: ONLY string-keyed maps reach the cast.
  # Any other term — plain lists, keyword lists, nil, binaries, numbers,
  # structs, or maps with atom/mixed keys (including forged atom-keyed meta) —
  # is rejected outright with a controlled error instead of raising
  # Ecto.CastError inside cast/4. Atom keys are never silently cast.
  defp manual_changeset(attrs) when is_map(attrs) and not is_struct(attrs) do
    if Enum.all?(attrs, fn {key, _value} -> is_binary(key) end) do
      {:ok, Review.changeset(%Review{}, attrs)}
    else
      {:error, :invalid_request}
    end
  end

  defp manual_changeset(_other), do: {:error, :invalid_request}

  defp ensure_valid(%Changeset{valid?: true}), do: :ok
  defp ensure_valid(%Changeset{} = changeset), do: {:error, changeset}

  defp manual_payload(%Changeset{} = changeset) do
    %{
      "applicability" => Changeset.get_field(changeset, :applicability),
      "priority" => Changeset.get_field(changeset, :priority),
      "next_action" => Changeset.get_field(changeset, :next_action),
      "rationale" => Changeset.get_field(changeset, :rationale)
    }
  end

  defp request_hash(manual, expected_revision, expected_snapshot_id) do
    canonical_hash(@request_hash_domain, %{
      "manual" => manual,
      "expected_revision" => expected_revision,
      "expected_snapshot_id" => expected_snapshot_id
    })
  end

  ## Review queue read model (PR 3)

  # Total request-shape validation BEFORE any query: only a proper keyword
  # list with at most the three known keys reaches a database. Non-keyword
  # lists, duplicate or unknown keys, non-atom keys, maps, structs and every
  # other shape fail closed with :invalid_request.
  defp validate_queue_opts(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      validate_queue_keys(opts)
    else
      {:error, :invalid_request}
    end
  end

  defp validate_queue_opts(_other), do: {:error, :invalid_request}

  defp validate_queue_keys(opts) do
    keys = Keyword.keys(opts)

    cond do
      not Enum.all?(keys, &(&1 in @queue_opt_keys)) -> {:error, :invalid_request}
      length(keys) != length(Enum.uniq(keys)) -> {:error, :invalid_request}
      true -> validate_queue_values(opts)
    end
  end

  defp validate_queue_values(opts) do
    with {:ok, before_id} <- validate_queue_before_id(Keyword.get(opts, :before_id)),
         {:ok, owner} <- validate_queue_scope(Keyword.get(opts, :owner)),
         {:ok, environment} <- validate_queue_scope(Keyword.get(opts, :environment)) do
      {:ok, %{owner: owner, environment: environment, before_id: before_id}}
    end
  end

  # nil or a positive bigint within the int8 range: no coercion of floats,
  # booleans, strings or oversized numerics. The cursor is a position, never
  # a requirement that the referenced case exists.
  defp validate_queue_before_id(nil), do: {:ok, nil}

  defp validate_queue_before_id(before_id) do
    if valid_positive_integer?(before_id), do: {:ok, before_id}, else: {:error, :invalid_request}
  end

  # Read-side scope validation. Deliberately NOT the strict write
  # validate_scope/1: blank-after-trim is the All/unrestricted state and a
  # team literally named "all" is matched like any other name. Like the write
  # path, the raw-binary checks (valid UTF-8, no NUL/C0/DEL) run BEFORE
  # trimming, and the trimmed value must fit 120 characters.
  defp validate_queue_scope(nil), do: {:ok, nil}

  defp validate_queue_scope(value) when not is_binary(value), do: {:error, :invalid_scope}

  defp validate_queue_scope(value) do
    cond do
      not String.valid?(value) ->
        {:error, :invalid_scope}

      Regex.match?(@unsafe_scope, value) ->
        {:error, :invalid_scope}

      true ->
        case String.trim(value) do
          "" ->
            {:ok, nil}

          trimmed ->
            if String.length(trimmed) > @scope_max,
              do: {:error, :invalid_scope},
              else: {:ok, trimmed}
        end
    end
  end

  # A read or assembly failure must surface as a controlled queue error and
  # never degrade into a trustworthy-looking status such as :current.
  defp queue_load(%{owner: owner, environment: environment, before_id: before_id}) do
    candidates = queue_page(owner, environment, before_id)

    {shown, has_more?} =
      if length(candidates) > @queue_page_size,
        do: {Enum.take(candidates, @queue_page_size), true},
        else: {candidates, false}

    rows = queue_rows(shown)

    next_before_id =
      if has_more? do
        {last_case, _snapshot, _latest} = List.last(shown)
        last_case.id
      else
        nil
      end

    {:ok, %{rows: rows, has_more?: has_more?, next_before_id: next_before_id}}
  rescue
    _e in [Postgrex.Error, DBConnection.ConnectionError, Ecto.QueryError, Ecto.SubQueryError] ->
      {:error, :queue_unavailable}
  end

  # Page query: owner AND environment scope plus the id < before_id cursor,
  # strict id DESC ("newest opened first"), fixed page size plus one sentinel
  # row. The sentinel only decides has_more? and never becomes a row.
  #
  # The case pointer/revision, its current snapshot and its latest review are
  # hydrated TOGETHER by this one SELECT: the snapshot is joined by the case's
  # own current_snapshot_id (same-case join; a missing snapshot row means the
  # binding's snapshot is nil), and the latest review comes from a left
  # latest-per-case correlated subquery on (inserted_at DESC, id DESC). The
  # three references can never mix across reads or cases, and a nil latest
  # review means no review exists (awaiting), never needs_revalidation.
  defp queue_page(owner, environment, before_id) do
    from(c in ReviewCase,
      left_join: s in EvidenceSnapshot,
      on: s.id == c.current_snapshot_id,
      left_join: r in Review,
      # fragment/1 needs one literal SQL string: the latest review id per
      # case by (inserted_at DESC, id DESC), correlated on the case row.
      on:
        r.id ==
          fragment(
            "SELECT r2.id FROM review_reviews AS r2 WHERE r2.case_id = ? ORDER BY r2.inserted_at DESC, r2.id DESC LIMIT 1",
            c.id
          ),
      order_by: [desc: c.id],
      limit: ^@queue_fetch_limit,
      select: {c, s, r}
    )
    |> maybe_queue_owner(owner)
    |> maybe_queue_environment(environment)
    |> maybe_queue_before(before_id)
    |> Repo.all()
  end

  defp maybe_queue_owner(query, nil), do: query

  defp maybe_queue_owner(query, owner), do: where(query, [c], c.owner == ^owner)

  defp maybe_queue_environment(query, nil), do: query

  defp maybe_queue_environment(query, environment),
    do: where(query, [c], c.environment == ^environment)

  defp maybe_queue_before(query, nil), do: query

  defp maybe_queue_before(query, before_id), do: where(query, [c], c.id < ^before_id)

  defp queue_rows([]), do: []

  # `loaded` is the {case, current snapshot, latest review} binding hydrated
  # by the single queue_page SELECT; only the fixed source-read batches
  # remain here.
  defp queue_rows(loaded) do
    cases = Enum.map(loaded, fn {cse, _snapshot, _latest} -> cse end)

    finding_ids = cases |> Enum.map(& &1.finding_id) |> Enum.uniq()
    findings = queue_findings(finding_ids)

    image_ids = findings |> Map.values() |> Enum.map(& &1.image_id) |> Enum.uniq()
    placements = queue_scoped_placements(cases, image_ids)
    events = queue_lifecycle_events(finding_ids)

    Enum.map(loaded, fn {cse, snapshot, latest} ->
      queue_row(cse, snapshot, latest, findings, placements, events)
    end)
  end

  # Fixed query families — never a per-row get_case/1 or a per-row
  # Inventory.fetch_finding/2. The case/snapshot/latest-review binding is
  # already hydrated together by the single queue_page SELECT above.

  # Findings with their images joined and preloaded in ONE fixed query;
  # other_occurrences are never loaded here — they are not part of the
  # canonical content hash.
  defp queue_findings([]), do: %{}

  defp queue_findings(finding_ids) do
    from(f in Inventory.Finding,
      where: f.id in ^finding_ids,
      join: image in assoc(f, :image),
      preload: [image: image]
    )
    |> Repo.all()
    |> Map.new(fn finding -> {finding.id, finding} end)
  end

  # Scoped placements batch: ALL matching placements (active AND inactive)
  # for the displayed images within the saved owner/environment values, then
  # grouped by the exact {image_id, owner, environment} triple so each case
  # keeps only its own scope — never another case's placements.
  defp queue_scoped_placements(_cases, []), do: %{}

  defp queue_scoped_placements(cases, image_ids) do
    owners = cases |> Enum.map(& &1.owner) |> Enum.uniq()
    environments = cases |> Enum.map(& &1.environment) |> Enum.uniq()

    Repo.all(
      from(p in Inventory.ImagePlacement,
        where:
          p.image_id in ^image_ids and p.owner in ^owners and
            p.environment in ^environments
      )
    )
    |> Enum.group_by(fn placement ->
      {placement.image_id, placement.owner, placement.environment}
    end)
  end

  # Full lifecycle events for the displayed findings, one batched query; the
  # canonical payload builder re-sorts them deterministically. History is
  # never truncated to fit the query budget.
  defp queue_lifecycle_events([]), do: %{}

  defp queue_lifecycle_events(finding_ids) do
    Repo.all(
      from(e in Inventory.FindingEvent,
        where: e.finding_id in ^finding_ids,
        order_by: [asc: e.occurred_at, asc: e.id]
      )
    )
    |> Enum.group_by(& &1.finding_id)
  end

  # A committed case always carries a current snapshot; a nil pointer (or a
  # missing snapshot row) arrives as a nil binding snapshot and maps to
  # :source_missing, mirroring get_case/1.
  defp queue_row(cse, snapshot, latest, findings, placements, events) do
    finding = Map.get(findings, cse.finding_id)
    scoped = queue_case_placements(cse, finding, placements)
    lifecycle = Map.get(events, cse.finding_id, [])

    evidence_status = queue_evidence_status(cse, snapshot, finding, scoped, lifecycle)

    %{
      id: cse.id,
      finding_id: cse.finding_id,
      owner: cse.owner,
      environment: cse.environment,
      revision: cse.revision,
      current_snapshot_id: cse.current_snapshot_id,
      opened_at: cse.inserted_at,
      finding: queue_finding_display(snapshot, finding),
      image: queue_image_display(snapshot),
      snapshot: queue_snapshot_display(snapshot),
      latest_review: queue_review_display(latest),
      evidence_status: evidence_status,
      review_status: queue_review_status(latest, cse, evidence_status)
    }
  end

  defp queue_case_placements(_cse, nil, _placements), do: []

  defp queue_case_placements(
         %ReviewCase{owner: owner, environment: environment},
         finding,
         placements
       ) do
    Map.get(placements, {finding.image_id, owner, environment}, [])
  end

  # Same evidence contract as get_case/1, recomputed read-only from the
  # batched source reads through the EXISTING canonical builder and hash:
  # missing finding or snapshot -> :source_missing; no active matching
  # placement -> :source_out_of_scope (inactive placements still participate
  # in the hash, exactly like PR 2); equal canonical hash -> :current;
  # anything else -> :changed. It never defaults to :current.
  defp queue_evidence_status(_cse, nil, _finding, _placements, _events), do: :source_missing

  defp queue_evidence_status(_cse, _snapshot, nil, _placements, _events), do: :source_missing

  defp queue_evidence_status(cse, snapshot, finding, placements, events) do
    if Enum.any?(placements, & &1.active) do
      data = %{finding: finding, placements: placements, events: events}
      {_built, hash} = build_snapshot(cse, data)

      if hash == snapshot.payload_hash, do: :current, else: :changed
    else
      :source_out_of_scope
    end
  end

  # Review status is derived, never persisted: no review -> :awaiting_review;
  # the latest review bound to the current snapshot on current evidence ->
  # :current_review; anything else -> :needs_revalidation. A recapture alone
  # never revalidates an old review.
  defp queue_review_status(nil, _cse, _evidence_status), do: :awaiting_review

  defp queue_review_status(review, %ReviewCase{} = cse, evidence_status) do
    if review.snapshot_id == cse.current_snapshot_id and evidence_status == :current do
      :current_review
    else
      :needs_revalidation
    end
  end

  # Frozen display text: identity comes from the snapshot payload, never the
  # live source — new source facts change the evidence badge, not the
  # captured CVE/package/image text.
  defp queue_finding_display(%EvidenceSnapshot{payload: payload}, _finding) do
    frozen = payload["finding"]
    image = payload["image"]

    %{
      cve: frozen["cve"],
      package_name: frozen["package_name"],
      package_version: frozen["package_version"],
      severity: frozen["severity"],
      suppressed: frozen["suppressed"],
      image: %{
        digest: image["digest"],
        repository: image["repository"],
        tag: image["tag"]
      }
    }
  end

  # Frozen-display guard: only reachable for a case whose current_snapshot_id
  # is nil (never exposed after a committed open) or whose source finding no
  # longer exists. No snapshot means NO captured evidence, so identity display
  # returns explicit unknown/empty fields with the same UI-safe finding/image
  # map shape — the LIVE source is never substituted as if it had been
  # captured — while the status stays :source_missing.
  defp queue_finding_display(nil, _finding) do
    %{
      cve: "",
      package_name: "",
      package_version: "",
      severity: "",
      suppressed: nil,
      image: %{digest: "", repository: "", tag: ""}
    }
  end

  # The row contract's top-level frozen image map: the same captured image
  # identity as the nested finding.image, read from the same snapshot payload.
  # Frozen until an explicit recapture — never re-read from the live source.
  defp queue_image_display(%EvidenceSnapshot{payload: payload}) do
    image = payload["image"]

    %{digest: image["digest"], repository: image["repository"], tag: image["tag"]}
  end

  defp queue_image_display(nil), do: %{digest: "", repository: "", tag: ""}

  defp queue_snapshot_display(nil), do: nil

  defp queue_snapshot_display(%EvidenceSnapshot{} = snapshot) do
    %{id: snapshot.id, version: snapshot.version, captured_at: snapshot.captured_at}
  end

  defp queue_review_display(nil), do: nil

  defp queue_review_display(review) do
    %{
      id: review.id,
      snapshot_id: review.snapshot_id,
      inserted_at: review.inserted_at,
      applicability: review.applicability,
      priority: review.priority,
      next_action: review.next_action
    }
  end

  defp distinct_nonblank_scopes(queryable, field) do
    from(c in queryable, distinct: true, select: field(c, ^field), order_by: field(c, ^field))
    |> Repo.all()
    |> Enum.reject(fn value -> is_nil(value) or String.trim(value) == "" end)
  end

  ## Frozen evidence payload and deterministic content hashing

  # The stable snapshot payload shape (schema_version 1). Only captured facts:
  # no ORM inserted_at/updated_at, no capture time (that is separate
  # `captured_at` metadata), so the content hash is stable across reads and
  # recomputations.
  defp build_snapshot(%ReviewCase{owner: owner, environment: environment}, data) do
    built = payload(owner, environment, data)
    {built, content_hash(built)}
  end

  defp payload(owner, environment, data) do
    %{
      "schema_version" => @payload_schema_version,
      "source" =>
        if(Triage.ReferenceData.reference_image?(data.finding.image),
          do: "nvd_public_reference",
          else: @payload_source
        ),
      "scope" => %{"owner" => owner, "environment" => environment},
      "finding" => finding_payload(data.finding),
      "image" => image_payload(data.finding.image),
      "placements" => placements_payload(data.placements),
      "events" => lifecycle_payload(data.events),
      "coverage" =>
        if(Triage.ReferenceData.reference_image?(data.finding.image),
          do: %{"kind" => "public_reference_only", "warning" => Triage.ReferenceData.warning()},
          else: @coverage
        )
    }
  end

  defp finding_payload(finding) do
    %{
      "id" => finding.id,
      "image_id" => finding.image_id,
      "cve" => finding.cve,
      "package_name" => finding.package_name,
      "package_version" => finding.package_version,
      "severity" => finding.severity,
      "fix" => finding.fix,
      "url" => finding.url,
      "description" => finding.description,
      "suppressed" => finding.suppressed,
      "first_seen" => iso8601(finding.first_seen),
      "last_seen" => iso8601(finding.last_seen),
      "resolved_at" => iso8601(finding.resolved_at),
      "reopen_count" => finding.reopen_count
    }
  end

  defp image_payload(image) do
    %{
      "id" => image.id,
      "digest" => image.digest,
      "repository" => image.repository,
      "tag" => image.tag,
      "description" => image.description
    }
  end

  defp placements_payload(placements) do
    placements
    |> Enum.map(fn placement ->
      %{
        "id" => placement.id,
        "owner" => placement.owner,
        "namespace" => placement.namespace,
        "environment" => placement.environment,
        "active" => placement.active,
        "first_seen" => iso8601(placement.first_seen),
        "last_seen" => iso8601(placement.last_seen)
      }
    end)
    |> Enum.sort_by(&{&1["owner"], &1["namespace"], &1["environment"], &1["id"]})
  end

  defp lifecycle_payload(events) do
    events
    |> Enum.sort_by(&{&1.occurred_at, &1.id})
    |> Enum.map(fn event ->
      %{
        "id" => event.id,
        "event" => event.event,
        "occurred_at" => iso8601(event.occurred_at),
        "note" => event.note
      }
    end)
  end

  defp iso8601(nil), do: nil
  defp iso8601(%DateTime{} = datetime), do: DateTime.to_iso8601(datetime)

  defp content_hash(value), do: canonical_hash(@hash_domain, value)

  defp canonical_hash(domain, value) do
    :crypto.hash(:sha256, domain <> "|" <> canonical(value))
    |> Base.encode16(case: :lower)
  end

  # Canonical structured-content encoding: nil/bool/int tagged by type,
  # binaries length-tagged (no delimiter ambiguity), lists explicit, maps
  # sorted by encoded key so query and map insertion order are irrelevant.
  defp canonical(nil), do: "n"
  defp canonical(true), do: "t"
  defp canonical(false), do: "f"

  defp canonical(value) when is_integer(value), do: "i" <> Integer.to_string(value)

  defp canonical(value) when is_binary(value),
    do: "s" <> Integer.to_string(byte_size(value)) <> ":" <> value

  defp canonical(value) when is_list(value) do
    "l[" <> Enum.map_join(value, ",", &canonical/1) <> "]"
  end

  defp canonical(value) when is_map(value) do
    "m{" <>
      (value
       |> Enum.map(fn {key, item} -> canonical(key) <> "=" <> canonical(item) end)
       |> Enum.sort()
       |> Enum.join(",")) <>
      "}"
  end
end
