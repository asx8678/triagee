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
  alias Triage.Cases.{CaseEvent, Evidence, EvidenceSnapshot, Queue, Review, ReviewCase}
  alias Triage.Inventory
  alias Triage.Repo

  @actor "local-operator"
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
  defdelegate list_cases(opts \\ []), to: Queue

  @doc """
  Batched saved-case state for advisory action rows, using the queue's existing
  source/evidence comparison. Does not open cases or change scanner inventory.
  Only positive bigint finding IDs are accepted; empty input performs no query.
  """
  defdelegate states_for_findings(finding_ids), to: Queue

  @doc """
  Sorted distinct nonblank owner and environment values from saved cases.

  Queue filter options come from `review_cases` only — independent of the
  current active inventory — so retired teams and environments remain
  selectable. Pure read; no status counters.
  """
  defdelegate case_filter_options(), to: Queue

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
          {built, hash} = Evidence.build_snapshot(created, data)
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
    request_hash = Evidence.request_hash(manual, expected_revision, expected_snapshot_id)

    case Repo.get(ReviewCase, case_id) do
      nil ->
        {:error, :not_found}

      %ReviewCase{} ->
        Repo.transaction(fn ->
          cse = lock_case!(case_id)

          save_or_replay(
            cse,
            manual,
            request_hash,
            expected_revision,
            expected_snapshot_id,
            token
          )
        end)
        |> case do
          {:ok, {cse, review, replayed?}} ->
            {:ok, %{case: cse, review: review, replayed?: replayed?}}

          {:error, %Postgrex.Error{postgres: %{code: :unique_violation}}} ->
            {:error, :token_reuse}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp save_or_replay(cse, manual, request_hash, expected_revision, expected_snapshot_id, token) do
    case Repo.one(from r in Review, where: r.case_id == ^cse.id and r.idempotency_token == ^token) do
      %Review{} = replay ->
        # Exact retries precede freshness checks, including after later revisions.
        if replay.request_hash == request_hash and
             replay.expected_revision == expected_revision and
             replay.snapshot_id == expected_snapshot_id do
          {cse, replay, true}
        else
          Repo.rollback(:token_reuse)
        end

      nil ->
        save_new_review(cse, manual, request_hash, expected_revision, expected_snapshot_id, token)
    end
  end

  defp save_new_review(cse, manual, request_hash, expected_revision, expected_snapshot_id, token) do
    # These guards run under the existing row lock, in the original error order.
    if cse.revision != expected_revision, do: Repo.rollback(:conflict)
    if cse.current_snapshot_id != expected_snapshot_id, do: Repo.rollback(:evidence_stale)

    data = current_data!(cse)
    {_built, hash} = Evidence.build_snapshot(cse, data)
    if hash != current_snapshot!(cse).payload_hash, do: Repo.rollback(:evidence_stale)

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

  defp current_data!(cse) do
    case fetch_finding_for_case(cse) do
      {:ok, data} -> data
      :missing -> Repo.rollback(:source_out_of_scope)
      :out_of_scope -> Repo.rollback(:source_out_of_scope)
    end
  end

  ## Refresh

  defp recapture(case_id, expected_revision, expected_snapshot_id) do
    Repo.transaction(fn ->
      cse = lock_case!(case_id)

      if cse.revision != expected_revision or cse.current_snapshot_id != expected_snapshot_id,
        do: Repo.rollback(:conflict)

      data = current_data!(cse)
      current = current_snapshot!(cse)
      {built, hash} = Evidence.build_snapshot(cse, data)

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
        {_built, hash} = Evidence.build_snapshot(cse, data)

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
end
