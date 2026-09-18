defmodule Triage.Cases.Queue do
  @moduledoc "Internal bounded, read-only case projections. Public callers use Triage.Cases."
  import Ecto.Query
  alias Triage.Cases.{Evidence, EvidenceSnapshot, Review, ReviewCase}
  alias Triage.{Inventory, Repo}

  @unsafe_scope ~r/[\x00-\x1F\x7F]/
  @scope_max 120
  @max_id Integer.pow(2, 63) - 1

  # PR 3 read-only Review Queue. Fixed page size; one extra sentinel row
  # decides has_more?. The read-side scope validator is deliberately NOT the
  # strict write validate_scope/1: blank means the All/unrestricted filter and
  # a team literally named "all" is an ordinary team name here.
  @queue_page_size 25
  @queue_fetch_limit @queue_page_size + 1
  @queue_opt_keys [:owner, :environment, :before_id]

  def list_cases(opts \\ []) do
    with {:ok, queue_opts} <- validate_queue_opts(opts) do
      queue_load(queue_opts)
    end
  end

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

  def case_filter_options do
    %{
      owners: distinct_nonblank_scopes(ReviewCase, :owner),
      environments: distinct_nonblank_scopes(ReviewCase, :environment)
    }
  end

  defp valid_positive_integer?(value) do
    is_integer(value) and not is_boolean(value) and value > 0 and value <= @max_id
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
        validate_trimmed_scope(String.trim(value))
    end
  end

  defp validate_trimmed_scope(""), do: {:ok, nil}

  defp validate_trimmed_scope(trimmed) do
    if String.length(trimmed) > @scope_max,
      do: {:error, :invalid_scope},
      else: {:ok, trimmed}
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
      {_built, hash} = Evidence.build_snapshot(cse, data)

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
end
