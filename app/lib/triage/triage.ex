defmodule Triage.Triage do
  @moduledoc """
  Read-only read model for the Triage page: which critical advisories still need
  a human, and what a human has already recorded about each scope they affect.

  ## What admits a row

  The page answers "what must a human look at, and what have they already
  judged?", so its admission rules are stated once, here:

    * **Active** — the inventory's own predicate: unresolved
      (`resolved_at IS NULL`), unsuppressed, and at least one active placement.
      Opening a case or saving a review never changes it.
    * **Assessed** — a `review_reviews` row exists for that `(finding, owner,
      environment)` scope. Opening a case is *not* an assessment, and neither
      `resolved_at` nor `suppressed` is a handling decision.
    * **Impact recorded** — the latest review of that scope says
      `applicability = "affected"` *and* that review is still bound to the
      case's current evidence snapshot. This schema has no impact field, so the
      page labels the value applicability and never calls it impact.

  Scope assessment states:

    * `:awaiting_assessment` — no review at all.
    * `:assessed` — the latest review is bound to the case's current snapshot.
    * `:assessment_superseded` — a review exists, but evidence was recaptured
      after it. Whether the *content* still matches is decided authoritatively
      by the case page from the canonical hash; this module never upgrades a
      superseded review to current just because a row exists.

  ## Lane state and filters

  `:state` is `:impact_confirmed` (at least one scope carries a current
  `affected` review), `:assessed_no_impact` (every scope has a current review
  and none says affected) or `:awaiting_assessment` (everything else —
  including an advisory whose only review was superseded, because unfinished
  judgement is never reported as handled).

  The filters are exact complements and nothing can hide between them:
  `"active"` is every state except `:assessed_no_impact`, `"handled"` is
  `:assessed_no_impact`, and `"all"` is every critical active advisory.
  An unknown filter is rejected rather than silently treated as the default.

  Reads are pure: no locks, no writes, no changesets. A read failure returns
  `{:error, :triage_unavailable}` instead of a trustworthy-looking empty page.
  """

  import Ecto.Query

  alias Triage.Cases.{Review, ReviewCase}
  alias Triage.Inventory
  alias Triage.Inventory.{Finding, ImagePlacement}
  alias Triage.Repo

  @filters ~w(active handled all)
  @default_filter "active"

  # One page of advisory rows, bounded by the inventory's own group limit. The
  # unpaged total is read separately so a capped page can say so.
  @row_limit 200

  @doc "Request filters accepted through `list_critical/1`'s `:filter` option."
  def filters, do: @filters

  @doc "The filter applied when `:filter` is omitted."
  def default_filter, do: @default_filter

  @doc "The maximum number of advisory rows one page can return."
  def row_limit, do: @row_limit

  @doc """
  Critical advisories with their per-scope work items.

  Returns `{:ok, %{filter: filter, rows: rows, total: total, truncated?: boolean}}`
  where `total` is the unpaged count of critical, active advisories,
  `{:error, :invalid_filter}` for a filter this module does not publish, or
  `{:error, :triage_unavailable}` when the read itself failed.
  """
  def list_critical(opts \\ []) do
    with {:ok, filter} <- normalize_filter(Keyword.get(opts, :filter)) do
      load(filter)
    end
  end

  @doc """
  Lane and scope totals for a list of rows, so the page header and the lanes
  are computed from exactly the rows being shown.
  """
  def summarize(rows) when is_list(rows) do
    %{
      impact_confirmed: Enum.count(rows, &(&1.state == :impact_confirmed)),
      awaiting_assessment: Enum.count(rows, &(&1.state == :awaiting_assessment)),
      assessed_no_impact: Enum.count(rows, &(&1.state == :assessed_no_impact)),
      scopes_total: Enum.sum(Enum.map(rows, & &1.scopes_total)),
      scopes_assessed: Enum.sum(Enum.map(rows, & &1.scopes_assessed)),
      scopes_impacted: Enum.sum(Enum.map(rows, & &1.scopes_impacted))
    }
  end

  defp load(filter) do
    groups = Inventory.list_groups(severity: "CRITICAL", sort: "last_seen", limit: @row_limit)
    total = Inventory.count_groups(severity: "CRITICAL")

    scopes = scopes_by_cve(Enum.map(groups, & &1.cve))
    cases = cases_by_scope(finding_ids(scopes))

    rows =
      groups
      |> Enum.map(&build_row(&1, scopes, cases))
      |> Enum.filter(&matches?(&1, filter))

    {:ok, %{filter: filter, rows: rows, total: total, truncated?: total > length(groups)}}
  rescue
    _e in [Postgrex.Error, DBConnection.ConnectionError, Ecto.QueryError, Ecto.SubQueryError] ->
      {:error, :triage_unavailable}
  end

  # Blank is the intentional default (the URL may omit the parameter); an
  # unknown non-blank value is rejected rather than silently coerced.
  defp normalize_filter(nil), do: {:ok, @default_filter}

  defp normalize_filter(filter) when is_binary(filter) do
    case filter |> String.trim() |> String.downcase() do
      "" ->
        {:ok, @default_filter}

      normalized ->
        if normalized in @filters, do: {:ok, normalized}, else: {:error, :invalid_filter}
    end
  end

  defp normalize_filter(_other), do: {:error, :invalid_filter}

  # Active-scope work items for the page's advisories: one row per
  # (finding, owner, environment) the advisory currently affects. Scope comes
  # from active placements only, exactly like `list_groups/1`, so a retired
  # placement is not open work.
  defp scopes_by_cve([]), do: %{}

  defp scopes_by_cve(cves) do
    from(f in Finding,
      join: p in ImagePlacement,
      on: p.image_id == f.image_id and p.active == true,
      join: i in assoc(f, :image),
      where: f.cve in ^cves and is_nil(f.resolved_at) and f.suppressed == false,
      order_by: [asc: f.cve, asc: f.package_name, asc: f.id, asc: p.owner, asc: p.environment],
      distinct: true,
      select: %{
        cve: f.cve,
        finding_id: f.id,
        owner: p.owner,
        environment: p.environment,
        package_name: f.package_name,
        package_version: f.package_version,
        image_repository: i.repository,
        image_tag: i.tag
      }
    )
    |> Repo.all()
    |> Enum.group_by(& &1.cve)
  end

  defp finding_ids(scopes) do
    scopes
    |> Map.values()
    |> List.flatten()
    |> Enum.map(& &1.finding_id)
    |> Enum.uniq()
  end

  # One SELECT hydrates the saved case for a scope together with its LATEST
  # review by (inserted_at DESC, id DESC) — the same latest-per-case shape the
  # review queue uses, so the two read models cannot disagree about which
  # review is current.
  defp cases_by_scope([]), do: %{}

  defp cases_by_scope(finding_ids) do
    from(c in ReviewCase,
      left_join: r in Review,
      on:
        r.id ==
          fragment(
            "SELECT r2.id FROM review_reviews AS r2 WHERE r2.case_id = ? ORDER BY r2.inserted_at DESC, r2.id DESC LIMIT 1",
            c.id
          ),
      where: c.finding_id in ^finding_ids,
      select: %{
        finding_id: c.finding_id,
        owner: c.owner,
        environment: c.environment,
        case_id: c.id,
        revision: c.revision,
        current_snapshot_id: c.current_snapshot_id,
        review_id: r.id,
        applicability: r.applicability,
        priority: r.priority,
        next_action: r.next_action,
        reviewed_at: r.inserted_at,
        review_snapshot_id: r.snapshot_id
      }
    )
    |> Repo.all()
    |> Map.new(fn row -> {{row.finding_id, row.owner, row.environment}, row} end)
  end

  defp build_row(group, scopes, cases) do
    work_items =
      scopes
      |> Map.get(group.cve, [])
      |> Enum.map(&work_item(&1, cases))
      |> Enum.sort_by(&{&1.owner, &1.environment, &1.finding_id})

    assessed = Enum.count(work_items, &(&1.assessment == :assessed))

    impacted =
      Enum.count(work_items, &(&1.assessment == :assessed and &1.applicability == "affected"))

    reviewed = Enum.count(work_items, &(&1.assessment != :awaiting_assessment))

    %{
      cve: group.cve,
      severity: Inventory.severity_label(group.severity_rank),
      severity_rank: group.severity_rank,
      occurrences: group.occurrences,
      images: group.images,
      teams: group.teams,
      packages: group.packages,
      fixable: group.fixable,
      reopened: group.reopened,
      first_seen: group.first_seen,
      last_seen: group.last_seen,
      scopes_total: length(work_items),
      scopes_assessed: assessed,
      scopes_reviewed: reviewed,
      scopes_impacted: impacted,
      state: lane_state(assessed, impacted, length(work_items)),
      work_items: work_items
    }
  end

  defp lane_state(_assessed, impacted, _total) when impacted > 0, do: :impact_confirmed

  defp lane_state(assessed, _impacted, total) when total > 0 and assessed == total,
    do: :assessed_no_impact

  defp lane_state(_assessed, _impacted, _total), do: :awaiting_assessment

  # A scope with no saved case is still open work: the page links to the
  # finding, which is the only place a case can be opened.
  defp work_item(scope, cases) do
    case Map.get(cases, {scope.finding_id, scope.owner, scope.environment}) do
      nil ->
        Map.merge(scope, %{
          case_id: nil,
          revision: nil,
          assessment: :awaiting_assessment,
          applicability: nil,
          priority: nil,
          next_action: nil,
          reviewed_at: nil
        })

      saved ->
        Map.merge(scope, %{
          case_id: saved.case_id,
          revision: saved.revision,
          assessment: assessment(saved),
          applicability: saved.applicability,
          priority: saved.priority,
          next_action: saved.next_action,
          reviewed_at: saved.reviewed_at
        })
    end
  end

  defp assessment(%{review_id: nil}), do: :awaiting_assessment

  defp assessment(%{review_snapshot_id: snapshot_id, current_snapshot_id: current_id})
       when not is_nil(snapshot_id) and snapshot_id == current_id,
       do: :assessed

  defp assessment(_saved), do: :assessment_superseded

  defp matches?(_row, "all"), do: true
  defp matches?(%{state: :assessed_no_impact}, "handled"), do: true
  defp matches?(_row, "handled"), do: false
  defp matches?(%{state: :assessed_no_impact}, "active"), do: false
  defp matches?(_row, "active"), do: true
end
