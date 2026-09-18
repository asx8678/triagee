defmodule Triage.Triage do
  @moduledoc """
  Read model for the Triage page: which critical advisories still need a human,
  what a human has already recorded about each scope they affect, and which
  operator decisions currently cover them.

  ## What admits a row

  The page answers "what must a human look at, and what have they already
  judged?", so its admission rules are stated once, here:

    * **Active** — the inventory's own predicate: unresolved
      (`resolved_at IS NULL`), unsuppressed, and at least one active placement.
      Opening a case, saving a review or recording a decision never changes it.
    * **Assessed** — a `review_reviews` row exists for that `(finding, owner,
      environment)` scope. Opening a case is *not* an assessment, and neither
      `resolved_at` nor `suppressed` is a handling decision.
    * **Applicability confirmed** — the latest review of that scope says
      `applicability = "affected"` *and* that review is still bound to the
      case's current evidence snapshot. This is what a human wrote in the only
      judgement field the schema has; it is labelled applicability and never
      called impact.
    * **Impact evidence** — an unexpired `placement_impact_evidences` row for the
      placement the scope belongs to, with its source and observation time.
      Absence is *not* "no impact": absence is silence.
    * **Decision** — the governing `advisory_decisions` row for the advisory
      (`Triage.Decisions`): the latest effective decision in each exact scope.
      Future records cover nothing and expired replacements never revive older
      acceptances. Every active placement must be covered before the advisory
      leaves the work list; a placement decision never covers its siblings.

  Scope assessment states:

    * `:awaiting_assessment` — no review at all.
    * `:assessed` — the latest review is bound to the case's current snapshot.
    * `:assessment_superseded` — a review exists, but evidence was recaptured
      after it. Whether the *content* still matches is decided authoritatively
      by the case page from the canonical hash; this module never upgrades a
      superseded review to current just because a row exists.

  ## Lane state, precedence and filters

  `:state` is decided in one documented order:

    1. `:assessed_no_impact` — every active scope has a current review and none
       says affected. A human judgement is the strongest statement, so it wins.
    2. `:decision_recorded` — an active decision covers the advisory and the
       scopes are not fully cleared by review.
    3. `:applicability_confirmed` — at least one scope carries a current
       `affected` review.
    4. `:awaiting_assessment` — everything else, including an advisory whose
       only review was superseded, because unfinished judgement is never
       reported as handled.

  A decision is still *displayed* on rows in any state, so the stricter state
  never hides the fact that a decision exists.

  The filters are exact complements and nothing can hide between them:
  `"active"` is `:applicability_confirmed` and `:awaiting_assessment`,
  `"whitelisted"` is `:decision_recorded`, `"handled"` is
  `:assessed_no_impact`, and `"all"` is every critical active advisory.
  An unknown filter is rejected rather than silently treated as the default.

  Reads are pure: no locks, no writes, no changesets. A read failure returns
  `{:error, :triage_unavailable}` instead of a trustworthy-looking empty page.
  """

  import Ecto.Query

  alias Triage.Cases.{Review, ReviewCase}
  alias Triage.Decisions
  alias Triage.Impact
  alias Triage.Inventory
  alias Triage.Inventory.{Finding, ImagePlacement}
  alias Triage.Repo

  @filters ~w(active whitelisted handled all)
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
      applicability_confirmed: Enum.count(rows, &(&1.state == :applicability_confirmed)),
      decision_recorded: Enum.count(rows, &(&1.state == :decision_recorded)),
      awaiting_assessment: Enum.count(rows, &(&1.state == :awaiting_assessment)),
      assessed_no_impact: Enum.count(rows, &(&1.state == :assessed_no_impact)),
      scopes_total: Enum.sum(Enum.map(rows, & &1.scopes_total)),
      scopes_assessed: Enum.sum(Enum.map(rows, & &1.scopes_assessed)),
      scopes_applicable: Enum.sum(Enum.map(rows, & &1.scopes_applicable)),
      scopes_with_impact: Enum.sum(Enum.map(rows, & &1.scopes_with_impact))
    }
  end

  defp load(filter) do
    groups = Inventory.list_groups(severity: "CRITICAL", sort: "last_seen", limit: @row_limit)
    total = Inventory.count_groups(severity: "CRITICAL")

    cves = Enum.map(groups, & &1.cve)
    scopes = scopes_by_cve(cves)
    cases = cases_by_scope(finding_ids(scopes))
    decisions = Decisions.latest_by_scope(cves)
    impacts = impacts_by_placement(scopes)

    rows =
      groups
      |> Enum.map(&build_row(&1, scopes, cases, decisions, impacts))
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
  # (finding, owner, environment) the advisory currently affects, with the
  # placement that carries its exposure and impact evidence. Scope comes from
  # active placements only, exactly like `list_groups/1`, so a retired
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
        placement_id: p.id,
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

  defp impacts_by_placement(scopes) do
    ids =
      scopes
      |> Map.values()
      |> List.flatten()
      |> Enum.map(& &1.placement_id)
      |> Enum.uniq()

    case ids do
      [] -> %{}
      ids -> Impact.current_by_placement(ids)
    end
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

  defp build_row(group, scopes, cases, decisions, impacts) do
    work_items =
      scopes
      |> Map.get(group.cve, [])
      |> Enum.map(fn scope ->
        scope
        |> work_item(cases, impacts)
        |> Map.put(
          :decision,
          Decisions.covering_decision(decisions, group.cve, scope.placement_id)
        )
      end)
      |> Enum.sort_by(&{&1.owner, &1.environment, &1.finding_id})

    assessed = Enum.count(work_items, &(&1.assessment == :assessed))

    applicable =
      Enum.count(work_items, &(&1.assessment == :assessed and &1.applicability == "affected"))

    reviewed = Enum.count(work_items, &(&1.assessment != :awaiting_assessment))

    with_impact =
      Enum.count(work_items, &(&1.impact != nil and &1.impact.state == :active))

    decision = Map.get(decisions, {group.cve, nil})
    decided = Enum.count(work_items, &Decisions.active?(&1.decision))

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
      scopes_applicable: applicable,
      scopes_with_impact: with_impact,
      decision: decision,
      scopes_decided: decided,
      state: lane_state(assessed, applicable, length(work_items), decided),
      work_items: work_items
    }
  end

  # Precedence is documented in the moduledoc: a completed human review wins,
  # then a live decision, then a partial applicability judgement, then nothing.
  defp lane_state(assessed, applicable, total, _decision)
       when total > 0 and assessed == total and applicable == 0,
       do: :assessed_no_impact

  defp lane_state(_assessed, _applicable, total, decided) when total > 0 and total == decided,
    do: :decision_recorded

  defp lane_state(_assessed, applicable, _total, _decision) when applicable > 0,
    do: :applicability_confirmed

  defp lane_state(_assessed, _applicable, _total, _decision), do: :awaiting_assessment

  # A scope with no saved case is still open work: the page links to the
  # finding, which is the only place a case can be opened.
  defp work_item(scope, cases, impacts) do
    base = %{
      impact: Map.get(impacts, scope.placement_id),
      assessment: :awaiting_assessment,
      case_id: nil,
      revision: nil,
      applicability: nil,
      priority: nil,
      next_action: nil,
      reviewed_at: nil
    }

    case Map.get(cases, {scope.finding_id, scope.owner, scope.environment}) do
      nil ->
        Map.merge(scope, base)

      saved ->
        Map.merge(
          scope,
          Map.merge(base, %{
            case_id: saved.case_id,
            revision: saved.revision,
            assessment: assessment(saved),
            applicability: saved.applicability,
            priority: saved.priority,
            next_action: saved.next_action,
            reviewed_at: saved.reviewed_at
          })
        )
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
  defp matches?(%{state: :decision_recorded}, "whitelisted"), do: true
  defp matches?(_row, "whitelisted"), do: false

  defp matches?(%{state: state}, "active")
       when state in [:assessed_no_impact, :decision_recorded],
       do: false

  defp matches?(_row, "active"), do: true
end
