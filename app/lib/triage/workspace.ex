defmodule Triage.Workspace do
  @moduledoc "Scoped operational read model. CVE × immutable placement is a target; packages remain evidence, not extra placements."
  import Ecto.Query, except: [select: 2]
  alias Triage.{Decisions, Evidence, Exposure, Intel, ReferenceData, Repo, Risk}
  alias Triage.Inventory.{Finding, Image, ImagePlacement}

  @doc """
  Bounded database workspace read. Accepts the workspace URL's string-keyed
  parameters and returns `page_rows` (at most 50), `total`, scalar `metrics`,
  `teams`, `options`, and bounded `targets`/`matching` for the page and explicit
  `item`/`inspect` CVEs. `row` is the full scoped focused CVE; the inspector keeps
  the urgent/unknown drilldown's matching-target semantics. Review defaults to
  the first matching CVE, independently of the page offset.

  Metric entries contain only `%{value: count}`; use mode/scope queries for
  drilldowns rather than materializing an estate-wide list of target IDs.
  """
  defdelegate page(params, now \\ DateTime.utc_now()), to: Triage.Workspace.Query

  @doc """
  Full read-only scope projection, retained for domain callers. Supports `team`,
  `environment`, `cve`, `cves` (list), and `placement_ids` (list); empty lists
  match nothing. Limits apply to complete targets, never individual findings.
  Never hydrates a filtered CVE back to all of its placements.
  """
  def targets(filters \\ %{}, now \\ DateTime.utc_now()) do
    query =
      from f in Finding,
        join: p in ImagePlacement,
        on: p.image_id == f.image_id,
        join: i in Image,
        on: i.id == f.image_id,
        where:
          (is_nil(p.owner) or p.owner != ^ReferenceData.owner()) and
            (is_nil(p.environment) or p.environment != ^ReferenceData.environment()),
        select: %{finding: f, placement: p, image: i}

    items =
      query
      |> scoped(filters)
      |> Repo.all()
      |> Enum.reject(&ReferenceData.reference_image?(&1.image))

    cves = Enum.map(items, & &1.finding.cve) |> Enum.uniq()
    exposure = Exposure.current_evidence(Enum.map(items, & &1.placement.id), now)
    decisions = Decisions.latest_by_scope(cves, now)
    kev = Intel.kev_index(cves)

    items
    |> Enum.group_by(&{&1.finding.cve, &1.placement.id})
    |> Enum.map(fn {{cve, id}, scopes} ->
      first = hd(scopes)
      findings = Enum.map(scopes, & &1.finding) |> Enum.sort_by(& &1.id)
      active = Enum.filter(findings, &is_nil(&1.resolved_at))
      # A retired placement is history, not exposure: its decisions stay
      # inspectable, but it never counts as operational work. The evidence
      # hash includes placement.active, so retirement also invalidates stale
      # draft and retry bindings like any other evidence change.
      operational = active != [] and first.placement.active
      exposure_evidence = Map.get(exposure, id)
      exposed = if exposure_evidence, do: exposure_evidence.exposure, else: "unknown"

      risks =
        Enum.map(
          active,
          &Risk.classify(%{
            severity: &1.severity,
            exposure: exposed,
            known_exploited: if(Map.has_key?(kev, cve), do: true),
            fix_available: not is_nil(&1.fix)
          })
        )

      evidence_hash =
        hash(
          {Map.take(first.placement, [:id, :image_id, :owner, :environment, :namespace, :active]),
           first.image.digest,
           Enum.map(
             findings,
             &Map.take(&1, [
               :id,
               :package_name,
               :package_version,
               :severity,
               :fix,
               :description,
               :resolved_at,
               :reopen_count,
               :first_seen,
               :suppressed
             ])
           )}
        )

      packet =
        Evidence.Packet.build(%{
          cve: cve,
          placement: first.placement,
          image_digest: first.image.digest,
          findings: findings,
          exposure: Evidence.Packet.exposure_material(exposure_evidence),
          intel: Evidence.Packet.intel_material(Map.get(kev, cve)),
          captured_at: now,
          provenance: %{
            "exposure" => Evidence.Packet.exposure_provenance(exposure_evidence),
            "intel" => Evidence.Packet.intel_provenance(Map.get(kev, cve))
          },
          blockers: Evidence.Packet.live_blockers()
        })

      decision = Decisions.covering_decision(decisions, cve, id)

      # A retired placement is history: its recorded decision stays visible as
      # coverage of that historical scope even though retirement itself changed
      # the evidence. Operational targets require a v2 packet binding;
      # pre-packet (v1 or nil) dismissals are never promoted to "covered".
      coverage =
        Evidence.coverage_state(decision,
          packet_hash: packet.hash,
          legacy_hash: evidence_hash,
          active?: operational
        )

      covered = Evidence.covered?(coverage)

      %{
        id: id,
        cve: cve,
        placement: first.placement,
        image: first.image,
        findings: findings,
        active?: operational,
        exposure: exposed,
        exposure_state: if(exposure_evidence, do: exposure_evidence.state, else: :none),
        risk: Risk.aggregate(risks),
        evidence_hash: evidence_hash,
        packet_hash: packet.hash,
        coverage_state: coverage,
        decision: decision,
        covered?: covered,
        needs_decision?: operational and not covered,
        fingerprint:
          hash({evidence_hash, exposed, risks, decisions[{cve, nil}], decisions[{cve, id}]}),
        first_seen: findings |> Enum.map(& &1.first_seen) |> Enum.min(DateTime),
        last_seen: findings |> Enum.map(& &1.last_seen) |> Enum.max(DateTime)
      }
    end)
    |> Enum.sort_by(&{&1.cve, &1.id})
  end

  defp scoped(query, filters) do
    Enum.reduce(filters, query, fn
      {"team", "__unassigned__"}, q ->
        where(
          q,
          [f, p],
          is_nil(p.owner) or p.owner in ["", "(unknown)", "unassigned", "__unassigned__"]
        )

      {"team", value}, q when is_binary(value) and value != "" ->
        where(q, [f, p], p.owner == ^value)

      {"environment", value}, q when is_binary(value) and value != "" ->
        where(q, [f, p], p.environment == ^value)

      {"cve", value}, q when is_binary(value) and value != "" ->
        where(q, [f], f.cve == ^value)

      {"cves", values}, q when is_list(values) ->
        where(q, [f], f.cve in ^values)

      {"placement_ids", values}, q when is_list(values) ->
        where(q, [f, p], p.id in ^values)

      _, q ->
        q
    end)
  end

  def options do
    query =
      from p in ImagePlacement,
        where:
          p.active and (is_nil(p.owner) or p.owner != ^ReferenceData.owner()) and
            p.environment != ^ReferenceData.environment(),
        select: {p.owner, p.environment},
        distinct: true

    rows = Repo.all(query)

    %{
      teams: rows |> Enum.map(&team_key(elem(&1, 0))) |> Enum.uniq() |> Enum.sort(),
      environments: rows |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> Enum.sort()
    }
  end

  def team_key(name) when name in [nil, "", "(unknown)", "unassigned"], do: "__unassigned__"
  def team_key(name), do: name

  @doc "Same exact target selector is used by cards, team rows and drilldowns."
  def select(targets, view), do: Enum.filter(targets, &matches?(&1, view))

  defp matches?(_target, "all"), do: true
  defp matches?(target, "history"), do: not target.active?
  defp matches?(target, "needs"), do: target.needs_decision?
  defp matches?(target, "attention"), do: Triage.Attention.needs_attention?(target)
  defp matches?(target, "progress"), do: Triage.Attention.in_progress?(target)
  defp matches?(target, "urgent"), do: target.active? and target.risk.priority == "critical"
  defp matches?(target, "unknown"), do: target.active? and target.exposure == "unknown"

  defp matches?(target, "fixed"),
    do: target.covered? and target.decision.decision == "fixed"

  defp matches?(target, "accepted"),
    do: target.active? and target.covered? and target.decision.decision == "accepted_risk"

  defp matches?(target, _view), do: target.active?

  def rows(targets) do
    targets
    |> Enum.group_by(& &1.cve)
    |> Enum.map(fn {cve, scopes} ->
      findings = Enum.flat_map(scopes, & &1.findings) |> Enum.uniq_by(& &1.id)

      %{
        cve: cve,
        scopes: scopes,
        risk: Risk.aggregate(Enum.map(scopes, & &1.risk) |> Enum.reject(&is_nil/1)),
        severity: findings |> Enum.map(& &1.severity) |> Enum.max_by(&Triage.Severity.rank/1),
        packages: findings |> Enum.map(& &1.package_name) |> Enum.uniq() |> Enum.join(", "),
        first_seen: scopes |> Enum.map(& &1.first_seen) |> Enum.min(DateTime)
      }
    end)
    |> Enum.sort_by(&{severity_sort(&1.severity), priority_rank(&1.risk), &1.cve})
  end

  # T05: attention-led ordering. The SQL computes the same band per target;
  # a CVE row takes its most urgent contributing target's band (min).
  def rows(targets, :attention) do
    targets
    |> rows()
    |> Enum.sort_by(&attention_sort(&1))
  end

  defp attention_sort(row) do
    bands =
      row.scopes
      |> Enum.map(&Triage.Attention.band(&1))
      |> Enum.min(fn -> 4 end)

    {bands, severity_sort(row.severity), priority_rank(row.risk), row.cve}
  end

  # Severity leads the queue: a critical advisory is never outranked by a high
  # one, whatever review priority scores them. Review priority and the CVE id
  # break ties, so the order is total and stable across pages. A row with no
  # recorded severity sorts last.
  defp severity_sort(severity), do: -Triage.Severity.rank(severity)

  defp priority_rank(nil), do: 9
  defp priority_rank(risk), do: Enum.find_index(Risk.priorities(), &(&1 == risk.priority))

  def metrics(targets) do
    for view <- ~w(active needs urgent unknown), into: %{} do
      contributing = select(targets, view)
      ids = contributing |> Enum.map(& &1.cve) |> Enum.uniq() |> Enum.sort()

      {view,
       %{
         value: if(view == "unknown", do: length(contributing), else: length(ids)),
         cves: ids,
         targets: Enum.map(contributing, &{&1.cve, &1.id})
       }}
    end
  end

  def history(cve, targets, filters \\ %{}) do
    ids = Enum.map(targets, & &1.id)

    Decisions.history_for_cve(cve)
    |> Enum.filter(fn d ->
      snapshot = d.metadata["target"] || %{}

      (is_nil(d.placement_id) or d.placement_id in ids) and
        Enum.all?([{"team", "team"}, {"environment", "environment"}], fn {filter, field} ->
          filters[filter] in [nil, ""] or snapshot[field] == nil or
            history_scope_value(field, snapshot[field]) == filters[filter]
        end)
    end)
  end

  defp history_scope_value("team", value), do: team_key(value)
  defp history_scope_value(_field, value), do: value

  # Canonical encoding, never default term_to_binary: these hashes are stored
  # and compared across restarts, and ETF orders small maps by VM atom state.
  def hash(value), do: Triage.Canonical.hash(value)
end
