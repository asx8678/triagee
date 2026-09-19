defmodule Triage.Workspace do
  @moduledoc "Scoped operational read model. CVE × immutable placement is a target; packages remain evidence, not extra placements."
  import Ecto.Query, except: [select: 2]
  alias Triage.{Decisions, Exposure, Intel, ReferenceData, Repo, Risk}
  alias Triage.Inventory.{Finding, Image, ImagePlacement}

  @doc "Read-only scope projection. Never hydrates a filtered CVE back to all of its placements."
  def targets(filters \\ %{}, now \\ DateTime.utc_now()) do
    query =
      from f in Finding,
        join: p in ImagePlacement,
        on: p.image_id == f.image_id and p.active,
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
    exposure = Exposure.current_by_placement(Enum.map(items, & &1.placement.id), now)
    decisions = Decisions.latest_by_scope(cves, now)
    kev = Intel.kev_index(cves)

    items
    |> Enum.group_by(&{&1.finding.cve, &1.placement.id})
    |> Enum.map(fn {{cve, id}, scopes} ->
      first = hd(scopes)
      findings = Enum.map(scopes, & &1.finding) |> Enum.sort_by(& &1.id)
      active = Enum.filter(findings, &is_nil(&1.resolved_at))
      exposed = Map.get(exposure, id, "unknown")

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

      decision = Decisions.covering_decision(decisions, cve, id)
      covered = decision != nil and decision.metadata["evidence_hash"] in [nil, evidence_hash]

      %{
        id: id,
        cve: cve,
        placement: first.placement,
        image: first.image,
        findings: findings,
        active?: active != [],
        exposure: exposed,
        risk: Risk.aggregate(risks),
        evidence_hash: evidence_hash,
        decision: decision,
        covered?: covered,
        needs_decision?: active != [] and not covered,
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
  defp matches?(target, "urgent"), do: target.active? and target.risk.priority == "critical"
  defp matches?(target, "unknown"), do: target.active? and target.exposure == "unknown"

  defp matches?(target, "accepted"),
    do: target.active? and target.covered? and target.decision.decision == "accepted_risk"

  defp matches?(target, "progress"),
    do:
      target.active? and target.covered? and target.decision.decision in Decisions.work_actions()

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
    |> Enum.sort_by(&{priority_rank(&1.risk), &1.cve})
  end

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

  def hash(value),
    do:
      value
      |> :erlang.term_to_binary()
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16(case: :lower)
end
