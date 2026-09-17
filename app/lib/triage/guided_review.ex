defmodule Triage.GuidedReview do
  @moduledoc "Actionable CVE queue and durable, per-team remediation requests. Never marks inventory fixed."
  import Ecto.Query
  alias Triage.{Repo, Decisions, Exposure, Risk}
  alias Triage.Inventory.{Finding, Image, ImagePlacement}
  alias Triage.Decisions.Decision

  defmodule Request do
    use Ecto.Schema
    schema "remediation_requests" do
      field :cve, :string
      field :owner, :string
      field :scope_key, :string
      field :status, :string, default: "planned"
      field :payload, :map
      field :ticket_id, :integer
      field :ticket_url, :string
      field :error, :string
      field :actor, :string
      timestamps(type: :utc_datetime)
    end
  end

  def queue do
    from(f in Finding,
      join: p in ImagePlacement, on: p.image_id == f.image_id and p.active,
      join: i in Image, on: i.id == f.image_id,
      where: is_nil(f.resolved_at) and not f.suppressed,
      order_by: [asc: f.cve, asc: p.owner, asc: p.id, asc: f.id],
      select: %{finding: f, placement: p, image: i})
    |> Repo.all()
    |> decorate()
    |> Enum.filter(&(&1.pending != []))
    |> Enum.sort_by(&{priority_rank(&1.risk.priority), &1.cve})
  end

  def get(cve), do: Enum.find(queue(), &(&1.cve == cve))

  defp decorate(scopes) do
    now = DateTime.utc_now()
    exposure = Exposure.current_by_placement(Enum.map(scopes, & &1.placement.id), now)
    cves = scopes |> Enum.map(& &1.finding.cve) |> Enum.uniq()
    decisions = Repo.all(from d in Decision, where: d.cve in ^cves)
    requests = Repo.all(from r in Request, where: r.cve in ^cves)

    scopes
    |> Enum.group_by(& &1.finding.cve)
    |> Enum.map(fn {cve, items} ->
      history = Enum.filter(decisions, &(&1.cve == cve))
      # Latest effective decision within each exact scope; future records do not
      # revoke a currently effective decision. Placement decisions cover only that placement.
      active = history
        |> Enum.reject(&(DateTime.compare(&1.decided_at, now) == :gt))
        |> Enum.group_by(& &1.placement_id)
        |> Enum.map(fn {_scope, ds} -> Enum.max_by(ds, &{DateTime.to_unix(&1.decided_at), &1.id}) end)
        |> Enum.filter(&(Decisions.state(&1, now) == :active))

      items = Enum.map(items, fn item ->
        exposed = Map.get(exposure, item.placement.id, "unknown")
        Map.merge(item, %{
          exposure: exposed,
          covered?: Enum.any?(active, &(is_nil(&1.placement_id) or &1.placement_id == item.placement.id)),
          risk: Risk.classify(%{severity: item.finding.severity, exposure: exposed, fix_available: not is_nil(item.finding.fix)})
        })
      end)

      teams = items |> Enum.reject(& &1.covered?) |> Enum.group_by(& &1.placement.owner)
        |> Enum.map(fn {owner, team_items} ->
          key = scope_key(team_items)
          request = Enum.find(requests, &(&1.cve == cve and &1.owner == owner and &1.scope_key == key))
          %{owner: owner, scopes: team_items, scope_key: key, request: request}
        end)
        |> Enum.sort_by(& &1.owner)

      %{cve: cve, scopes: items, teams: teams,
        pending: Enum.reject(teams, &(&1.request && &1.request.status == "created")),
        descriptions: items |> Enum.map(& &1.finding.description) |> Enum.reject(&(&1 in [nil, ""])) |> Enum.uniq(),
        risk: Risk.aggregate(Enum.map(items, & &1.risk)),
        first_seen: items |> Enum.map(& &1.finding.first_seen) |> Enum.reject(&is_nil/1) |> Enum.min(DateTime, fn -> nil end)}
    end)
  end

  defp scope_key(items) do
    items |> Enum.map(&{&1.finding.id, &1.finding.reopen_count, &1.placement.id, &1.finding.first_seen})
    |> Enum.sort() |> :erlang.term_to_binary() |> then(&:crypto.hash(:sha256, &1)) |> Base.encode16(case: :lower)
  end

  defp priority_rank("critical"), do: 0
  defp priority_rank("high"), do: 1
  defp priority_rank("medium"), do: 2
  defp priority_rank(_), do: 3

  def whitelist(cve, reason, expires_on) do
    with row when not is_nil(row) <- get(cve),
         true <- is_binary(reason) and String.length(String.trim(reason)) >= 3,
         {:ok, date} <- Date.from_iso8601(expires_on || ""),
         true <- Date.compare(date, Date.utc_today()) != :lt do
      Decisions.record(%{cve: cve, decision: "accepted_risk", reason: String.trim(reason),
        actor: "local-operator", decided_at: DateTime.utc_now(),
        expires_at: DateTime.new!(date, ~T[23:59:59], "Etc/UTC")})
    else
      _ -> {:error, :invalid_whitelist}
    end
  end

  def preview(cve) do
    case get(cve) do
      nil -> {:error, :not_actionable}
      row -> {:ok, Enum.map(row.pending, &ticket_plan(row, &1))}
    end
  end

  defp ticket_plan(row, team) do
    mapping = Triage.ReviewIntegrations.team_mapping(team.owner)
    %{cve: row.cve, owner: team.owner, scope_key: team.scope_key,
      mapping: mapping, request: team.request,
      title: "Fix #{row.cve} — #{team.owner}",
      description: Enum.join([
        "CVE: #{row.cve}", "Responsible team: #{team.owner}",
        "Review priority: #{row.risk.priority} (local policy, not CVSS)",
        Enum.join(row.descriptions, "\n\n"),
        "Affected services and libraries:",
        Enum.map_join(team.scopes, "\n", fn s ->
          "#{s.image.repository}:#{s.image.tag} | #{s.placement.environment} | #{s.finding.package_name} #{s.finding.package_version} | fix: #{s.finding.fix || "not reported"} | exposure: #{s.exposure}"
        end), "Created by local-operator. Ticket creation is not evidence of a deployed fix."
      ], "\n\n")}
  end

  # Preview fingerprint binds confirmation to the current scope and destination.
  def fingerprint(plans) do
    plans |> Enum.map(&Map.take(&1, [:cve, :owner, :scope_key, :mapping, :title, :description]))
    |> :erlang.term_to_binary() |> then(&:crypto.hash(:sha256, &1)) |> Base.encode16()
  end

  def mark_for_fix(cve) do
    with {:ok, plans} <- preview(cve) do
      Repo.transaction(fn -> Enum.map(plans, &persist/1) end)
    end
  end

  defp persist(plan) do
    payload = %{title: plan.title, description: plan.description, mapping: plan.mapping}
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    Repo.insert!(%Request{cve: plan.cve, owner: plan.owner, scope_key: plan.scope_key,
      payload: payload, actor: "local-operator", inserted_at: now, updated_at: now},
      on_conflict: :nothing, conflict_target: [:cve, :owner, :scope_key])
    Repo.one!(from r in Request, where: r.cve == ^plan.cve and r.owner == ^plan.owner and r.scope_key == ^plan.scope_key)
  end

  def create_tickets(cve, expected_fingerprint) do
    with {:ok, plans} <- preview(cve),
         true <- fingerprint(plans) == expected_fingerprint,
         true <- Triage.ReviewIntegrations.azure_configured?(),
         true <- Enum.all?(plans, & &1.mapping) do
      {:ok, Enum.map(plans, fn plan -> plan |> persist() |> send_ticket(plan) end)}
    else
      false -> {:error, :preview_changed_or_configuration_missing}
      error -> error
    end
  end

  defp send_ticket(request, plan) do
    # Claim is durable before the external write. A crash or ambiguous network
    # response must never cause an automatic duplicate ticket on retry.
    {claimed, _} = Repo.update_all(from(r in Request,
      where: r.id == ^request.id and r.status in ["planned", "failed"]),
      set: [status: "sending", error: nil, updated_at: DateTime.utc_now() |> DateTime.truncate(:second)])
    if claimed == 1 do
      result = Triage.ReviewIntegrations.create_ticket(plan)
      attrs = case result do
        {:ok, id, url} -> %{status: "created", ticket_id: id, ticket_url: url, error: nil}
        {:error, :rejected} -> %{status: "failed", error: "Azure rejected this request. Check configuration before retrying."}
        _ -> %{status: "unknown", error: "Creation could not be confirmed. Check Azure before any manual retry; automatic retry is blocked."}
      end
      request |> Ecto.Changeset.change(attrs) |> Repo.update!()
    else
      Repo.get!(Request, request.id)
    end
  end

  def requests(cve), do: Repo.all(from r in Request, where: r.cve == ^cve, order_by: [asc: r.owner, desc: r.id])
end
