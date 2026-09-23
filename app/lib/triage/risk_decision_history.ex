defmodule Triage.RiskDecisionHistory do
  @moduledoc "Read-only presentation of recorded risk decisions; never an effective-coverage calculation."
  alias Triage.Decisions

  @keys ~w(risk_q risk_status risk_team risk_environment risk_page)
  @page_size 12
  def filter_keys, do: @keys

  def build(decisions, params, now \\ DateTime.utc_now()) do
    filters = Map.new(@keys, &{&1, text(params[&1])})
    status = if filters["risk_status"] == "", do: "all", else: filters["risk_status"]
    filters = Map.put(filters, "risk_status", status)
    scoped = Enum.filter(decisions, &matches?(&1, filters))

    groups =
      scoped
      |> Enum.group_by(&group_key/1)
      |> Enum.map(fn {_, records} -> group(records, now) end)
      |> Enum.sort_by(&{DateTime.to_unix(&1.decided_at), &1.id}, :desc)

    counts = %{
      "all" => length(groups),
      "valid" => Enum.count(groups, &(&1.status in ~w(valid expiring unlimited))),
      "expiring" => Enum.count(groups, &(&1.status == "expiring")),
      "expired" => Enum.count(groups, &(&1.status == "expired"))
    }

    matching = Enum.filter(groups, &status_matches?(&1.status, status))
    pages = max(1, ceil(length(matching) / @page_size))
    page = min(page_number(filters["risk_page"]), pages)

    %{
      rows: Enum.slice(matching, (page - 1) * @page_size, @page_size),
      total: length(matching),
      records: Enum.sum(Enum.map(matching, &length(&1.records))),
      counts: counts,
      page: page,
      pages: pages,
      filters: filters,
      teams: options(decisions, "team"),
      environments: options(decisions, "environment"),
      empty?: decisions == [],
      filtered?:
        Enum.any?(~w(risk_q risk_team risk_environment), &(filters[&1] != "")) or status != "all"
    }
  end

  defp text(value) when is_binary(value), do: String.trim(value)
  defp text(_), do: ""

  defp page_number(value) do
    case Integer.parse(value) do
      {page, ""} when page > 0 -> page
      _ -> 1
    end
  end

  defp target(d) do
    case (d.metadata || %{})["target"] do
      value when is_map(value) -> value
      _ -> %{}
    end
  end

  defp field(d, key), do: text(target(d)[key])

  defp options(decisions, key),
    do:
      decisions
      |> Enum.map(&field(&1, key))
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()
      |> Enum.sort()

  defp matches?(d, filters) do
    team = filters["risk_team"]
    environment = filters["risk_environment"]

    searchable =
      [d.cve, d.reason, d.actor, field(d, "team"), field(d, "environment"), field(d, "namespace")]
      |> Enum.map_join(" ", &text/1)
      |> String.downcase()

    (team == "" or team == field(d, "team")) and
      (environment == "" or environment == field(d, "environment")) and
      String.contains?(searchable, String.downcase(filters["risk_q"]))
  end

  # Group only an explicit shared operation with identical approval facts.
  # No operation ID means a distinct record, even if its prose happens to match.
  defp group_key(d) do
    operation =
      if text(d.operation_id) == "", do: {:record, d.id}, else: {:operation, d.operation_id}

    {operation, d.cve, d.decision, d.actor, d.reason, d.decided_at, d.expires_at,
     (d.metadata || %{})["expiry_boundary"]}
  end

  defp group(records, now) do
    records = Enum.sort_by(records, & &1.id)
    d = hd(records)
    status = expiry_status(d, now)

    %{
      id: d.id,
      cve: d.cve,
      decision: d.decision,
      reason: text(d.reason),
      actor: text(d.actor),
      decided_at: d.decided_at,
      expires_at: d.expires_at,
      records: records,
      status: status,
      status_label: status_label(status),
      relative_expiry: relative_expiry(d, status, now),
      teams: options(records, "team"),
      environments: options(records, "environment"),
      legacy?: Enum.any?(records, &is_nil(&1.placement_id)),
      scopes:
        Enum.map(records, fn record ->
          %{
            record_id: record.id,
            placement_id: record.placement_id,
            team: field(record, "team"),
            environment: field(record, "environment"),
            namespace: field(record, "namespace"),
            supersedes_id: record.supersedes_id
          }
        end)
    }
  end

  defp expiry_status(d, now) do
    decision = struct(Decisions.Decision, Map.take(d, [:decided_at, :expires_at, :metadata]))

    case Decisions.state(decision, now) do
      :expired -> "expired"
      :pending -> "pending"
      :active -> active_status(d.expires_at, now)
    end
  end

  defp active_status(nil, _now), do: "unlimited"

  defp active_status(expiry, now) do
    if DateTime.compare(expiry, DateTime.add(now, 7, :day)) != :gt, do: "expiring", else: "valid"
  end

  defp status_matches?(_status, "all"), do: true
  defp status_matches?(status, "valid"), do: status in ~w(valid expiring unlimited)
  defp status_matches?(status, filter), do: status == filter and filter in ~w(expiring expired)
  defp status_label("valid"), do: "Not expired"
  defp status_label("expiring"), do: "Expiring soon"
  defp status_label("expired"), do: "Expired"
  defp status_label("unlimited"), do: "No expiry"
  defp status_label("pending"), do: "Scheduled"

  defp relative_expiry(_d, "unlimited", _now), do: "No end date recorded"
  defp relative_expiry(_d, "pending", _now), do: "Not yet in effect"

  defp relative_expiry(d, "expired", now) do
    days = Date.diff(DateTime.to_date(now), DateTime.to_date(d.expires_at))
    if days < 1, do: "Expired today", else: "#{days}d past expiry"
  end

  defp relative_expiry(d, _status, now) do
    days = Date.diff(DateTime.to_date(d.expires_at), DateTime.to_date(now))
    if days < 1, do: "Expires today", else: "#{days}d remaining"
  end
end
