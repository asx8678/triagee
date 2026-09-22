defmodule Triage.DailyTimeline do
  @moduledoc """
  Read-only CVE activity: recorded detections, observation changes and decisions.

  Each CVE appears once, with its complete recorded history oldest first.
  CVEs are paged by latest activity and CVE ID; pages never split a lifecycle.
  A saved operation spanning several deployments is one action with many scopes.
  Response timing uses the first recorded detection and first subsequent human
  action on any deployment. It describes a response, not verified remediation or
  complete deployment coverage. Future decisions do not count as actions taken.
  """
  import Ecto.Query
  alias Triage.Decisions.Decision
  alias Triage.Inventory.{Finding, FindingEvent}
  alias Triage.Repo

  @page_size 20
  @option_keys ~w(before before_date scope now)a

  @doc "CVE histories grouped by their latest activity date, with response timing."
  def list(opts \\ []) do
    with {:ok, request} <- validate(opts) do
      events = activity_query(request)

      latest =
        from(e in events,
          group_by: e.cve,
          select: %{cve: e.cve, occurred_at: max(e.occurred_at)}
        )

      rows =
        from(e in subquery(latest))
        |> before_cursor(request.before)
        |> before_date(request.before_date)
        |> order_by([e], desc: e.occurred_at, desc: e.cve)
        |> limit(^(@page_size + 1))
        |> Repo.all()

      shown = Enum.take(rows, @page_size)
      has_more? = length(rows) > @page_size
      cves = shown |> Enum.map(& &1.cve) |> Enum.uniq()
      summaries = summaries(cves, request.now)
      history = Repo.all(from(e in events, where: e.cve in ^cves))
      details = event_details(history)
      days = group_days(history, summaries, details)

      {:ok,
       %{
         days: days,
         has_more?: has_more?,
         next_before: if(has_more?, do: encode_cursor(List.last(shown))),
         total_cves: Repo.one(from(e in events, select: count(e.cve, :distinct))),
         event_count: Enum.sum(Enum.map(days, & &1.event_count)),
         earlier?: not is_nil(request.before) or not is_nil(request.before_date),
         as_of: request.now
       }}
    end
  end

  defp validate(opts) when is_list(opts) do
    if Keyword.keyword?(opts) and Enum.all?(Keyword.keys(opts), &(&1 in @option_keys)) do
      with {:ok, cursor} <- decode_cursor(Keyword.get(opts, :before)),
           {:ok, date} <- validate_date(Keyword.get(opts, :before_date)),
           scope when scope in ["all", "critical"] <- Keyword.get(opts, :scope, "all"),
           %DateTime{} = now <- Keyword.get(opts, :now, DateTime.utc_now()),
           true <- is_nil(cursor) or is_nil(date) do
        {:ok, %{before: cursor, before_date: date, scope: scope, now: now}}
      else
        {:error, _} = error -> error
        _ -> {:error, :invalid_request}
      end
    else
      {:error, :invalid_request}
    end
  end

  defp validate(_), do: {:error, :invalid_request}
  defp validate_date(nil), do: {:ok, nil}
  defp validate_date(%Date{} = date), do: {:ok, date}

  defp validate_date(date) when is_binary(date) do
    case Date.from_iso8601(date) do
      {:ok, date} -> {:ok, date}
      _ -> {:error, :invalid_date}
    end
  end

  defp validate_date(_), do: {:error, :invalid_date}
  defp decode_cursor(nil), do: {:ok, nil}

  defp decode_cursor(cursor) when is_binary(cursor) and byte_size(cursor) <= 300 do
    with {:ok, json} <- Base.url_decode64(cursor, padding: false),
         {:ok, %{"at" => at, "cve" => cve}} <- Jason.decode(json),
         true <- is_binary(at) and is_binary(cve) and byte_size(cve) in 1..100,
         {:ok, time, 0} <- DateTime.from_iso8601(at) do
      {:ok, %{at: time, cve: cve}}
    else
      _ -> {:error, :invalid_cursor}
    end
  end

  defp decode_cursor(_), do: {:error, :invalid_cursor}

  defp encode_cursor(event) do
    %{at: DateTime.to_iso8601(event.occurred_at), cve: event.cve}
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
  end

  # first_seen is recorded inventory evidence even when the event log is absent.
  # An earlier appeared event is also preserved as the first detection time.
  defp detections do
    appeared =
      from(e in FindingEvent,
        where: e.event == "appeared",
        group_by: e.finding_id,
        select: %{finding_id: e.finding_id, at: min(e.occurred_at)}
      )

    from(f in Finding,
      left_join: e in subquery(appeared),
      on: e.finding_id == f.id,
      select: %{
        id: f.id,
        cve: f.cve,
        source: "detection",
        kind: "detected",
        occurred_at: type(fragment("LEAST(?, ?)", f.first_seen, e.at), :utc_datetime)
      }
    )
  end

  defp activity_query(request) do
    observations =
      from(e in FindingEvent,
        join: f in Finding,
        on: f.id == e.finding_id,
        where: e.event in ["reopened", "resolved"],
        select: %{
          id: e.id,
          cve: f.cve,
          source: "observation",
          kind: e.event,
          occurred_at: e.occurred_at
        }
      )

    decisions =
      from(d in Decision,
        select: %{
          id: d.id,
          cve: d.cve,
          source: "decision",
          kind: d.decision,
          occurred_at: d.decided_at
        }
      )

    combined = detections() |> union_all(^observations) |> union_all(^decisions)
    query = from(e in subquery(combined), where: e.occurred_at <= ^request.now)

    if request.scope == "critical" do
      critical = from(f in Finding, where: f.severity == "CRITICAL", select: f.cve)
      where(query, [e], e.cve in subquery(critical))
    else
      query
    end
  end

  defp before_cursor(query, nil), do: query

  defp before_cursor(query, cursor) do
    where(
      query,
      [e],
      e.occurred_at < ^cursor.at or
        (e.occurred_at == ^cursor.at and e.cve < ^cursor.cve)
    )
  end

  defp before_date(query, nil), do: query

  defp before_date(query, date),
    do: where(query, [e], e.occurred_at < ^DateTime.new!(date, ~T[00:00:00], "Etc/UTC"))

  defp summaries([], _now), do: %{}

  defp summaries(cves, now) do
    detected =
      from(e in subquery(detections()),
        where: e.cve in ^cves and e.occurred_at <= ^now,
        group_by: e.cve,
        select: %{cve: e.cve, at: min(e.occurred_at)}
      )

    first_seen = detected |> Repo.all() |> Map.new(&{&1.cve, &1.at})

    first_actions =
      from(d in Decision,
        left_join: e in subquery(detected),
        on: e.cve == d.cve,
        where: d.cve in ^cves and d.decided_at <= ^now,
        where: is_nil(e.at) or d.decided_at >= e.at,
        distinct: d.cve,
        order_by: [asc: d.cve, asc: d.decided_at, asc: d.id],
        select: %{cve: d.cve, id: d.id, kind: d.decision, at: d.decided_at}
      )
      |> Repo.all()
      |> Map.new(&{&1.cve, &1})

    metadata =
      from(f in Finding,
        where: f.cve in ^cves,
        group_by: f.cve,
        select: %{
          cve: f.cve,
          description: min(f.description),
          severity:
            max(
              fragment(
                "CASE ? WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END",
                f.severity
              )
            ),
          packages:
            fragment("array_agg(DISTINCT (? || ' ' || ?))", f.package_name, f.package_version)
        }
      )
      |> Repo.all()
      |> Map.new(&{&1.cve, &1})

    Map.new(cves, fn cve ->
      info = Map.get(metadata, cve, %{description: nil, severity: 0, packages: []})
      detection = first_seen[cve]
      action = first_actions[cve]

      {cve,
       %{
         cve: cve,
         description: info.description || "No description recorded",
         severity: severity(info.severity),
         packages: info.packages |> Enum.sort() |> Enum.join(", "),
         first_detected_at: detection,
         first_action: action,
         response_seconds: elapsed(detection, action && action.at),
         waiting_seconds: if(is_nil(action), do: elapsed(detection, now))
       }}
    end)
  end

  defp event_details(rows) do
    ids = fn source -> for row <- rows, row.source == source, do: row.id end

    findings =
      from(f in Finding,
        where: f.id in ^ids.("detection"),
        select: %{
          id: f.id,
          package_name: f.package_name,
          package_version: f.package_version,
          image_id: f.image_id
        }
      )
      |> Repo.all()
      |> Map.new(
        &{{"detection", &1.id},
         %{scope: package_scope(&1), actor: nil, reason: nil, expires_at: nil}}
      )

    observations =
      from(e in FindingEvent,
        join: f in Finding,
        on: f.id == e.finding_id,
        where: e.id in ^ids.("observation"),
        select: %{
          id: e.id,
          note: e.note,
          package_name: f.package_name,
          package_version: f.package_version,
          image_id: f.image_id
        }
      )
      |> Repo.all()
      |> Map.new(
        &{{"observation", &1.id},
         %{scope: package_scope(&1), actor: nil, reason: &1.note, expires_at: nil}}
      )

    decisions =
      from(d in Decision, where: d.id in ^ids.("decision"))
      |> Repo.all()
      |> Map.new(
        &{{"decision", &1.id},
         %{
           scope: decision_scope(&1),
           operation_id: &1.operation_id,
           placement_id: &1.placement_id,
           actor: &1.actor,
           reason: &1.reason,
           expires_at: &1.expires_at
         }}
      )

    findings |> Map.merge(observations) |> Map.merge(decisions)
  end

  defp package_scope(f), do: "#{f.package_name} #{f.package_version} · image ##{f.image_id}"
  defp decision_scope(%{placement_id: nil}), do: "All deployments for this CVE"

  defp decision_scope(d) do
    target = d.metadata["target"] || %{}

    [target["team"], target["environment"], "deployment ##{d.placement_id}"]
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.join(" · ")
  end

  defp group_days(rows, summaries, details) do
    rows
    |> Enum.group_by(& &1.cve)
    |> Enum.map(fn {cve, cve_events} ->
      summary = Map.fetch!(summaries, cve)

      events =
        cve_events
        |> Enum.map(fn event ->
          event
          |> Map.merge(Map.fetch!(details, {event.source, event.id}))
          |> Map.put(:elapsed_seconds, elapsed(summary.first_detected_at, event.occurred_at))
        end)
        |> group_operations()

      latest = Enum.max_by(cve_events, &DateTime.to_unix(&1.occurred_at)).occurred_at
      Map.merge(summary, %{events: events, latest_at: latest})
    end)
    |> Enum.group_by(&DateTime.to_date(&1.latest_at))
    |> Enum.map(fn {date, entries} ->
      cves = Enum.sort_by(entries, &{DateTime.to_unix(&1.latest_at), &1.cve}, :desc)

      %{
        date: date,
        count: length(cves),
        event_count: Enum.sum(Enum.map(cves, &length(&1.events))),
        cves: cves
      }
    end)
    |> Enum.sort_by(& &1.date, {:desc, Date})
  end

  defp group_operations(events) do
    events
    |> Enum.group_by(&operation_key/1)
    |> Enum.map(fn {_key, records} ->
      first = Enum.min_by(records, &{DateTime.to_unix(&1.occurred_at), &1.id})

      Map.merge(first, %{
        scopes: records |> Enum.map(& &1.scope) |> Enum.uniq() |> Enum.sort(),
        record_ids: records |> Enum.map(& &1.id) |> Enum.sort(),
        last_recorded_at: Enum.max_by(records, &DateTime.to_unix(&1.occurred_at)).occurred_at
      })
    end)
    |> Enum.sort_by(&{DateTime.to_unix(&1.occurred_at), event_order(&1), &1.id})
    |> Enum.map_reduce(MapSet.new(), fn event, seen ->
      key = {event.kind, event.scopes}
      {Map.put(event, :repeated?, MapSet.member?(seen, key)), MapSet.put(seen, key)}
    end)
    |> elem(0)
  end

  # Only rows from the same saved operation are merged. Independent reviews,
  # renewals, and changes of expiry remain separately dated audit events.
  defp operation_key(%{source: "decision"} = event),
    do:
      {event.source, event.operation_id || event.id, event.kind, event.actor, event.reason,
       event.expires_at}

  defp operation_key(event), do: {event.source, event.kind, event.occurred_at, event.reason}
  defp event_order(%{kind: kind}) when kind in ["detected", "reopened"], do: 0
  defp event_order(%{source: "decision"}), do: 1
  defp event_order(_), do: 2

  defp elapsed(%DateTime{} = from, %DateTime{} = to) do
    seconds = DateTime.diff(to, from)
    if seconds >= 0, do: seconds
  end

  defp elapsed(_, _), do: nil
  defp severity(4), do: "CRITICAL"
  defp severity(3), do: "HIGH"
  defp severity(2), do: "MEDIUM"
  defp severity(1), do: "LOW"
  defp severity(_), do: "UNKNOWN"
end
