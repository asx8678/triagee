defmodule Triage.Timeline.Days do
  @moduledoc "Pure day-band projection: counts precede display truncation and rows retain event identity."
  @row_limit 25

  @spec row_limit() :: pos_integer()
  def row_limit, do: @row_limit

  @spec build(map(), list(), map()) :: [map()]
  def build(req, events, judged_counts) do
    by_date = Enum.group_by(events, fn {e, _f, _i} -> DateTime.to_date(e.occurred_at) end)

    dates_by_cve =
      events
      |> Enum.group_by(fn {_e, f, _i} -> f.cve end, fn {e, _f, _i} ->
        DateTime.to_date(e.occurred_at)
      end)
      |> Map.new(fn {cve, dates} -> {cve, MapSet.new(dates)} end)

    req.from
    |> Date.range(req.to)
    |> Enum.reverse()
    |> Enum.map(fn date ->
      day(date, Map.get(by_date, date, []), Map.get(judged_counts, date, 0), dates_by_cve)
    end)
  end

  defp day(date, rows, judged_count, dates_by_cve) do
    {shown, rest} = Enum.split(rows, @row_limit)
    counts = Enum.frequencies_by(rows, fn {event, _finding, _image} -> event.event end)

    %{
      date: date,
      iso_date: Date.to_iso8601(date),
      label: Calendar.strftime(date, "%a %d %b %Y"),
      weekday: Calendar.strftime(date, "%a"),
      iso_weekday: Date.day_of_week(date),
      observed?: rows != [],
      event_count: length(rows),
      new_count: Map.get(counts, "appeared", 0),
      resolved_count: Map.get(counts, "resolved", 0),
      reopened_count: Map.get(counts, "reopened", 0),
      judged_count: judged_count,
      truncated_count: length(rest),
      rows: Enum.map(shown, &day_row(&1, date, dates_by_cve))
    }
  end

  defp day_row({event, finding, image}, date, dates_by_cve) do
    dates = Map.get(dates_by_cve, finding.cve, MapSet.new())

    %{
      event_id: event.id,
      finding_id: finding.id,
      cve: finding.cve,
      severity: finding.severity,
      package_name: finding.package_name,
      package_version: finding.package_version,
      fix: finding.fix,
      kind: event.event,
      occurred_at: event.occurred_at,
      note: event.note,
      image: image_reference(image),
      suppressed: finding.suppressed,
      state: if(is_nil(finding.resolved_at), do: :open, else: :no_longer_observed),
      resolved_at: finding.resolved_at,
      reopened?: (finding.reopen_count || 0) > 0,
      continues?: MapSet.member?(dates, Date.add(date, -1)),
      continued_from?: MapSet.member?(dates, Date.add(date, 1))
    }
  end

  defp image_reference(%{repository: repository, tag: tag})
       when is_binary(repository) and repository != "" and is_binary(tag) and tag != "",
       do: repository <> ":" <> tag

  defp image_reference(%{repository: repository}) when is_binary(repository) and repository != "",
    do: repository

  defp image_reference(image), do: Map.get(image, :digest)
end
