defmodule Triage.DailyTimeline do
  @moduledoc """
  Chronological daily feed of CVE appearances with descriptions.

  Groups finding lifecycle events by the UTC day they occurred, showing which
  CVEs appeared or were re-observed on each day alongside their descriptions.
  This is a read-only projection; it never creates or mutates records.
  Scanner observations are facts, not remediation evidence.
  """

  import Ecto.Query
  alias Triage.Repo

  @page_size 30

  @doc """
  Returns a page of days, newest first. Each day has the date and a list of
  CVE entries that appeared on that day, each with the CVE ID, description,
  severity, package, and first-observed note. `before_date` pages backwards.
  """
  @spec list(keyword()) :: {:ok, map()} | {:error, atom()}
  def list(opts \\ []) do
    before = Keyword.get(opts, :before_date)
    scope = Keyword.get(opts, :scope, "all")

    with {:ok, before_date} <- validate_before(before) do
      days = load_days(before_date, scope)
      has_more? = length(days) > @page_size
      days = Enum.take(days, @page_size)

      {:ok,
       %{
         days: days,
         has_more?: has_more?,
         next_before: next_before(days, has_more?),
         total_cves: count_distinct_cves(scope)
       }}
    end
  end

  defp validate_before(nil), do: {:ok, nil}

  defp validate_before(%Date{} = date), do: {:ok, date}

  defp validate_before(date) when is_binary(date) do
    case Date.from_iso8601(date) do
      {:ok, d} -> {:ok, d}
      _ -> {:error, :invalid_date}
    end
  end

  defp validate_before(_), do: {:error, :invalid_date}

  defp load_days(before_date, scope) do
    event_query =
      from(e in Triage.Inventory.FindingEvent,
        join: f in Triage.Inventory.Finding,
        on: f.id == e.finding_id,
        where: e.event == "appeared",
        where: ^scope_filter(scope),
        where: is_nil(before_date) or fragment("(?::date)", e.occurred_at) < ^before_date,
        select: %{
          date: fragment("(?::date)", e.occurred_at),
          cve: f.cve,
          description: f.description,
          severity: f.severity,
          package: f.package_name,
          package_version: f.package_version,
          note: e.note,
          occurred_at: e.occurred_at
        },
        order_by: [desc: fragment("(?::date)", e.occurred_at), asc: f.cve],
        limit: 500
      )

    event_query
    |> Repo.all()
    |> group_by_day()
  end

  defp scope_filter("all"), do: dynamic([e, f], true)
  defp scope_filter("critical"), do: dynamic([e, f], f.severity == "CRITICAL")
  defp scope_filter(_), do: dynamic([e, f], true)

  defp group_by_day(events) do
    events
    |> Enum.group_by(& &1.date)
    |> Enum.map(fn {date, entries} ->
      # Deduplicate by CVE within a day (multiple packages = one appearance).
      unique = Enum.uniq_by(entries, & &1.cve)

      %{
        date: date,
        count: length(unique),
        cves:
          Enum.map(unique, fn e ->
            %{cve: e.cve, description: e.description || "No description recorded", severity: e.severity, packages: packages_for(entries, e.cve)}
          end)
      }
    end)
    |> Enum.sort_by(& &1.date, {:desc, Date})
  end

  defp packages_for(entries, cve) do
    entries
    |> Enum.filter(&(&1.cve == cve))
    |> Enum.map(&"#{&1.package} #{&1.package_version}")
    |> Enum.uniq()
    |> Enum.join(", ")
  end

  defp next_before([], _has_more), do: nil
  defp next_before(days, true), do: Date.to_iso8601(List.last(days).date)
  defp next_before(_days, false), do: nil

  defp count_distinct_cves(scope) do
    from(f in Triage.Inventory.Finding,
      where: ^scope_filter(scope),
      select: count(f.cve, :distinct)
    )
    |> Repo.one()
  end
end
