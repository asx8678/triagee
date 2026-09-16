defmodule Triage.Timeline.History do
  @moduledoc "Read-only timeline history pages and SQL aggregates, independent of rendering."
  import Ecto.Query
  alias Triage.Cases.Review
  alias Triage.Inventory.FindingEvent
  alias Triage.Repo

  @event_page_size 50
  @case_page_size 10
  @max_id Integer.pow(2, 63) - 1

  def event_page_size, do: @event_page_size
  def case_page_size, do: @case_page_size

  @spec valid_cursor?(term()) :: boolean()
  def valid_cursor?(nil), do: true
  def valid_cursor?(id), do: is_integer(id) and id > 0 and id <= @max_id

  @doc "Chronological keyset page; the cursor must belong to the same scoped finding set."
  def event_page(finding_ids, cursor, req) do
    base = from(e in FindingEvent, where: e.finding_id in ^finding_ids)

    with {:ok, query} <- after_event(base, cursor) do
      fetch_limit = @event_page_size + 1

      rows =
        Repo.all(from(e in query, order_by: [asc: e.occurred_at, asc: e.id], limit: ^fetch_limit))

      summary = event_summary(base, req)

      {:ok,
       page(rows, @event_page_size, cursor, summary.event_count) |> Map.put(:summary, summary)}
    end
  end

  defp after_event(query, nil), do: {:ok, query}

  defp after_event(query, id) do
    case Repo.one(from(e in query, where: e.id == ^id, select: e.occurred_at)) do
      nil -> {:error, :invalid_cursor}
      at -> {:ok, where(query, [e], e.occurred_at > ^at or (e.occurred_at == ^at and e.id > ^id))}
    end
  end

  defp event_summary(query, req) do
    summary =
      Repo.one(
        from(e in query,
          select: %{
            event_count: count(e.id),
            appeared_count: filter(count(e.id), e.event == "appeared"),
            resolved_events: filter(count(e.id), e.event == "resolved"),
            reopened_events: filter(count(e.id), e.event == "reopened"),
            observed_day_count: count(fragment("?::date", e.occurred_at), :distinct),
            window_observed_count:
              filter(
                count(fragment("?::date", e.occurred_at), :distinct),
                e.occurred_at >= ^req.from_dt and e.occurred_at <= ^req.to_dt
              ),
            first_date: type(min(fragment("?::date", e.occurred_at)), :date),
            last_date: type(max(fragment("?::date", e.occurred_at)), :date)
          }
        )
      )

    summary
    |> Map.put(:first_seen_in_window?, in_window?(summary.first_date, req))
    |> Map.put(:last_observed_in_window?, in_window?(summary.last_date, req))
    |> Map.drop([:first_date, :last_date])
  end

  @doc "The query must bind scoped cases as :case and their findings as :finding."
  def case_page(query, cursor) do
    with :ok <- check_case_cursor(query, cursor) do
      total = Repo.aggregate(query, :count)
      after_query = if cursor, do: where(query, [case: c], c.id > ^cursor), else: query
      fetch_limit = @case_page_size + 1

      rows =
        Repo.all(
          from([case: c] in after_query, order_by: [asc: c.id], limit: ^fetch_limit, select: c)
        )

      result = page(rows, @case_page_size, cursor, total)
      histories = Triage.Cases.History.previews(result.rows)

      rows =
        Enum.map(result.rows, fn cse -> %{id: cse.id, data: Map.fetch!(histories, cse.id)} end)

      {:ok, %{result | rows: rows} |> Map.put(:truncated_count, max(total - length(rows), 0))}
    end
  end

  defp check_case_cursor(_query, nil), do: :ok

  defp check_case_cursor(query, id) do
    if Repo.exists?(where(query, [case: c], c.id == ^id)),
      do: :ok,
      else: {:error, :invalid_cursor}
  end

  # Counts cover every matching case, while metadata is capped independently
  # per CVE. A busy CVE cannot consume another lane's case preview budget.
  def case_summaries(query) do
    totals =
      from([case: c, finding: f] in query,
        left_join: r in Review,
        on: r.case_id == c.id,
        group_by: f.cve,
        select: {f.cve, %{case_count: count(c.id, :distinct), judged_count: count(r.id)}}
      )
      |> Repo.all()

    ranked =
      from([case: c, finding: f] in query,
        left_join: r in Review,
        on: r.case_id == c.id,
        group_by: [c.id, f.cve],
        windows: [per_cve: [partition_by: f.cve, order_by: [asc: c.id]]],
        select: %{
          cve: f.cve,
          id: c.id,
          owner: c.owner,
          environment: c.environment,
          revision: c.revision,
          review_count: count(r.id),
          position: over(row_number(), :per_cve)
        }
      )

    limit = @case_page_size

    rows =
      Repo.all(
        from(r in subquery(ranked),
          where: r.position <= ^limit,
          order_by: [asc: r.cve, asc: r.id]
        )
      )

    by_cve = Enum.group_by(rows, & &1.cve, &Map.drop(&1, [:cve, :position]))

    Map.new(totals, fn {cve, counts} ->
      shown = Map.get(by_cve, cve, [])

      {cve,
       Map.merge(counts, %{
         cases: shown,
         cases_truncated_count: max(counts.case_count - length(shown), 0)
       })}
    end)
  end

  defp page(rows, limit, cursor, total) do
    shown = Enum.take(rows, limit)
    has_more? = length(rows) > limit

    %{
      rows: shown,
      shown: length(shown),
      total: total,
      cursor: cursor,
      has_more?: has_more?,
      next_after: if(has_more?, do: List.last(shown).id)
    }
  end

  defp in_window?(nil, _req), do: false

  defp in_window?(date, req),
    do: Date.compare(date, req.from) != :lt and Date.compare(date, req.to) != :gt
end
