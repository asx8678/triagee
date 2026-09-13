defmodule TriageWeb.PageController do
  use TriageWeb, :controller

  alias Triage.{Cases, Intel, Inventory}

  # Rows shown per overview table. Each list also reads its unpaged total, so a
  # capped table never claims to show the whole inventory.
  @overview_rows 10

  def home(conn, _params) do
    counts = read_overview(fn -> {:ok, Inventory.cve_summary_counts()} end)
    occurrences = read_overview(fn -> {:ok, Inventory.summary_counts()} end)
    newest = read_overview(fn -> {:ok, Inventory.newest_cve_groups(@overview_rows)} end)
    newest_total = read_overview(fn -> {:ok, Inventory.count_groups([])} end)

    critical =
      read_overview(fn ->
        {:ok,
         Inventory.list_groups(severity: "CRITICAL", sort: "severity", limit: @overview_rows)}
      end)

    critical_total = read_overview(fn -> {:ok, Inventory.count_groups(severity: "CRITICAL")} end)
    cases = read_overview(fn -> Cases.list_cases() end)
    news = read_overview(fn -> {:ok, Intel.list_cached_news(10)} end)
    receipts = read_overview(fn -> Intel.latest_receipts() end)

    render(conn, :home,
      page_title: "Overview",
      summary: counts,
      occurrence_counts: occurrences,
      newest: shape_group_rows(newest),
      newest_total: shape_total(newest_total),
      critical: shape_group_rows(critical),
      critical_total: shape_total(critical_total),
      news: shape_news(news),
      news_receipts: shape_receipts(receipts),
      recent_cases:
        case cases do
          {:ok, %{rows: rows}} -> {:ok, Enum.take(rows, 5)}
          _ -> :unavailable
        end
    )
  end

  defp shape_group_rows({:ok, rows}) when is_list(rows) do
    {:ok,
     Enum.map(rows, fn g ->
       Map.merge(g, %{
         severity: Inventory.severity_label(g.severity_rank),
         team_list: shape_team_list(g)
       })
     end)}
  end

  defp shape_group_rows(_other), do: :unavailable

  # nil means "the total could not be read", which the template renders by
  # falling back to the rows it actually has instead of inventing a count.
  defp shape_total({:ok, total}) when is_integer(total), do: total
  defp shape_total(_other), do: nil

  defp shape_team_list(%{team_names: names}) when is_list(names) and length(names) > 0,
    do: names |> Enum.uniq() |> Enum.sort() |> Enum.join(", ")

  defp shape_team_list(_), do: nil

  defp shape_news({:ok, rows}) when is_list(rows) do
    {:ok,
     Enum.map(rows, fn n ->
       Map.merge(n, %{
         source: n.source |> to_string(),
         link: if(Triage.Intel.safe_link?(n.link), do: n.link, else: nil)
       })
     end)}
  end

  defp shape_news(_other), do: :unavailable

  defp shape_receipts({:ok, receipts}) when is_list(receipts) do
    Enum.map(receipts, fn receipt ->
      receipt
      |> Map.from_struct()
      |> Map.merge(%{attempted_at_label: relative_receipt_label(receipt)})
    end)
  end

  defp shape_receipts(_other), do: []

  defp relative_receipt_label(%{attempted_at: nil}), do: "never"

  defp relative_receipt_label(%{attempted_at: at}) do
    case TriageWeb.UIComponents.relative_time(at) do
      nil -> "unknown"
      label -> label
    end
  end

  defp read_overview(reader) do
    reader.()
  rescue
    _ -> :unavailable
  catch
    :exit, _ -> :unavailable
  end
end
