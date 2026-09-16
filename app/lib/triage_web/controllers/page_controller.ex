defmodule TriageWeb.PageController do
  use TriageWeb, :controller

  alias Triage.Inventory

  @rail_rows 5

  # Old overview bookmarks land on the single canonical list, not a hidden mode.
  def home(conn, %{"view" => view}) when view in ["recent", "newest"],
    do: redirect(conn, to: ~p"/")

  def home(conn, %{"view" => _invalid}) do
    conn |> put_status(:bad_request) |> text("Invalid overview view. Open / for recent findings.")
  end

  def home(conn, _params) do
    counts = read_overview(fn -> {:ok, Inventory.cve_summary_counts()} end)
    occurrences = read_overview(fn -> {:ok, Inventory.summary_counts()} end)
    groups = read_overview(fn -> {:ok, Inventory.active_now_cve_groups(@rail_rows)} end)
    advisory_total = read_overview(fn -> {:ok, Inventory.count_groups([])} end)

    render(conn, :home,
      page_title: "Overview",
      summary: counts,
      occurrence_counts: occurrences,
      groups: shape_group_rows(groups),
      advisory_total: shape_total(advisory_total)
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

  # Unknown is explicit rather than an invented zero.
  defp shape_total({:ok, total}) when is_integer(total), do: total
  defp shape_total(_other), do: nil

  defp shape_team_list(%{team_names: names}) when is_list(names) and names != [],
    do: names |> Enum.uniq() |> Enum.sort() |> Enum.join(", ")

  defp shape_team_list(_), do: nil

  defp read_overview(reader) do
    reader.()
  rescue
    _ -> :unavailable
  catch
    :exit, _ -> :unavailable
  end
end
