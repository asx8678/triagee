defmodule TriageWeb.PageController do
  use TriageWeb, :controller

  alias Triage.Inventory

  # Rows shown per overview rail. Each rail also reads the unpaged total, so a
  # capped rail never claims to show the whole inventory.
  @rail_rows 5

  # Posture and two bounded rails, nothing else: the critical work list is the
  # Triage page's job, case history belongs to the case pages, and public
  # intelligence lives under Data tools · Intel.
  def home(conn, _params) do
    counts = read_overview(fn -> {:ok, Inventory.cve_summary_counts()} end)
    occurrences = read_overview(fn -> {:ok, Inventory.summary_counts()} end)
    active_now = read_overview(fn -> {:ok, Inventory.active_now_cve_groups(@rail_rows)} end)
    newest = read_overview(fn -> {:ok, Inventory.newest_cve_groups(@rail_rows)} end)
    advisory_total = read_overview(fn -> {:ok, Inventory.count_groups([])} end)

    render(conn, :home,
      page_title: "Overview",
      summary: counts,
      occurrence_counts: occurrences,
      active_now: shape_group_rows(active_now),
      newest: shape_group_rows(newest),
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

  # nil means "the total could not be read", which the template renders as an
  # explicit unknown instead of inventing a count.
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
