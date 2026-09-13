defmodule TriageWeb.TimelineLive.Grid do
  @moduledoc """
  The weekday x week grid: one row per day of the week, one column per week, and
  each cell counting the CVEs whose first recorded observation falls on that
  date.

  It is a real table with a caption rather than a decorative graphic, so the
  counts are readable and copyable without relying on colour. Intensity is
  decorative; the count and the text equivalent carry the meaning.
  """

  use TriageWeb, :html

  attr :grid, :map, required: true

  def weekday_grid(assigns) do
    ~H"""
    <section id="tl-grid" class="tl-section" aria-labelledby="tl-grid-title">
      <div class="section-header">
        <h2 id="tl-grid-title">New CVEs by day of week</h2>
        <p class="supporting">
          Oldest week on the left, current week on the right. A cell counts CVEs whose
          first recorded observation falls on that day, not CVE publication dates.
          Days after today are not yet observed.
        </p>
      </div>

      <div
        id="tl-grid-scroll"
        class="table-region"
        role="region"
        aria-label="New CVEs by week and day of week"
        tabindex="0"
      >
        <table id="tl-grid-table" class="tl-grid-table">
          <caption class="sr-only">
            CVEs with a first recorded observation, by week and day of week.
          </caption>
          <thead>
            <tr>
              <th scope="col">Day</th>
              <th :for={week <- @grid.weeks} scope="col">
                <time datetime={Date.to_iso8601(week.start)}>{week.label}</time>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr :for={row <- @grid.rows} id={"tl-grid-" <> row.weekday}>
              <th scope="row">{row.weekday}</th>
              <td :for={cell <- row.cells} class={["tl-cell", cell_class(cell, @grid.max_count)]}>
                <span class="tl-cell-value" aria-hidden="true">{cell.count}</span>
                <span class="sr-only">{cell_text(cell)}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p class="supporting">
        Cell shading shows relative volume only. A zero means no first observation was
        recorded that day; it is not evidence that no vulnerable image existed.
      </p>
    </section>
    """
  end

  defp cell_class(%{in_future?: true}, _max_count), do: "tl-cell-future"
  defp cell_class(%{count: 0}, _max_count), do: "tl-cell-zero"
  defp cell_class(%{count: count}, max_count), do: "tl-cell-" <> intensity(count, max_count)

  defp intensity(_count, max_count) when max_count <= 0, do: "low"

  defp intensity(count, max_count) do
    ratio = count / max_count

    cond do
      ratio > 0.75 -> "high"
      ratio > 0.4 -> "medium"
      true -> "low"
    end
  end

  defp cell_text(%{in_future?: true} = cell), do: "#{date_label(cell.date)}: not yet observed"
  defp cell_text(%{count: 0} = cell), do: "#{date_label(cell.date)}: no new CVE recorded"

  defp cell_text(%{count: 1} = cell),
    do: "#{date_label(cell.date)}: 1 CVE newly recorded"

  defp cell_text(cell),
    do: "#{date_label(cell.date)}: #{cell.count} CVEs newly recorded"

  defp date_label(date), do: Calendar.strftime(date, "%d %b %Y")
end
