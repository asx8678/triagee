defmodule TriageWeb.TimelineLive.Chart do
  @moduledoc """
  The connected lane chart: one SVG track per CVE across the window's days.

  The chart can only ever restate what the day bands, the grid and the lane
  table already say, so it is `aria-hidden` and its caption says so. A solid
  segment joins two adjacent days this CVE was recorded on, a dashed segment
  joins two recorded days with no recorded observation in between, and a lane
  with one recorded day draws no segment at all: a line is never a claim of
  continuous presence, and a missing line is never a claim that nothing existed.

  Every segment and marker carries a `<title>` in the app's own vocabulary, so
  hovering explains the geometry rather than leaving it to be guessed.
  """

  use TriageWeb, :html

  # Spacing is a display choice, so it is an input to the chart rather than a
  # constant: "detail" keeps day-sized spacing and scrolls, "fit" narrows the
  # tracks so the window the operator chose is visible without a nested scroll.
  @detail_day_width 26
  @min_fit_day_width 8
  # The width the fit calculation aims at. The server cannot measure the browser,
  # so it fits the window to a desktop content width and leaves the region
  # scrollable at narrower viewports rather than guessing per request.
  # Measured container width is supplied by the resize hook.
  @gutter 180
  @row_height 34
  @axis_height 64
  @marker_gap 6
  @kinds ["open", "ended", "reopened", "suppressed"]

  attr :chart, :map, required: true
  attr :lanes, :map, required: true
  attr :scale, :string, default: "fit"
  attr :width, :integer, default: 1000
  attr :action_paths, :map, default: %{}
  attr :selected_cve, :string, default: nil

  def lane_chart(assigns) do
    chart = assigns.chart

    selected =
      Enum.find(
        Map.get(chart, :available_tracks, chart.tracks),
        &(&1.cve == assigns.selected_cve)
      )

    tracks =
      if selected && not Enum.any?(chart.tracks, &(&1.cve == selected.cve)) do
        Enum.take(chart.tracks, max(length(chart.tracks) - 1, 0)) ++ [selected]
      else
        chart.tracks
      end

    assigns = assign(assigns, :chart, %{chart | tracks: tracks})

    assigns =
      assign(assigns,
        layout:
          layout(
            assigns.chart,
            day_width(assigns.scale, length(assigns.chart.dates), assigns.width)
          )
      )

    ~H"""
    <section id="tl-chart" class="tl-section" aria-labelledby="tl-chart-title">
      <div class="section-header">
        <h2 id="tl-chart-title">Recorded observations across the window</h2>
        <p class="supporting">
          Oldest day on the left, newest on the right; one track per CVE, most severe
          current scanner severity first.
        </p>
      </div>

      <p id="tl-chart-truncation" class="supporting tl-chart-truncation">
        Showing <strong>{@chart.shown} of {@chart.total} CVEs</strong>, ranked by current scanner severity.
        <a href="#tl-lanes-table">View lane table ({@lanes.shown})</a>
        · Unplotted lanes are not quiet lanes.
      </p>

      <figure class="tl-chart-figure">
        <p id="tl-chart-scroll-hint" class="supporting tl-chart-mobile-hint">
          Scroll horizontally for later dates. With a keyboard, focus the chart and use the arrow keys.
          <a href="#tl-lanes-table">Use the lane table</a>
          for the full text detail.
        </p>
        <div
          id="tl-chart-scroll"
          phx-hook="TimelineWidth"
          data-selected-cve={@selected_cve}
          class="table-region tl-chart-region"
          role="region"
          tabindex="0"
          aria-label="Recorded observations across the window, scrollable"
        >
          <svg
            class={["tl-chart", "tl-chart-#{@scale}"]}
            width={@layout.width}
            height={@layout.height}
            viewBox={"0 0 #{@layout.width} #{@layout.height}"}
            aria-hidden="true"
            focusable="false"
          >
            <defs>
              <marker
                :for={kind <- @layout.kinds}
                id={"tl-c-arrow-" <> kind}
                viewBox="0 0 10 10"
                refX="10"
                refY="5"
                markerWidth="6.5"
                markerHeight="6.5"
                markerUnits="userSpaceOnUse"
                orient="auto"
              >
                <path class={["tl-c-head", "tl-c-" <> kind]} d="M0 1 L10 5 L0 9 z" />
              </marker>
            </defs>

            <g class="tl-chart-axis">
              <line
                class="tl-c-axis-line"
                x1={@layout.gutter}
                y1={@layout.axis_y}
                x2={@layout.width}
                y2={@layout.axis_y}
              />
              <text
                class="tl-c-week-label"
                x={@layout.gutter - 10}
                y={@layout.week_label_y}
                text-anchor="end"
              >
                CVE
              </text>

              <g :for={date <- @layout.dates}>
                <line
                  class={["tl-c-grid", date.week_start? && "tl-c-grid-week"]}
                  x1={date.left}
                  y1={@layout.axis_y}
                  x2={date.left}
                  y2={@layout.height}
                />
                <line
                  class={["tl-c-tick", date.week_start? && "tl-c-tick-week"]}
                  x1={date.left}
                  y1={tick_top(date, @layout)}
                  x2={date.left}
                  y2={@layout.axis_y}
                />
                <text
                  :if={@scale == "detail"}
                  class="tl-c-weekday"
                  x={date.left + 3}
                  y={@layout.weekday_y}
                  text-anchor="start"
                >
                  {String.slice(date.weekday, 0, 2)}
                </text>
                <text
                  :if={date.week_start?}
                  class="tl-c-week-label"
                  x={min(date.left + 3, @layout.width - 48)}
                  y={@layout.week_label_y}
                  text-anchor="start"
                >
                  {date.day} {date.month}
                </text>
              </g>

              <line
                class="tl-c-today"
                x1={@layout.today_x}
                y1={@layout.today_label_y + 3}
                x2={@layout.today_x}
                y2={@layout.height}
              />
              <text
                class="tl-c-today-label"
                x={@layout.today_x - 4}
                y={@layout.today_label_y}
                text-anchor="end"
              >
                today
              </text>
            </g>

            <g
              :for={track <- @layout.tracks}
              id={"tl-track-" <> track.cve}
              class={["tl-chart-track", track.cve == @selected_cve && "tl-selected"]}
              aria-current={if track.cve == @selected_cve, do: "true"}
            >
              <title>{track.span_label}</title>

              <rect
                :if={track.band? or track.cve == @selected_cve}
                class="tl-c-band"
                x={@layout.gutter}
                y={track.y - div(@layout.row_height, 2)}
                width={@layout.track_width}
                height={@layout.row_height}
              />

              <rect
                class={["tl-c-sev", track.severity_chip.class]}
                x={@layout.sev_x}
                y={track.y - 7}
                width="16"
                height="14"
                rx="2"
              />
              <text
                class={["tl-c-sev-text", track.severity_chip.class]}
                x={@layout.sev_x + 8}
                y={track.y + 3.5}
                text-anchor="middle"
              >
                {track.severity_chip.letter}
              </text>

              <a
                href={Map.get(@action_paths, track.cve, ~p"/cves/#{track.cve}")}
                aria-label={
                  if Map.has_key?(@action_paths, track.cve),
                    do: "Triage #{track.cve} — action required",
                    else: "View #{track.cve}"
                }
              >
                <text
                  class="tl-chart-cve"
                  x={@layout.gutter - 10}
                  y={track.y + 4}
                  text-anchor="end"
                >
                  {track.cve}
                </text>
              </a>

              <line
                :if={track.entry_x}
                class="tl-c-entry"
                x1={@layout.gutter + 1}
                y1={track.y}
                x2={track.entry_x}
                y2={track.y}
              />

              <line
                :for={segment <- track.segments}
                class={segment_class(segment)}
                x1={segment.x1}
                y1={segment.y}
                x2={segment.x2}
                y2={segment.y}
                marker-end={"url(#tl-c-arrow-" <> segment.kind <> ")"}
              >
                <title>{segment.title}</title>
              </line>

              <g :for={point <- track.points} class={["tl-c-point", "tl-c-" <> point.kind]}>
                <title>{point.kind_title}</title>
                <line
                  :if={point.single?}
                  class="tl-c-pin"
                  x1={point.x}
                  y1={track.y - 8}
                  x2={point.x}
                  y2={track.y - 2}
                />
                <circle class="tl-c-halo" cx={point.x} cy={track.y} r="7" />
                <circle class="tl-c-dot" cx={point.x} cy={track.y} r="4.5" />
              </g>
            </g>
          </svg>
        </div>

        <figcaption class="supporting tl-chart-caption">
          This chart is hidden from screen readers: every marker is a recorded observation, listed
          in the day bands and counted per CVE in the lane table.
        </figcaption>
      </figure>

      <.explain
        id="tl-chart-key"
        summary="How to read lines and gaps"
      >
        <p>
          A solid line joins two adjacent days this CVE was recorded on. A dashed line joins two
          recorded days with no recorded observation in between.
          A line is not a claim that the CVE was present in between, and a missing line is not a claim that nothing existed.
          The Scale control changes spacing only: the days drawn and the gaps between them do not change.
        </p>
      </.explain>
      <div class="tl-chart-legend-groups">
        <div class="tl-chart-legend-group">
          <h3 class="tl-chart-legend-title">Markers — one per recorded observation</h3>
          <ul class="tl-chart-legend">
            <li :for={{class, text} <- legend_marks()}>
              <span class={["tl-c-key", class]} aria-hidden="true"></span>
              {text}
            </li>
          </ul>
        </div>
        <div class="tl-chart-legend-group">
          <h3 class="tl-chart-legend-title">Lines — drawn only between two recorded days</h3>
          <ul class="tl-chart-legend">
            <li>
              <svg
                class="tl-c-key-line"
                width="34"
                height="10"
                viewBox="0 0 34 10"
                aria-hidden="true"
                focusable="false"
              >
                <line
                  class="tl-c-seg tl-c-seg-solid tl-c-open"
                  x1="1"
                  y1="5"
                  x2="22"
                  y2="5"
                  marker-end="url(#tl-c-arrow-open)"
                />
              </svg>
              recorded on two adjacent days
            </li>
            <li>
              <svg
                class="tl-c-key-line"
                width="34"
                height="10"
                viewBox="0 0 34 10"
                aria-hidden="true"
                focusable="false"
              >
                <line
                  class="tl-c-seg tl-c-seg-dashed tl-c-ended"
                  x1="1"
                  y1="5"
                  x2="22"
                  y2="5"
                  marker-end="url(#tl-c-arrow-ended)"
                />
              </svg>
              recorded at both ends; nothing recorded in between
            </li>
            <li>
              <svg
                class="tl-c-key-line"
                width="34"
                height="10"
                viewBox="0 0 34 10"
                aria-hidden="true"
                focusable="false"
              >
                <line class="tl-c-entry" x1="1" y1="5" x2="30" y2="5" />
              </svg>
              also recorded before this window starts
            </li>
            <li>
              <svg
                class="tl-c-key-line"
                width="34"
                height="10"
                viewBox="0 0 34 10"
                aria-hidden="true"
                focusable="false"
              >
                <line class="tl-c-today" x1="16" y1="0" x2="16" y2="10" />
              </svg>
              today, where the window ends
            </li>
            <li>
              <svg
                class="tl-c-key-line"
                width="34"
                height="10"
                viewBox="0 0 34 10"
                aria-hidden="true"
                focusable="false"
              >
                <line class="tl-c-pin tl-c-open" x1="16" y1="1" x2="16" y2="7" />
                <circle class="tl-c-dot tl-c-open" cx="16" cy="7" r="3.5" />
              </svg>
              a single recorded day, so no line is drawn
            </li>
          </ul>
        </div>
      </div>
    </section>
    """
  end

  defp legend_marks do
    [
      {"tl-c-open", "first recorded observation (filled marker)"},
      {"tl-c-ended", "no longer observed in local inventory (hollow marker)"},
      {"tl-c-reopened", "observed again locally"},
      {"tl-c-suppressed", "suppression flag currently set (imported scanner data)"}
    ]
  end

  ## Layout

  # Fit never widens a short window past day-sized spacing, and a day is never
  # drawn narrower than the floor. The control changes scale, not the window: the
  # days drawn and the gaps between them are the same in both modes.
  defp day_width("detail", _days, _width), do: @detail_day_width

  defp day_width(_fit, days, width) do
    max((width - @gutter - 8) / max(days, 1), @min_fit_day_width)
  end

  defp layout(chart, day_width) do
    xs =
      chart.dates
      |> Enum.with_index()
      |> Map.new(fn {date, index} ->
        %{
          x: @gutter + index * day_width + day_width / 2,
          left: @gutter + index * day_width
        }
        |> then(&{date.iso_date, &1})
      end)

    tracks =
      chart.tracks
      |> Enum.with_index()
      |> Enum.map(fn {track, index} -> track_layout(track, index, xs) end)

    %{
      width: round(@gutter + length(chart.dates) * day_width + 8),
      height: @axis_height + length(tracks) * @row_height + 4,
      gutter: @gutter,
      row_height: @row_height,
      axis_y: @axis_height - 1,
      tick_top: @axis_height - 11,
      week_tick_top: @axis_height - 23,
      weekday_y: @axis_height - 16,
      today_label_y: 13,
      week_label_y: 32,
      track_width: length(chart.dates) * day_width + 4,
      sev_x: 2,
      kinds: @kinds,
      dates: Enum.map(chart.dates, &date_layout(&1, xs)),
      tracks: tracks,
      today_x: Map.fetch!(xs, List.last(chart.dates).iso_date).x
    }
  end

  defp date_layout(date, xs) do
    %{
      iso_date: date.iso_date,
      day: date.day,
      month: date.month,
      weekday: date.weekday,
      week_start?: date.week_start?,
      today?: date.today?,
      label: date.label,
      x: Map.fetch!(xs, date.iso_date).x,
      left: Map.fetch!(xs, date.iso_date).left
    }
  end

  defp tick_top(%{week_start?: true}, layout), do: layout.week_tick_top
  defp tick_top(_date, layout), do: layout.tick_top

  defp track_layout(track, index, xs) do
    y = @axis_height + index * @row_height + div(@row_height, 2)
    single? = length(track.points) == 1

    points =
      Enum.map(track.points, fn point ->
        %{
          date: point.date,
          iso_date: point.iso_date,
          label: point.label,
          x: Map.fetch!(xs, point.iso_date).x,
          kind: point_kind(point),
          single?: single?,
          kind_title: kind_title(point)
        }
      end)

    segments =
      points
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.map(fn [from, to] -> segment(from, to, y) end)

    %{
      cve: track.cve,
      y: y,
      band?: rem(index, 2) == 1,
      severity_chip: severity_chip(track.severity),
      points: points,
      segments: segments,
      entry_x: entry_x(track, points),
      span_label: span_label(track, points, segments)
    }
  end

  defp entry_x(%{recorded_before?: true}, [first | _rest]), do: first.x - @marker_gap
  defp entry_x(_track, _points), do: nil

  defp segment(from, to, y) do
    dashed? = Date.diff(to.date, from.date) != 1

    %{
      x1: from.x,
      x2: to.x - @marker_gap,
      y: y,
      dashed?: dashed?,
      kind: to.kind,
      title: segment_title(from, to, dashed?)
    }
  end

  defp segment_class(segment) do
    style = if segment.dashed?, do: "tl-c-seg-dashed", else: "tl-c-seg-solid"
    ["tl-c-seg", style, "tl-c-" <> segment.kind]
  end

  defp segment_title(from, to, false) do
    "#{from.label} and #{to.label} are adjacent days this CVE is recorded on."
  end

  defp segment_title(from, to, true) do
    "#{from.label} and #{to.label} both have a recorded observation for this CVE; " <>
      "the days in between have none recorded."
  end

  # Suppression first, then the lifecycle kind: the same precedence the day-band
  # glyphs use, so one state never has two meanings in the same view.
  defp point_kind(%{suppressed?: true}), do: "suppressed"
  defp point_kind(%{kinds: kinds}) when is_list(kinds), do: kind_of(kinds)

  defp kind_of(kinds) do
    cond do
      "resolved" in kinds -> "ended"
      "reopened" in kinds -> "reopened"
      true -> "open"
    end
  end

  defp kind_title(point) do
    kinds = Enum.map_join(point.kinds, ", ", &kind_label/1)
    base = "#{point.label}: #{kinds}"

    if point.suppressed? do
      base <>
        "; suppression flag currently set from the imported scanner data (no recorded date or author)"
    else
      base
    end
  end

  defp kind_label("appeared"), do: "first recorded observation"
  defp kind_label("resolved"), do: "no longer observed in local inventory"
  defp kind_label("reopened"), do: "observed again locally"
  defp kind_label(_other), do: "unrecognized lifecycle event"

  defp severity_chip(severity) do
    name = severity |> to_string() |> String.downcase()

    if name in ["critical", "high", "medium", "low"] do
      %{
        class: "tl-c-sev-" <> name,
        letter: String.first(String.upcase(name)),
        label: String.capitalize(name)
      }
    else
      %{class: "tl-c-sev-unknown", letter: "?", label: "no recorded severity"}
    end
  end

  defp span_label(track, [], _segments),
    do: "#{track.cve}: no recorded observation in this window."

  defp span_label(track, points, segments) do
    first = List.first(points)
    last = List.last(points)

    [
      "#{track.cve}: #{length(points)} recorded day(s), #{span_range(first, last)}.",
      "Current scanner severity: #{severity_chip(track.severity).label}.",
      gaps(segments),
      if(track.recorded_before?, do: "Also recorded before this window starts.", else: nil)
    ]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" ")
  end

  defp span_range(first, last) do
    if first.iso_date == last.iso_date, do: first.label, else: "#{first.label} to #{last.label}"
  end

  defp gaps(segments) do
    case Enum.count(segments, & &1.dashed?) do
      0 -> nil
      count -> "#{count} gap(s) with no recorded observation between recorded days."
    end
  end
end
