defmodule TriageWeb.TimelineLive.Chart do
  @moduledoc """
  Recorded lifecycle state through today. Red denotes open state, grey denotes
  advisory-wide whitelisting. Status lines are not continuous observation evidence.
  Closure markers mean recorded disappearance, not independently verified remediation.
  """

  use TriageWeb, :html
  alias TriageWeb.TimelineFilters

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
  @kinds ["open", "ended", "reopened", "suppressed", "whitelisted"]

  attr :chart, :map, required: true
  attr :lanes, :map, required: true
  attr :scale, :string, default: "fit"
  attr :width, :integer, default: 1000
  attr :action_paths, :map, default: %{}
  attr :selected_cve, :string, default: nil
  attr :filters, :map, default: %{}

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
        <.link
          :if={@filters[:chart] != "all"}
          id="tl-show-all"
          patch={TimelineFilters.path(@filters, %{chart: "all"})}
        >Show all</.link>
        <.link
          :if={@filters[:chart] == "all"}
          id="tl-show-20"
          patch={TimelineFilters.path(@filters, %{chart: "20"})}
        >Show 20</.link>
        <span :if={@chart.shown < @chart.total}>· Unplotted lanes are not quiet lanes.</span>
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
                markerWidth="10"
                markerHeight="10"
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
              class={[
                "tl-chart-track",
                track.cve == @selected_cve && "tl-selected",
                track.severity_chip.class in ["tl-c-sev-critical", "tl-c-sev-high"] && "tl-c-danger"
              ]}
              aria-current={if track.cve == @selected_cve, do: "true"}
            >
              <title>{track.span_label}</title>

              <rect
                :if={track.band? or track.cve == @selected_cve or track.ended?}
                class={["tl-c-band", track.ended? && "tl-c-band-ended"]}
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

              <g :if={track.entry_detect?} class="tl-c-point tl-c-open">
                <title>
                  Detected before this window; the dashed line continues the recorded history.{track.affected_note}
                </title>
                <circle class="tl-c-chip" cx={@layout.gutter + 2} cy={track.y} r="3.5" />
              </g>

              <line
                :for={segment <- track.segments}
                class={segment_class(segment)}
                x1={segment.x1}
                y1={segment.y}
                x2={segment.x2}
                y2={segment.y}
                marker-end={if segment.arrow?, do: "url(#tl-c-arrow-" <> segment.kind <> ")"}
              >
                <title>{segment.title}</title>
              </line>

              <g :for={wl <- track.whitelists} class="tl-c-whitelist-marker tl-c-whitelisted">
                <title>
                  {wl.label} — {wl.from}{if wl.reason, do: ". Reason: " <> wl.reason}{track.affected_note}
                </title>
                <circle class="tl-c-chip" cx={wl.x} cy={track.y} r="3.5" />
              </g>
              <g
                :for={point <- track.points}
                :if={point.detection? and point.kind == "ended"}
                class="tl-c-point tl-c-open tl-c-same-day-detection"
              >
                <title>
                  Detected on {point.iso_date}, before same-day disappearance{track.affected_note}
                </title>
                <circle class="tl-c-chip" cx={point.x - 16} cy={track.y} r="3.5" />
              </g>
              <g
                :for={point <- track.points}
                class={[
                  "tl-c-point",
                  "tl-c-" <> point.kind,
                  point.whitelisted? && point.kind != "ended" && "tl-c-whitelisted"
                ]}
              >
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
                <circle class="tl-c-chip" cx={point.x} cy={track.y} r="3.5" />
              </g>
            </g>
          </svg>
        </div>

        <figcaption class="supporting tl-chart-caption">
          This chart is hidden from screen readers: observations and decisions are described in the lane table. Lines show recorded status, not verified continuous exposure.
        </figcaption>
      </figure>

      <p id="tl-chart-key" class="supporting">
        Red dots record detection; the black line behind them carries the open state through
        today. Every lane starts with a detection — a red dot at the window edge marks a CVE
        detected before the window. Black dots record a whitelist decision and every observation
        day it covers; the grey line behind the black dot runs while all displayed placements
        stay whitelisted until expiry or a superseding decision. Partial whitelists do not grey
        the whole CVE, and lane backgrounds stay white unless a whitelist or fix colors them.
        Green dots record disappearance, not a verified fix. Missing observations do not prove
        safety or continuous exposure.
      </p>
    </section>
    """
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
          open?: Map.get(point, :open?, point_kind(point) != "ended"),
          detected_on: Map.get(point, :detected_on),
          detection?: Enum.any?(point.kinds, &(&1 in ["appeared", "reopened"])),
          single?: single?,
          kind_title: kind_title(point) <> affected_note(track) <> fix_note(point)
        }
      end)
      |> Enum.map(&Map.put(&1, :whitelisted?, whitelisted_on?(track, &1.date, &1.detected_on)))
      |> Enum.map(fn point ->
        if point.detection?, do: Map.put(point, :whitelisted?, false), else: point
      end)

    segments = status_segments(track, points, xs, y)

    %{
      cve: track.cve,
      y: y,
      band?: rem(index, 2) == 1,
      ended?: Map.get(track, :state) == :no_longer_observed,
      affected_note: affected_note(track),
      severity_chip: severity_chip(track.severity),
      points: points,
      segments: segments,
      whitelists:
        Map.get(track, :whitelists, [])
        |> Enum.filter(
          &(&1.decision == "accepted_risk" and Map.has_key?(xs, Date.to_iso8601(&1.from)))
        )
        |> Enum.map(fn w ->
          x = xs[Date.to_iso8601(w.from)].x

          # A whitelist decided hours after a same-day detection shares the day
          # column: nudge it right so the red detection dot stays visible.
          if Enum.any?(points, &(&1.iso_date == Date.to_iso8601(w.from))) do
            Map.put(w, :x, x + 16)
          else
            Map.put(w, :x, x)
          end
        end),
      entry_detect?:
        Map.get(track, :recorded_before?, false) and points != [] and
          hd(points).kind == "ended",
      entry_x: entry_x(track, points),
      span_label: span_label(track, points, segments)
    }
  end

  defp entry_x(%{recorded_before?: true}, [first | _rest]), do: first.x - @marker_gap
  defp entry_x(_track, _points), do: nil

  # A day is whitelisted when every placement of the advisory is covered by an
  # active accepted-risk decision recorded no earlier than the latest
  # detection: the same coverage the grey line uses, so a W marker never
  # contradicts the line beneath it.
  defp whitelisted_on?(track, date, detected_on) do
    decisions =
      Map.get(track, :whitelists, []) |> Enum.filter(&(Date.compare(&1.from, date) != :gt))

    latest = Enum.reduce(decisions, %{}, &Map.put(&2, &1.placement_id, &1))
    ids = Map.get(track, :placement_ids, [])

    ids != [] and
      Enum.all?(ids, fn id ->
        decision = latest[id] || latest[nil]

        decision && decision.decision == "accepted_risk" &&
          (is_nil(detected_on) || Date.compare(decision.from, detected_on) != :lt) &&
          (is_nil(decision.until) || Date.compare(date, decision.until) == :lt)
      end)
  end

  defp status_segments(track, points, xs, y) do
    xs
    |> Enum.sort_by(fn {date, _} -> date end)
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.flat_map(&status_segment(&1, track, points, y))
    |> mark_run_arrows()
  end

  defp status_segment([{iso, from}, {_, to}], track, points, y) do
    date = Date.from_iso8601!(iso)
    point = points |> Enum.filter(&(Date.compare(&1.date, date) != :gt)) |> List.last()

    if point && point.open? do
      covered = whitelisted_on?(track, date, point.detected_on)

      kind = if covered, do: "whitelisted", else: "open"

      [
        %{
          x1: from.x,
          x2: to.x,
          y: y,
          dashed?: false,
          kind: kind,
          title:
            "#{iso}: #{if covered, do: "Whitelisted", else: "Open / not fully whitelisted"}; recorded state, not continuous observation."
        }
      ]
    else
      []
    end
  end

  # An arrowhead closes each contiguous run — where the state changes and at
  # the line's end — so the line keeps its direction without an arrow every day.
  defp mark_run_arrows(segments) do
    segments
    |> Enum.with_index()
    |> Enum.map(fn {segment, index} ->
      next = Enum.at(segments, index + 1)

      Map.put(
        segment,
        :arrow?,
        is_nil(next) or next.kind != segment.kind or next.x1 != segment.x2
      )
    end)
  end

  defp segment_class(segment) do
    style = if segment.dashed?, do: "tl-c-seg-dashed", else: "tl-c-seg-solid"
    ["tl-c-seg", style, "tl-c-" <> segment.kind]
  end

  # The marker follows the day's latest recorded event: a re-detection after a
  # fix draws D again and resumes the line, and a fix after a re-detection
  # draws F and stops it. The full kinds list stays in the hover title.
  defp point_kind(%{last_event: "resolved"}), do: "ended"
  defp point_kind(%{last_event: "reopened"}), do: "reopened"
  defp point_kind(_point), do: "open"

  # Hover text: how many libraries the advisory affects and where it was
  # first detected; on a fix day, how the fix was recorded.
  defp affected_note(track) do
    case Map.get(track, :packages, []) do
      [] ->
        ""

      packages ->
        names = packages |> Enum.map(&elem(&1, 0)) |> Enum.uniq()
        count = length(names)
        also = names |> Enum.drop(1) |> Enum.take(2)

        "\n#{count} affected #{if(count == 1, do: "library", else: "libraries")} — " <>
          "first affected: #{hd(names)}" <>
          if(also == [], do: "", else: ", also: " <> Enum.join(also, ", "))
    end
  end

  defp fix_note(point) do
    if point_kind(point) == "ended" do
      case Map.get(point, :fix_note) do
        note when note in [nil, ""] -> "\nFix reason not recorded."
        note -> "\nRecorded resolution: " <> note
      end
    else
      ""
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
