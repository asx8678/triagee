defmodule TriageWeb.TimelineLive do
  @moduledoc """
  Read-only CVE timeline: recorded local observations over time.

  Days stack newest first and each CVE reads as an arrow across the days it was
  recorded on. Nothing here is a scan-completion time, a CVE publication date, a
  verified fix, an approval or a completeness claim: every row is a recorded
  row, and a day with no recorded observation is shown as exactly that. The
  detail drawer reuses the case detail's own history ordering, so the two views
  cannot disagree about what happened.

  All loading is delegated to `Triage.Timeline`, which validates every option
  before it queries and writes nothing. Invalid parameters produce a visible
  error state with no rows rather than a widened view.
  """

  use TriageWeb, :live_view

  alias Triage.Intel
  alias Triage.Timeline
  alias TriageWeb.CaseLive
  alias TriageWeb.TimelineFilters
  alias TriageWeb.TimelineLive.{Bands, Chart, Drawer, Grid, Lanes}

  @impl true
  def mount(_params, _session, socket) do
    {:ok, initialize(socket)}
  end

  @doc false
  def initialize(socket) do
    socket
    |> assign(:page_title, "Timeline")
    |> assign(:plot_width, 1000)
    |> assign(:raw_params, %{})
    |> assign(:filter_form, to_form(%{}))
    |> assign(:timeline_options, %{owners: [], environments: []})
    |> assign(:timeline, nil)
    |> assign(:filters, TimelineFilters.defaults())
    |> assign(:view_error, nil)
    |> assign(:expanded_cases, %{})
    |> assign(:detail, nil)
    |> assign(:selected_cve, nil)
    |> assign(:detail_error, nil)
    |> assign(:kev, %{})
    |> assign(:kev_status, nil)
  end

  @impl true
  def handle_params(params, _uri, socket) do
    {:noreply, load(socket, params)}
  end

  @doc false
  def load(socket, params),
    do: socket |> assign(raw_params: params, expanded_cases: %{}) |> load_view()

  @impl true
  def handle_event("filter", params, socket) do
    parsed = TimelineFilters.parse_event(params)

    if parsed.invalid == [] do
      {:noreply,
       push_patch(socket,
         to:
           TimelineFilters.path(parsed, %{
             cve: socket.assigns.selected_cve,
             chart: socket.assigns.filters.chart
           })
       )}
    else
      {:noreply, view_error(socket, parsed)}
    end
  end

  def handle_event(
        "timeline-case",
        %{"id" => id},
        %{assigns: %{detail: %{cases: cases}}} = socket
      )
      when is_binary(id) do
    # Only a case in this CVE's currently displayed, scoped page can be expanded.
    case Enum.find(cases.rows, &(Integer.to_string(&1.id) == id)) do
      nil ->
        {:noreply, socket}

      entry ->
        case Triage.Cases.get_case(entry.id) do
          {:ok, data} ->
            {:noreply,
             update(
               socket,
               :expanded_cases,
               &Map.put(&1, entry.id, CaseLive.Format.timeline_entries(data))
             )}

          _ ->
            {:noreply, socket}
        end
    end
  end

  def handle_event("plot_width", %{"width" => width}, socket)
      when is_integer(width) and width >= 240 and width <= 7680 do
    {:noreply, assign(socket, :plot_width, width)}
  end

  # An unrecognized event changes nothing: the current URL state is re-read
  # rather than a different or widened view being served.
  def handle_event(_other, _params, socket), do: {:noreply, load_view(socket)}

  defp load_view(socket) do
    parsed = TimelineFilters.parse(socket.assigns.raw_params)

    if parsed.invalid != [] do
      view_error(socket, parsed)
    else
      case Timeline.list_timeline(
             weeks: parsed.weeks,
             owner: parsed.owner,
             environment: parsed.environment,
             chart: parsed.chart
           ) do
        {:ok, timeline} ->
          socket
          |> assign(:view_error, nil)
          |> assign(:timeline, timeline)
          |> assign(:action_paths, action_paths(timeline, parsed.cve))
          |> assign(:filters, parsed)
          |> assign(:timeline_options, Timeline.filter_options())
          |> assign(:filter_form, to_form(filter_params(timeline, parsed)))
          |> assign(:kev, Intel.kev_index(Enum.map(timeline.lanes.rows, & &1.cve)))
          |> assign(:kev_status, Intel.kev_status())
          |> load_detail(parsed)

        {:error, _reason} ->
          view_error(socket, parsed)
      end
    end
  end

  # Every displayed surface participates, not just the truncated lane table.
  # Day rows and lanes are already bounded by Timeline; Query chunks this union.
  defp action_paths(timeline, selected_cve) do
    day_cves = Enum.flat_map(timeline.days, fn day -> Enum.map(day.rows, & &1.cve) end)
    lane_cves = Enum.map(timeline.lanes.rows, & &1.cve)

    (day_cves ++ lane_cves ++ [selected_cve])
    |> Enum.reject(&is_nil/1)
    |> Triage.GuidedReview.actionable_for()
    |> Map.new(fn row -> {row.cve, ~p"/triage/#{row.cve}"} end)
  end

  # The form shows what is displayed: the effective window size, not the raw
  # request, so an omitted `weeks` still shows the default it resolved to.
  defp filter_params(timeline, parsed) do
    %{
      "owner" => parsed.owner || "",
      "environment" => parsed.environment || "",
      "weeks" => Integer.to_string(timeline.window.weeks),
      "scale" => parsed.scale || "fit"
    }
  end

  # The visible error state: nothing from a previous valid view survives and
  # nothing is widened to All or to the default window.
  defp view_error(socket, parsed) do
    socket
    |> assign(:view_error, invalid_text(parsed.invalid))
    |> assign(:timeline, nil)
    |> assign(:filters, TimelineFilters.defaults())
    |> assign(:filter_form, to_form(blank_filter_params()))
    |> assign(:kev_status, nil)
    |> assign(:detail, nil)
    |> assign(:selected_cve, nil)
    |> assign(:detail_error, nil)
  end

  defp blank_filter_params do
    %{
      "owner" => "",
      "environment" => "",
      "weeks" => Integer.to_string(Timeline.default_weeks()),
      "scale" => "fit"
    }
  end

  defp invalid_text(invalid) do
    labels = invalid |> Enum.map(&TimelineFilters.field_label/1) |> Enum.uniq() |> Enum.sort()
    Enum.join(labels, ", ")
  end

  defp load_detail(socket, %{cve: nil}) do
    socket
    |> assign(:detail, nil)
    |> assign(:selected_cve, nil)
    |> assign(:detail_error, nil)
  end

  defp load_detail(socket, %{cve: cve} = parsed) do
    case Timeline.cve_detail(cve,
           weeks: parsed.weeks,
           owner: parsed.owner,
           environment: parsed.environment,
           events_after: parsed.events_after,
           cases_after: parsed.cases_after
         ) do
      {:ok, detail} ->
        socket
        |> assign(:detail, prepare_detail(detail))
        |> assign(:selected_cve, cve)
        |> assign(:detail_error, nil)

      {:error, reason} ->
        socket
        |> assign(:detail, nil)
        |> assign(:selected_cve, nil)
        |> assign(:detail_error, reason)
    end
  end

  # Judgment and case history are ordered by the case detail's own definition,
  # so the drawer and the case page cannot disagree about what happened.
  defp prepare_detail(detail) do
    rows =
      Enum.map(detail.cases.rows, fn %{id: id, data: data} ->
        %{
          id: id,
          case: data.case,
          entries: CaseLive.Format.timeline_entries(data),
          history_truncated?: data.history_truncated?
        }
      end)

    %{detail | cases: %{detail.cases | rows: rows}}
  end

  defp detail_error_text(:not_found),
    do: "No finding in the selected scope records that CVE."

  defp detail_error_text(:invalid_cve),
    do: "The CVE in the address is not a valid value."

  defp detail_error_text(:invalid_cursor),
    do:
      "This history position is not in the selected scope. Open the CVE again to start at the first page."

  defp detail_error_text(_other),
    do: "The selection could not be loaded. Nothing from a previous selection is shown."

  defp window_select_options do
    Enum.map(Timeline.window_options(), fn {label, weeks} ->
      {label, Integer.to_string(weeks)}
    end)
  end

  # The drawing scale of the chart, not a filter: it changes the spacing of the
  # tracks, never which days or observations are drawn.
  defp scale_options do
    [{"Fit window", "fit"}, {"Daily detail", "detail"}]
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="timeline">
      <.panel {assigns} />
    </Layouts.app>
    """
  end

  @doc false
  attr :workspace_scope, :map, default: nil

  def panel(assigns) do
    ~H"""
    <section id="workspace-timeline" class="restored-timeline">
      <.filter_bar id="timeline-form" form={@filter_form} change="filter">
        <.input
          :if={@workspace_scope}
          field={@filter_form[:owner]}
          type="hidden"
          value={@workspace_scope["team"] || ""}
        />
        <.input
          :if={@workspace_scope}
          field={@filter_form[:environment]}
          type="hidden"
          value={@workspace_scope["environment"] || ""}
        />
        <.input
          :if={is_nil(@workspace_scope)}
          field={@filter_form[:owner]}
          type="select"
          label="Team"
          options={
            display_scope_options(@timeline_options[:owners], @filter_form[:owner].value, "All teams")
          }
        />
        <.input
          :if={is_nil(@workspace_scope)}
          field={@filter_form[:environment]}
          type="select"
          label="Environment"
          options={
            display_scope_options(
              @timeline_options[:environments],
              @filter_form[:environment].value,
              "All environments"
            )
          }
        />
        <.input
          field={@filter_form[:weeks]}
          type="select"
          label="Window"
          options={window_select_options()}
        />
        <.input
          field={@filter_form[:scale]}
          type="select"
          label="Scale"
          options={scale_options()}
        />
        <:actions>
          <.link
            id="timeline-reset"
            patch={
              if @workspace_scope,
                do:
                  TimelineFilters.path(TimelineFilters.defaults(), %{
                    owner: @workspace_scope["team"],
                    environment: @workspace_scope["environment"]
                  }),
                else: ~p"/timeline"
            }
            class="button button-secondary"
          >
            {if @workspace_scope, do: "Reset window", else: "Reset view"}
          </.link>
        </:actions>
      </.filter_bar>

      <.explain
        id="timeline-banner"
        summary="Observation limits and provenance"
      >
        <p>
          A row is not a scan completion time, a CVE publication date, or an approval.
          "No longer observed" means the occurrence disappeared from an eligible local
          collection — it is not remediation.
        </p>
        <p>
          Suppression is an imported scanner flag with no recorded date or author. A day
          with no row is a day with no recorded observation, not a clean day. Local cases
          are written by the unauthenticated <code>local-operator</code> identity.
        </p>
      </.explain>

      <div :if={@view_error} id="timeline-error" class="notice" role="alert">
        <h2>Timeline could not be loaded</h2>
        <p>
          Invalid parameter: {@view_error}. Nothing was loaded and no previous view is shown. Team, environment and CVE values accept plain text of at most 120 characters without control characters; the window accepts 1–2 digits and must be one of the offered sizes. Correct the address or reset the view to recover.
        </p>
        <.link id="timeline-error-reset" patch={~p"/timeline"} class="button button-secondary">
          Reset timeline view
        </.link>
      </div>

      <div :if={@detail_error} id="timeline-detail-error" class="notice" role="alert">
        <h2>CVE detail could not be loaded</h2>
        <p>{detail_error_text(@detail_error)}</p>
        <.link
          id="timeline-detail-error-close"
          patch={TimelineFilters.path(@filters, %{cve: nil})}
          class="button button-secondary"
        >
          Close detail
        </.link>
      </div>

      <div :if={is_nil(@view_error) and not is_nil(@timeline)}>
        <div id="tl-summary" role="status">
          <dl class="timeline-totals">
            <div>
              <dt>CVEs</dt><dd>{@timeline.summary.cves}</dd>
            </div>
            <div>
              <dt>Recorded events</dt><dd>{@timeline.summary.events}</dd>
            </div>
            <div>
              <dt>Days observed</dt><dd>
                {@timeline.summary.observed_days} of {@timeline.summary.days}
              </dd>
            </div>
          </dl>
          <p class="supporting">Window: {@timeline.window.label}</p>
          <details class="tl-note timeline-breakdown">
            <summary>Observation breakdown</summary>
            <dl class="metric-strip">
              <div>
                <dt>New</dt><dd>{@timeline.summary.new_cves}</dd>
              </div>
              <div>
                <dt>No longer observed</dt><dd>{@timeline.summary.resolved}</dd>
              </div>
              <div>
                <dt>Re-observed</dt><dd>{@timeline.summary.reopened}</dd>
              </div>
              <div>
                <dt>Suppressed CVEs</dt><dd>{@timeline.summary.suppressed}</dd>
              </div>
              <div>
                <dt>Assessments recorded</dt><dd>{@timeline.summary.judged}</dd>
              </div>
            </dl>
          </details>
        </div>

        <p :if={@timeline.summary.truncated?} id="tl-truncated" class="supporting">
          This window contains more recorded events than are displayed; the newest are shown.
        </p>

        <Drawer.cve_drawer
          :if={@detail}
          detail={@detail}
          expanded_cases={@expanded_cases}
          action_paths={@action_paths}
          selected_cve={@selected_cve}
          filters={@filters}
        />

        <Chart.lane_chart
          :if={@timeline.chart.tracks != []}
          width={@plot_width}
          scale={@filters.scale || "fit"}
          chart={@timeline.chart}
          lanes={@timeline.lanes}
          action_paths={@action_paths}
          selected_cve={@selected_cve}
          filters={@filters}
        />

        <Lanes.lane_table
          action_paths={@action_paths}
          lanes={@timeline.lanes}
          filters={@filters}
          selected_cve={@selected_cve}
          kev={@kev}
          kev_status={@kev_status}
        />
        <Bands.waterfall
          action_paths={@action_paths}
          days={@timeline.days}
          filters={@filters}
          selected_cve={@selected_cve}
        />
        <Grid.weekday_grid grid={@timeline.grid} />
      </div>
    </section>
    """
  end
end
