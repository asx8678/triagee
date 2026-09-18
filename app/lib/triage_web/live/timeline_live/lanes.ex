defmodule TriageWeb.TimelineLive.Lanes do
  @moduledoc "CVE response timing for occurrences represented in the selected timeline window."
  use TriageWeb, :html

  alias TriageWeb.FindingFilters
  alias TriageWeb.TimelineFilters

  attr :action_paths, :map, default: %{}
  attr :selected_cve, :string, default: nil
  attr :lanes, :map, required: true
  attr :filters, :map, required: true
  attr :kev, :map, default: %{}
  attr :kev_status, :any, default: nil

  def lane_table(assigns) do
    assigns = assign(assigns, :now, DateTime.utc_now())

    ~H"""
    <section id="tl-lanes" class="tl-section" aria-labelledby="tl-lanes-title">
      <div class="section-header">
        <h2 id="tl-lanes-title">CVE detection, actions &amp; time to fix</h2>
        <p id="tl-timing-note" class="supporting">
          For now, “Fixed” uses the recorded disappearance date, not a verified repair. Dates cover the occurrences represented in this filtered window, not necessarily the whole CVE. Timing starts at first detection; reopened history is not a fresh repair timer.
        </p>
      </div>
      <p :if={@lanes.total == 0} id="tl-lanes-empty" class="supporting">
        No recorded observation in this window. An empty window is not evidence of a clean estate.
      </p>
      <div
        :if={@lanes.total > 0}
        id="tl-lanes-scroll"
        class="table-region"
        role="region"
        aria-label="CVEs observed in this window"
        tabindex="0"
      >
        <table id="tl-lanes-table" class="data-table">
          <thead>
            <tr>
              <th scope="col">CVE</th><th scope="col">First detected</th>
              <th scope="col">Fixed / whitelisted on</th><th scope="col">Time taken</th>
              <th scope="col">Current status</th><th scope="col">History</th>
            </tr>
          </thead>
          <tbody>
            <tr
              :for={lane <- @lanes.rows}
              id={"tl-lane-" <> lane.cve}
              class={lane.cve == @selected_cve && "tl-selected"}
              aria-current={if lane.cve == @selected_cve, do: "true"}
            >
              <% action = response(lane, @now) %>
              <th scope="row">
                <.link navigate={Map.get(@action_paths, lane.cve, ~p"/cves/#{lane.cve}")}>{lane.cve}</.link><span
                  :if={lane.cve == @selected_cve}
                  class="tl-selection-label"
                >Selected</span><span class="supporting"><.status_badge
                  label={display_value(lane.severity)}
                  kind="severity"
                /></span>
                <.kev_marker id={"tl-lane-kev-" <> lane.cve} kev={Map.get(@kev, lane.cve)} />
              </th>
              <td><.timestamp value={lane.first_seen} /></td>
              <td>
                <.timestamp :if={action.at} value={action.at} /><span :if={is_nil(action.at)}>{if action.waiting,
                  do: "—",
                  else: "Date unknown"}</span>
              </td>
              <td>
                <strong>{duration(lane.first_seen, if(action.waiting, do: @now, else: action.at))}</strong><span class="supporting">{action.timing}</span>
              </td>
              <td>
                <strong>{action.label}</strong><span class="supporting">{action.detail}</span>
                <span class="supporting">{if lane.state == :open,
                  do: "Open in local inventory",
                  else: "No longer observed in local inventory"}</span>
              </td>
              <td>
                <.link
                  id={"tl-lane-open-" <> lane.cve}
                  patch={TimelineFilters.path(@filters, %{cve: lane.cve})}
                  class="button button-secondary"
                >Timeline detail</.link>
                <.link
                  id={"tl-lane-cve-" <> lane.cve}
                  navigate={FindingFilters.advisory_path(lane.cve, @filters)}
                  class="button button-secondary"
                >CVE detail</.link>
                <details>
                  <summary>Actions &amp; scope</summary>
                  <p>
                    {lane.occurrence_count} occurrences ({lane.open_count} open, {lane.resolved_count} no longer observed) · {length(
                      lane.observed_dates
                    )} days observed · {lane.judged_count} assessments
                  </p>
                  <p :if={lane.reopen_count > 0}>Detected again · reopened history</p>
                  <p :if={lane.suppressed_count > 0}>
                    Whitelisted via scanner: {lane.suppressed_count} occurrence(s). Date unknown.
                  </p>
                  <ol>
                    <li :for={decision <- Map.get(lane, :decisions, [])}>
                      <strong>{Triage.Decisions.label(decision.decision)}</strong>
                      · {decision_state(decision, Map.get(lane, :decisions, []), @now)}
                      <span class="supporting"><.timestamp value={decision.decided_at} />
                      · {duration(lane.first_seen, decision.decided_at)} after detection</span>
                      <span class="supporting">{if decision.placement_id,
                        do: "Placement #{decision.placement_id} only",
                        else: "Whole-CVE decision"}</span>
                      <span :if={decision.expires_at} class="supporting">Expires
                      <.timestamp value={decision.expires_at} /></span>
                    </li>
                  </ol>
                </details>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <.kev_note id="tl-lanes-kev-note" present?={map_size(@kev) > 0} />
      <.kev_source_status id="tl-lanes-kev-status" status={@kev_status} />

      <p :if={@lanes.truncated_count > 0} class="supporting">
        {@lanes.truncated_count} further CVE(s) in this window are not shown.
      </p>
    </section>
    """
  end

  defp decision_state(d, history, now) do
    cond do
      DateTime.compare(d.decided_at, now) == :gt ->
        "Scheduled"

      Enum.any?(
        history,
        &(&1.supersedes_id == d.id and DateTime.compare(&1.decided_at, now) != :gt)
      ) ->
        "Superseded"

      Triage.Decisions.state(d, now) == :expired ->
        "Expired"

      true ->
        "Active"
    end
  end

  defp response(lane, now) do
    history = Map.get(lane, :decisions, [])

    active =
      Enum.filter(history, &(decision_state(&1, history, now) == "Active")) |> Enum.reverse()

    decision = Enum.find(active, &is_nil(&1.placement_id)) || List.first(active)

    cond do
      lane.state == :no_longer_observed ->
        %{
          label: "Fixed",
          detail: "Based on recorded disappearance",
          at: lane.resolved_at,
          timing: "Time to fix (recorded disappearance)",
          waiting: false
        }

      decision ->
        %{
          label: if(decision.placement_id, do: "Partially whitelisted", else: "Whitelisted"),
          detail: Triage.Decisions.label(decision.decision),
          at: decision.decided_at,
          timing: "Time to whitelist",
          waiting: false
        }

      lane.suppressed_count > 0 ->
        %{
          label:
            if(lane.suppressed_count == lane.occurrence_count,
              do: "Whitelisted",
              else: "Partially whitelisted"
            ),
          detail:
            "Via scanner · #{lane.suppressed_count} of #{lane.occurrence_count} occurrences",
          at: nil,
          timing: "Whitelist date unknown",
          waiting: false
        }

      true ->
        detail = waiting_detail(lane, history, now)

        %{
          label: "Awaiting action",
          detail: detail,
          at: nil,
          timing: "Waiting since detection",
          waiting: true
        }
    end
  end

  defp waiting_detail(lane, history, now) do
    cond do
      lane.reopen_count > 0 -> "Detected again"
      Enum.any?(history, &(decision_state(&1, history, now) == "Expired")) -> "Whitelist expired"
      true -> "Not fixed"
    end
  end

  defp duration(first, last) do
    case Triage.Statistics.elapsed_seconds(first, last) do
      nil -> "Unknown"
      seconds when seconds < 60 -> "Less than 1 minute"
      seconds when seconds < 3600 -> "#{div(seconds, 60)} min"
      seconds when seconds < 86_400 -> "#{div(seconds, 3600)} h"
      seconds -> "#{div(seconds, 86_400)} days #{div(rem(seconds, 86_400), 3600)} h"
    end
  end
end
