defmodule TriageWeb.TimelineLive.Lanes do
  @moduledoc """
  The per-CVE lane list for the selected window.

  A row aggregates every recorded occurrence of one CVE that has an observation
  in the window. Counts are occurrences, never claims: "no longer observed" is
  an observation, and a suppression flag is imported scanner state rather than
  an action this application took.
  """

  use TriageWeb, :html

  alias TriageWeb.FindingFilters
  alias TriageWeb.TimelineFilters

  attr :lanes, :map, required: true
  attr :filters, :map, required: true
  attr :kev, :map, default: %{}

  def lane_table(assigns) do
    ~H"""
    <section id="tl-lanes" class="tl-section" aria-labelledby="tl-lanes-title">
      <div class="section-header">
        <h2 id="tl-lanes-title">CVEs observed in this window</h2>
        <p class="supporting">
          Ordered by current scanner severity, then CVE. Occurrence counts are local inventory
          rows, not verified production coverage.
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
              <th scope="col">CVE</th>
              <th scope="col">Current severity</th>
              <th scope="col">Occurrences</th>
              <th scope="col">Days observed</th>
              <th scope="col">Current state</th>
              <th scope="col">Assessments</th>
              <th scope="col">Detail</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={lane <- @lanes.rows} id={"tl-lane-" <> lane.cve}>
              <th scope="row">
                <.link
                  id={"tl-lane-cve-" <> lane.cve}
                  navigate={FindingFilters.advisory_path(lane.cve, @filters)}
                >
                  {lane.cve}
                </.link>
                <.kev_marker id={"tl-lane-kev-" <> lane.cve} kev={@kev[lane.cve]} />
              </th>
              <td><.status_badge label={display_value(lane.severity)} kind="severity" /></td>
              <td>
                {lane.occurrence_count}
                <span class="supporting">({lane.open_count} open, {lane.resolved_count} no longer observed)</span>
              </td>
              <td>{length(lane.observed_dates)}</td>
              <td>
                {state_label(lane.state)}
                <span :if={lane.suppressed_count > 0}>
                  · suppression flag set on {lane.suppressed_count} occurrence(s)
                </span>
              </td>
              <td>{lane.judged_count}</td>
              <td>
                <.link
                  id={"tl-lane-open-" <> lane.cve}
                  patch={TimelineFilters.path(@filters, %{cve: lane.cve})}
                  class="button button-secondary"
                >
                  Timeline detail
                </.link>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <.kev_note id="tl-lanes-kev-note" present?={map_size(@kev) > 0} />

      <p :if={@lanes.truncated_count > 0} class="supporting">
        {@lanes.truncated_count} further CVE(s) in this window are not shown.
      </p>
    </section>
    """
  end

  defp state_label(:open), do: "Open in local inventory"
  defp state_label(:no_longer_observed), do: "No longer observed"
  defp state_label(_other), do: "Unknown state"
end
