defmodule TriageWeb.StatisticsLive do
  @moduledoc """
  Read-only per-advisory observation timing for the local inventory history
  (manager view).

  One row per advisory ever recorded locally: when an occurrence was first
  recorded, the most recent recorded disappearance ("no longer observed in an
  eligible local collection"), and the elapsed days compared with a local
  review target set by the highest scanner severity. Green means the
  observation stayed within the local target; red means it ran past. No
  timer, polling, filter, or write exists in this slice, and nothing here
  claims verified remediation, CVE publication dates, exposure, approval, or
  a clean estate.
  """

  use TriageWeb, :live_view

  alias Triage.Statistics

  @impl true
  def mount(_params, _session, socket) do
    {:ok, load(socket)}
  end

  @impl true
  def handle_event("reload", _params, socket) do
    {:noreply, load(socket)}
  end

  def handle_event(_other, _params, socket) do
    {:noreply, socket}
  end

  defp load(socket) do
    rows = Statistics.advisory_lifecycles()

    socket
    |> assign(:page_title, "Statistics")
    |> assign(:rows, rows)
    |> assign(:summary, Statistics.summarize(rows))
  end

  defp chip_class(%{on_target?: true}), do: "stat-chip-good"
  defp chip_class(%{on_target?: false}), do: "stat-chip-bad"

  defp status_label(%{open?: true}), do: "Open"
  defp status_label(%{open?: false}), do: "No longer observed"

  defp environment_list([]), do: "—"
  defp environment_list(environments), do: Enum.join(environments, ", ")

  defp median_label(nil), do: "—"
  defp median_label(value) when is_float(value), do: :erlang.float_to_binary(value, decimals: 1)
  defp median_label(value), do: to_string(value)

  defp count_label(count, singular, plural) do
    "#{count} #{if(count == 1, do: singular, else: plural)}"
  end

  defp severity_badge(severity), do: "highest severity " <> severity

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="statistics">
      <.page_header
        title="Statistics"
        subtitle="How long advisories stay observed in local inventory, against local review targets."
      >
        <:actions>
          <button
            id="reload-statistics"
            type="button"
            phx-click="reload"
            phx-disable-with="Reloading…"
            class="button button-secondary"
          >
            Reload statistics
          </button>
        </:actions>
      </.page_header>

      <.notice id="statistics-note" kind="info">
        Dates come from local collection records: first local observation and the most recent
        recorded disappearance. "No longer observed" means the occurrence vanished from an
        eligible local collection — it is not verified remediation, a fixed version claim,
        CVE publication, or approval. Green and red only compare elapsed observation time
        with the local review target.
      </.notice>

      <section id="statistics-cards" class="stat-cards" aria-label="Advisory timing summary">
        <div class="stat-card" id="stat-card-total">
          <p class="stat-card-value">{@summary.total}</p>
          <p class="stat-card-label">Advisories recorded</p>
        </div>
        <div class="stat-card" id="stat-card-open">
          <p class="stat-card-value">{@summary.open}</p>
          <p class="stat-card-label">Still observed</p>
        </div>
        <div class="stat-card" id="stat-card-past-target">
          <p class="stat-card-value stat-bad">{@summary.past_target}</p>
          <p class="stat-card-label">Past local target</p>
        </div>
        <div class="stat-card" id="stat-card-median-clear">
          <p class="stat-card-value">{median_label(@summary.median_clear_days)}</p>
          <p class="stat-card-label">Median days until no longer observed</p>
        </div>
      </section>

      <div :if={@rows == []} id="statistics-empty" class="notice" role="status">
        No advisories recorded locally — an empty table is not proof of a clean estate.
      </div>

      <table :if={@rows != []} id="statistics-table" class="data-table">
        <thead>
          <tr>
            <th scope="col">Advisory</th>
            <th scope="col">Severity</th>
            <th scope="col">Environments</th>
            <th scope="col">First observed</th>
            <th scope="col">No longer observed</th>
            <th scope="col">Time observed</th>
            <th scope="col">Status</th>
          </tr>
        </thead>
        <tbody id="statistics-rows">
          <tr :for={row <- @rows} id={"stat-row-#{row.cve}"}>
            <td>
              <.link navigate={~p"/cves/#{row.cve}"}>{row.cve}</.link>
              <span class="supporting">
                {count_label(row.occurrences, "occurrence", "occurrences")} · {count_label(
                  row.images,
                  "image",
                  "images"
                )}
              </span>
              <span :if={row.suppressed_count > 0} class="supporting muted">
                {count_label(row.suppressed_count, "suppressed occurrence", "suppressed occurrences")} — suppression is not mitigation evidence
              </span>
            </td>
            <td>
              <span
                :if={row.severity}
                class={"status-badge-#{String.downcase(row.severity)}"}
                title={severity_badge(row.severity)}
              >
                {row.severity}
              </span>
              <span :if={is_nil(row.severity)} class="status-badge-neutral">Not reported</span>
            </td>
            <td>
              {environment_list(row.environments)}
            </td>
            <td><.timestamp value={row.first_seen} /></td>
            <td>
              <.timestamp :if={not row.open?} value={row.resolved_at} />
              <span :if={row.open?} class="muted">Still observed</span>
            </td>
            <td>
              <span
                class={["stat-chip", chip_class(row)]}
                title={"local review target ≤ #{row.target} days"}
              >
                {row.days} d{if row.open?, do: " open", else: ""}
              </span>
              <span class="supporting muted">target ≤ {row.target} d</span>
            </td>
            <td>
              <span class="status-badge-state">{status_label(row)}</span>
              <span :if={row.reopened_count > 0} class="supporting">reopened history</span>
            </td>
          </tr>
        </tbody>
      </table>

      <p :if={@rows != []} id="statistics-legend" class="supporting">
        <span class="stat-chip stat-chip-good">green</span>
        within the local review target; <span class="stat-chip stat-chip-bad">red</span>
        past it. Targets by highest recorded severity:
        CRITICAL ≤ 7 days · HIGH ≤ 14 days · MEDIUM ≤ 30 days · LOW ≤ 60 days · unreported ≤ 90 days.
      </p>
    </Layouts.app>
    """
  end
end
