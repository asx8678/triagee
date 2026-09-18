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

  defp median_label(nil), do: "—"
  defp median_label(value) when is_float(value), do: :erlang.float_to_binary(value, decimals: 1)
  defp median_label(value), do: to_string(value)

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="statistics">
      <.page_header
        title="Statistics"
        subtitle="Aggregate CVE response statistics. Detection dates and action history are in Timeline."
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

      <details id="statistics-help" class="disclosure supporting">
        <summary>Local observation timing · not verified remediation. How metrics work</summary>
        <.notice id="statistics-note" kind="info">
          Dates come from local collection records: first local observation and the most recent
          recorded disappearance. "No longer observed" means the occurrence vanished from an
          eligible local collection — it is not verified remediation, a fixed version claim,
          CVE publication, or approval. Green and red only compare elapsed observation time
          with the local review target. Whitelist timing means a recorded operator decision, not a fix.
          Scanner suppression alone has no decision date. Durations start at the earliest recorded
          detection across this CVE’s occurrences; reopened history is not a per-incident repair timer.
        </.notice>
      </details>

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

      <section id="statistics-response-cards" class="stat-cards" aria-label="Response timing">
        <div class="stat-card" id="stat-card-median-decision">
          <p class="stat-card-value">{median_label(@summary.median_decision_days)}</p>
          <p class="stat-card-label">Median days to first advisory-wide whitelist decision</p>
          <p class="supporting muted">
            Historical decisions, including expired records. Placement-only decisions excluded.
          </p>
        </div>
        <div class="stat-card" id="stat-card-decisions">
          <p class="stat-card-value">{@summary.decisions_recorded}</p>
          <p class="stat-card-label">CVEs with recorded decision history</p>
          <p class="supporting muted">Not a count of currently whitelisted CVEs.</p>
        </div>
        <div class="stat-card" id="stat-card-fix">
          <p class="stat-card-value">Not recorded</p>
          <p class="stat-card-label">Verified time to fix</p>
          <p class="supporting muted">
            Collection disappearance cannot establish when a fix was applied.
          </p>
        </div>
      </section>
      <div :if={@rows == []} id="statistics-empty" class="notice" role="status">
        No advisories recorded locally — an empty table is not proof of a clean estate.
      </div>

      <.link
        id="statistics-timeline"
        navigate={~p"/timeline#tl-lanes"}
        class="button button-secondary"
      >
        View CVE dates, actions &amp; time to fix in Timeline
      </.link>
    </Layouts.app>
    """
  end
end
