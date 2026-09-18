defmodule TriageWeb.TimelineLive.Drawer do
  @moduledoc """
  The per-CVE detail drawer: the lane across every recorded observation, the
  paged lifecycle events, and saved cases with bounded assessment previews.
  Aggregate totals are independent of the selected page; full case histories
  remain reachable through the explicit Open case links.

  The case history is rendered from `TriageWeb.CaseLive.Format.timeline_entries/1`,
  the same ordering the case detail page uses, so the drawer and the case page
  cannot describe different histories. Every block reports recorded rows: an
  assessment is not an approval, an imported suppression flag is not a local
  action, and no block claims production coverage.
  """

  use TriageWeb, :html

  import TriageWeb.CaseLive.Format, only: [event_label: 1, label: 1]

  alias TriageWeb.FindingFilters
  alias TriageWeb.TimelineFilters

  attr :detail, :map, required: true
  attr :action_paths, :map, default: %{}
  attr :selected_cve, :string, required: true
  attr :filters, :map, required: true

  def cve_drawer(assigns) do
    assigns = assign(assigns, :history_stream_limit, Triage.Cases.History.stream_limit())

    ~H"""
    <aside id="tl-drawer" class="tl-drawer" aria-labelledby="tl-drawer-title">
      <div class="section-header">
        <h2 id="tl-drawer-title">
          <.link navigate={Map.get(@action_paths, @selected_cve, ~p"/cves/#{@selected_cve}")}>{@selected_cve}</.link>
          · recorded history
        </h2>
        <.link
          id="tl-drawer-close"
          patch={TimelineFilters.path(@filters, %{cve: nil})}
          class="button button-secondary"
        >
          Close detail
        </.link>
      </div>

      <dl id="tl-drawer-lane" class="key-value evidence-grid">
        <div>
          <dt>Current scanner severity</dt>
          <dd><.status_badge label={display_value(@detail.lane.severity)} kind="severity" /></dd>
        </div>
        <div>
          <dt>Package</dt>
          <dd>{@detail.lane.package_name} <code>{@detail.lane.package_version}</code></dd>
        </div>
        <div>
          <dt>Recorded fix</dt>
          <dd>{display_value(@detail.lane.fix)}</dd>
        </div>
        <div>
          <dt>Occurrences in local inventory</dt>
          <dd>
            {@detail.lane.occurrence_count} ({@detail.lane.open_count} open, {@detail.lane.resolved_count} no longer observed)
          </dd>
        </div>
        <div>
          <dt>Days observed in this window</dt>
          <dd>
            {@detail.lane.window_observed_count} of {@detail.lane.observed_day_count} recorded day(s)
          </dd>
        </div>
        <div>
          <dt>First recorded observation</dt>
          <dd><.timestamp value={@detail.lane.first_seen} /></dd>
        </div>
        <div>
          <dt>Last recorded observation</dt>
          <dd><.timestamp value={@detail.lane.last_seen} /></dd>
        </div>
        <div :if={@detail.lane.resolved_at}>
          <dt>Recorded as no longer observed</dt>
          <dd><.timestamp value={@detail.lane.resolved_at} /></dd>
        </div>
        <div>
          <dt>Suppression flag</dt>
          <dd>{suppression_text(@detail.lane.suppressed_count)}</dd>
        </div>
        <div :if={@detail.lane.reopen_count > 0}>
          <dt>Recorded re-observations</dt>
          <dd>{@detail.lane.reopen_count}</dd>
        </div>
      </dl>

      <div class="cluster">
        <.link
          :if={@detail.lane.url}
          id="tl-drawer-source"
          href={@detail.lane.url}
          class="button button-secondary"
        >
          Advisory reference
        </.link>
        <.link
          :if={is_binary(@selected_cve) and @selected_cve != ""}
          id="tl-drawer-advisory"
          navigate={FindingFilters.advisory_path(@selected_cve, @filters)}
          class="button button-secondary"
        >
          CVE detail
        </.link>
      </div>

      <section id="tl-drawer-events" aria-labelledby="tl-drawer-events-title">
        <h3 id="tl-drawer-events-title">Lifecycle events ({@detail.event_page.total} recorded)</h3>
        <.history_paging
          id="tl-events"
          page={@detail.event_page}
          cursor_key={:events_after}
          filters={@filters}
        />
        <p :if={@detail.event_page.total == 0} class="supporting">No recorded lifecycle event.</p>
        <ol :if={@detail.events != []} class="tl-history">
          <li :for={event <- @detail.events} id={"tl-event-" <> Integer.to_string(event.id)}>
            <span class="tl-arrow tl-arrow-history" aria-hidden="true">{event_glyph(event.kind)}</span>
            <div>
              <p>
                <strong>{event_label(event.kind)}</strong>
                <span> — <.timestamp value={event.occurred_at} /></span>
                <span :if={not event.in_window?} class="supporting"> · outside the selected window</span>
              </p>
              <p :if={event.note} class="supporting">Recorded note: {event.note}</p>
            </div>
          </li>
        </ol>
      </section>

      <section id="tl-drawer-cases" aria-labelledby="tl-drawer-cases-title">
        <h3 id="tl-drawer-cases-title">Saved cases ({@detail.cases.total})</h3>
        <p :if={@detail.cases.total == 0} class="supporting">
          No case has been opened for this CVE in the selected scope. No case is not evidence that no risk exists.
        </p>
        <p :if={@detail.cases.truncated_count > 0} class="supporting">
          {@detail.cases.truncated_count} other case(s) are not shown on this page.
        </p>
        <.history_paging
          id="tl-cases"
          page={@detail.cases}
          cursor_key={:cases_after}
          filters={@filters}
        />
        <.notice id="tl-drawer-actor" kind="info">
          Every local case was written by the unauthenticated <code>local-operator</code> identity.
          It is a server-owned constant, not a verified person, so no attribution to an individual
          is available anywhere in this application.
        </.notice>

        <article
          :for={case_entry <- @detail.cases.rows}
          id={"tl-case-" <> Integer.to_string(case_entry.id)}
          class="tl-case"
        >
          <div class="section-header">
            <h4>Case #{case_entry.id} · {case_entry.case.owner} · {case_entry.case.environment}</h4>
            <.link
              id={"tl-case-open-" <> Integer.to_string(case_entry.id)}
              navigate={~p"/cases/#{case_entry.id}"}
              class="button button-secondary"
            >
              Open case
            </.link>
          </div>
          <p class="supporting">
            Case revision {case_entry.case.revision} · {length(case_entry.entries)} history entries shown
          </p>
          <p
            :if={case_entry.history_truncated?}
            id={"tl-case-truncated-#{case_entry.id}"}
            class="supporting"
          >
            Recent assessments and audit events are shown (up to {@history_stream_limit} of each).
            Open case for the complete recorded history.
          </p>
          <ol class="tl-history">
            <li
              :for={entry <- case_entry.entries}
              id={"tl-case-entry-" <> entry.key}
            >
              <div>
                <p>
                  <strong>{entry_title(entry)}</strong>
                  <span> — <.timestamp value={entry.at} /></span>
                  <span class="supporting"> · recorded actor {display_value(entry.actor)}</span>
                </p>
                <p :if={entry.type == :review} class="supporting">
                  {label(entry.applicability)} · {label(entry.priority)} · {label(entry.next_action)}
                </p>
                <p :if={entry.rationale}>{entry.rationale}</p>
                <p :if={entry.type == :review and entry.is_stale} class="supporting">
                  Judged against an earlier evidence revision; a newer capture exists for this case.
                </p>
                <p :if={entry.detail_pairs != []} class="supporting">
                  {detail_pairs_text(entry.detail_pairs)}
                </p>
              </div>
            </li>
          </ol>
        </article>

        <p class="supporting">
          A saved assessment records what an operator judged against one frozen evidence revision.
          It does not approve an exception, suppress a finding, verify a fix or close this CVE.
        </p>
      </section>
    </aside>
    """
  end

  attr :id, :string, required: true
  attr :page, :map, required: true
  attr :cursor_key, :atom, required: true
  attr :filters, :map, required: true

  defp history_paging(assigns) do
    ~H"""
    <nav
      id={@id <> "-paging"}
      class="cluster"
      aria-label={
        if(@cursor_key == :events_after, do: "Lifecycle event pages", else: "Saved case pages")
      }
    >
      <span class="supporting">Showing {@page.shown} of {@page.total} recorded rows</span>
      <.link
        :if={@page.cursor}
        id={@id <> "-first"}
        patch={TimelineFilters.path(@filters, %{@cursor_key => nil})}
        class="button button-secondary"
      >
        First page
      </.link>
      <.link
        :if={@page.has_more?}
        id={@id <> "-next"}
        patch={TimelineFilters.path(@filters, %{@cursor_key => @page.next_after})}
        class="button button-secondary"
      >
        Next page
      </.link>
    </nav>
    """
  end

  defp entry_title(%{type: :review}), do: "Assessment recorded"
  defp entry_title(entry), do: event_label(entry.kind)

  defp event_glyph("resolved"), do: "╢"
  defp event_glyph("reopened"), do: "↺"
  defp event_glyph(_other), do: "▶"

  defp suppression_text(0), do: "Not currently set on any recorded occurrence"

  defp suppression_text(count) do
    "Suppressed on #{count} occurrence(s) as reported by the imported scanner data; " <>
      "this application records no suppression date or author and did not take that action"
  end

  defp detail_pairs_text(pairs) do
    Enum.map_join(pairs, " · ", fn pair -> "#{pair.key}: #{pair.value}" end)
  end
end
