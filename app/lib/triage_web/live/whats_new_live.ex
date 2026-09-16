defmodule TriageWeb.WhatsNewLive do
  @moduledoc """
  Read-only local "What's New" lifecycle feed (PR 4).

  One row per recorded `finding_events` entry, newest recorded id first. This
  is a local observation feed, not public news, not a completeness or
  remediation claim and not an authorization boundary. `handle_params` is the
  authoritative load: invalid URL parameters render a visible error and clear
  every row, link and pagination control instead of widening to All or keeping
  stale rows. No timer, polling or write exists in this slice.

  The finding and image values shown are the CURRENT local metadata joined to
  an existing event, not the facts recorded when the event happened. The
  team/environment filters match a recorded placement on the same image and
  are display scoping only - they never attribute a past event to a team.
  """

  use TriageWeb, :live_view

  alias Triage.Activity
  alias TriageWeb.ActivityFilters
  alias TriageWeb.FilterAssigns
  alias TriageWeb.FindingFilters

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "What’s New")
     |> assign(:filter_form, FilterAssigns.filter_form(%{}))
     |> assign(:filters, %{owner: nil, environment: nil})
     |> assign(:options, %{owners: [], environments: []})
     |> assign(:feed_error, nil)
     |> assign(:feed_empty?, false)
     |> assign(:page_count, 0)
     |> assign(:has_more?, false)
     |> assign(:next_before_id, nil)
     |> assign(:cursor, nil)
     |> assign(:raw_params, %{})
     |> stream_configure(:events, dom_id: &"event-#{&1.id}")}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    {:noreply, socket |> assign(:raw_params, params) |> load_feed()}
  end

  @impl true
  def handle_event("filter", params, socket) do
    parsed = ActivityFilters.parse_event(params)

    if parsed.invalid == [] do
      {:noreply,
       push_patch(socket,
         to: newest_path(%{owner: parsed.owner, environment: parsed.environment})
       )}
    else
      {:noreply, feed_error(socket, parsed.owner, parsed.environment)}
    end
  end

  @impl true
  def handle_event("reload", _params, socket) do
    {:noreply, load_feed(socket)}
  end

  def handle_event(_other, _params, socket) do
    filters = socket.assigns.filters

    {:noreply, feed_error(socket, filters[:owner], filters[:environment])}
  end

  defp load_feed(socket) do
    parsed = ActivityFilters.parse(socket.assigns.raw_params)

    if parsed.invalid != [] do
      feed_error(socket, parsed.owner, parsed.environment)
    else
      case Activity.list_events(
             owner: parsed.owner,
             environment: parsed.environment,
             before_id: parsed.before_id
           ) do
        {:ok, %{rows: rows, has_more?: has_more?, next_before_id: next_before_id}} ->
          socket
          |> assign(:feed_error, nil)
          |> assign(:feed_empty?, rows == [])
          |> assign(:page_count, length(rows))
          |> assign(
            :filter_form,
            FilterAssigns.filter_form(parsed)
          )
          |> assign(:filters, %{owner: parsed.owner, environment: parsed.environment})
          |> assign(:options, Activity.event_filter_options())
          |> assign(:has_more?, has_more?)
          |> assign(:next_before_id, next_before_id)
          |> assign(:cursor, parsed.before_id)
          |> stream(:events, rows, reset: true)

        {:error, _reason} ->
          feed_error(socket, parsed.owner, parsed.environment)
      end
    end
  end

  # The visible error state: nothing from a previous valid state survives and
  # nothing is widened to All.
  defp feed_error(socket, owner, environment) do
    socket
    |> assign(:feed_error, true)
    |> assign(:feed_empty?, false)
    |> assign(FilterAssigns.cleared_page())
    |> assign(:filters, %{owner: owner, environment: environment})
    |> stream(:events, [], reset: true)
  end

  defp newest_path(filters) do
    qs = scope_qs(filters)

    if map_size(qs) == 0 do
      ~p"/whats-new"
    else
      ~p"/whats-new?#{qs}"
    end
  end

  defp older_path(filters, next_before_id) do
    filters |> scope_qs() |> Map.put(:before, next_before_id) |> then(&~p"/whats-new?#{&1}")
  end

  defp detail_path(row, filters, cursor) do
    context =
      filters
      |> scope_qs()
      |> Map.put(:from, "activity")
      |> Map.put(:before, cursor)
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()

    qs = Map.put(scope_qs(filters), :activity, context)
    ~p"/findings/#{row.finding_id}?#{qs}"
  end

  defp scope_qs(filters) do
    %{owner: filters[:owner], environment: filters[:environment]}
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
  end

  defp event_label("appeared"), do: "First observed locally"
  defp event_label("resolved"), do: "No longer observed in local inventory"
  defp event_label("reopened"), do: "Observed again locally"
  defp event_label(_other), do: "Unknown lifecycle event"

  defp event_class("appeared"), do: "event-item-appeared"
  defp event_class("resolved"), do: "event-item-resolved"
  defp event_class(_other), do: nil

  defp event_explanation("appeared"),
    do: "The collector recorded this occurrence for the first time locally."

  defp event_explanation("resolved"),
    do:
      "The occurrence disappeared from an eligible local collection. This is not verified remediation."

  defp event_explanation("reopened"),
    do: "The collector observed this occurrence again after a recorded disappearance."

  defp event_explanation(_other),
    do: "An unrecognized lifecycle event was recorded; no security conclusion is available."

  defp image_reference(%{repository: repository, tag: tag})
       when is_binary(repository) and repository != "" and is_binary(tag) and tag != "",
       do: repository <> ":" <> tag

  defp image_reference(%{repository: repository}) when is_binary(repository) and repository != "",
    do: repository

  defp image_reference(_image), do: nil

  defp reported(value) when value in [nil, ""], do: "Not reported"
  defp reported(value), do: value

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="whats-new">
      <.page_header
        title="What’s New"
        subtitle="Recorded lifecycle observations from local inventory."
      >
        <:actions>
          <button
            id="reload-events"
            type="button"
            phx-click="reload"
            phx-disable-with="Reloading…"
            class="button button-secondary"
          >
            Reload activity
          </button>
        </:actions>
      </.page_header>

      <.filter_bar id="whats-new-form" form={@filter_form} change="filter">
        <.input
          field={@filter_form[:owner]}
          type="select"
          label="Team"
          options={display_scope_options(@options[:owners], @filter_form[:owner].value, "All teams")}
        />
        <.input
          field={@filter_form[:environment]}
          type="select"
          label="Environment"
          options={
            display_scope_options(
              @options[:environments],
              @filter_form[:environment].value,
              "All environments"
            )
          }
        />
        <:actions>
          <.link id="reset-activity" patch={~p"/whats-new"} class="button button-secondary">
            Reset
          </.link>
        </:actions>
      </.filter_bar>

      <.notice id="feed-banner" kind="info">
        Filters match a recorded placement on the same image, including inactive placements — not historical event ownership.
        They never claim a past event belonged to that team at the time; display scoping is not authorization.
        Recorded observation time is when the collector recorded the observation, not CVE publication,
        scan completion, a verified fix, or approval. Missing events do not establish a clean estate.
      </.notice>

      <div :if={@feed_error} id="events-error" class="notice" role="alert">
        <h2>Activity could not be loaded</h2>
        <p>
          Invalid feed parameters — nothing was loaded and no previous rows are shown. Filters accept
          plain text of at most 120 characters without control characters; the cursor must be a positive
          whole number. Correct the address or reset the filters to recover.
        </p>
        <.link patch={~p"/whats-new"} class="button button-secondary">Reset activity filters</.link>
      </div>

      <div :if={is_nil(@feed_error)} id="activity-summary" class="filter-summary" role="status">
        <strong>{@page_count} {if @page_count == 1, do: "event", else: "events"} on this page</strong>
        <span>· {@filters[:owner] || "All teams"} · {@filters[:environment] || "All environments"}</span>
        <span :if={@cursor}>· Older than record #{@cursor}</span>
      </div>
      <nav
        :if={is_nil(@feed_error)}
        id="events-pagination"
        class="cluster"
        aria-label="Activity pages"
      >
        <span class="supporting">Newest recorded first (record ID order), not observation-time order.</span>
        <.link
          :if={@has_more?}
          id="older-events"
          patch={older_path(@filters, @next_before_id)}
          class="button button-secondary"
        >
          Older events
        </.link>
        <.link
          :if={@cursor}
          id="newest-events"
          patch={newest_path(@filters)}
          class="button button-secondary"
        >
          Newest events
        </.link>
      </nav>

      <%!-- Empty/error states stay outside the stream so same-mount patches cannot retain them. --%>
      <div :if={@feed_empty? and is_nil(@feed_error)} id="events-empty" class="empty-state">
        <h2>No recorded lifecycle events for this scope</h2>
        <p>
          An empty feed is not proof that nothing changed, and it is not evidence of a clean estate.
        </p>
        <.link :if={@cursor} patch={newest_path(@filters)} class="button button-secondary">Return to newest events</.link>
      </div>

      <ul
        id="events-stream"
        phx-update="stream"
        class="event-list"
        aria-label="Recorded lifecycle events"
      >
        <li :for={{id, row} <- @streams.events} id={id} class={["event-item", event_class(row.event)]}>
          <section
            id={"event-facts-#{row.id}"}
            aria-labelledby={"event-title-#{row.id}"}
            class="stack"
          >
            <div class="section-header">
              <h2 id={"event-title-#{row.id}"}>{event_label(row.event)}</h2>
              <span class="supporting">Event #{row.id}</span>
            </div>
            <div id={"event-current-advisory-#{row.id}"} class="stack">
              <h3 class="supporting">Current local metadata</h3>
              <strong>Advisory</strong>
              <%!-- The recorded event stays the heading; the advisory shown here
                   comes from the current finding joined to that event. --%>
              <%= if target = FindingFilters.advisory_path(row.finding.cve, @filters) do %>
                <.link id={"event-cve-#{row.id}"} navigate={target}>
                  <strong>{row.finding.cve}</strong>
                </.link>
              <% else %>
                <%= if is_binary(row.finding.cve) and row.finding.cve != "" do %>
                  <strong>{row.finding.cve}</strong>
                <% else %>
                  <strong>No advisory id in current local records</strong>
                <% end %>
              <% end %>
              <p id={"event-advisory-provenance-#{row.id}"} class="supporting">
                Current local metadata — joined from current local records, not captured facts about this event.
              </p>
            </div>
            <p>
              Recorded observation time <.timestamp value={row.occurred_at} />
              <%= if relative = relative_time(row.occurred_at) do %>
                <span id={"event-relative-#{row.id}"} class="supporting">· {relative}</span>
              <% end %>
            </p>
            <p>{event_explanation(row.event)}</p>
            <p :if={is_binary(row.note) and row.note != ""}>Recorded note: {row.note}</p>
          </section>

          <section
            id={"event-current-#{row.id}"}
            aria-labelledby={"event-current-title-#{row.id}"}
            class="stack"
          >
            <h3 id={"event-current-title-#{row.id}"}>Current local metadata</h3>
            <p class="supporting">
              Joined from current local records, not captured facts about this event.
            </p>
            <p>
              <%= if target = FindingFilters.advisory_path(row.finding.cve, @filters) do %>
                <.link id={"event-current-cve-#{row.id}"} navigate={target}>
                  <strong>{row.finding.cve}</strong>
                </.link>
              <% else %>
                <%!-- A missing id addresses no route: honest text, never a broken link. --%>
                <strong>No advisory id in current local records</strong>
              <% end %>
              · {row.finding.package_name} <code>{row.finding.package_version}</code>
            </p>
            <dl class="evidence-grid key-value">
              <div>
                <dt>Current scanner severity</dt>
                <dd><.status_badge label={reported(row.finding.severity)} kind="severity" /></dd>
              </div>
              <div>
                <dt>Current observation state</dt>
                <dd>
                  {if row.finding.resolved_at,
                    do: "No longer observed in local inventory",
                    else: "Open in local inventory"}
                </dd>
              </div>
              <div :if={row.finding.suppressed}>
                <dt>Current scanner suppression</dt>
                <dd>Suppressed — not mitigation evidence</dd>
              </div>
            </dl>
            <.technical_value
              id={"event-image-#{row.id}"}
              label="Current image reference"
              value={image_reference(row.image)}
            />
            <.technical_value
              id={"event-digest-#{row.id}"}
              label="Current image digest"
              value={row.image.digest}
            />
            <div>
              <h4>Recorded placements · current local records</h4>
              <p :if={row.placements == []} class="supporting">No placements recorded.</p>
              <ul :if={row.placements != []}>
                <li :for={placement <- row.placements}>
                  {reported(placement.owner)} · {reported(placement.environment)} ·
                  Namespace: {reported(placement.namespace)} · {if placement.active,
                    do: "Active",
                    else: "Inactive"}
                </li>
              </ul>
            </div>
          </section>
          <.link
            :if={row.detail_available?}
            id={"event-link-#{row.id}"}
            navigate={detail_path(row, @filters, @cursor)}
            class="button button-secondary"
          >
            Open current finding detail
          </.link>
          <p
            :if={not row.detail_available?}
            id={"event-scope-note-#{row.id}"}
            class="supporting"
          >
            No active placement in this scope; current scoped detail unavailable.
          </p>
        </li>
      </ul>
    </Layouts.app>
    """
  end
end
