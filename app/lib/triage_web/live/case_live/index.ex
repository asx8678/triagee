defmodule TriageWeb.CaseLive.Index do
  @moduledoc """
  Read-only Review Queue (PR 3): one row per saved review case, newest opened
  first, filterable by the saved team/environment scope.

  Browsing never opens, writes or approves anything. `handle_params` is the
  authoritative queue load: invalid URL parameters render a visible error and
  clear all rows, pagination and row links — never a widened All scope or
  stale rows. The server-owned, explicitly unauthenticated `local-operator`
  model and the local/synthetic coverage warning stay visible; display
  scoping is not authorization. Evidence badges compare the captured snapshot
  hash against current local source facts only — they are not production
  freshness or approval claims.
  """

  use TriageWeb, :live_view

  alias Triage.Cases
  alias Triage.Exceptions
  alias Triage.Intel
  alias TriageWeb.CaseFilters
  alias TriageWeb.FilterAssigns

  # Only the route-id guard: `text/1` here is Phoenix.HTML's escaping helper,
  # which the queue already uses for captured display values.
  import TriageWeb.CaseLive.Format, only: [linkable?: 1]

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Review Queue")
     |> assign(:filter_form, FilterAssigns.filter_form(%{}))
     |> assign(:filters, %{owner: nil, environment: nil})
     |> assign(:options, %{owners: [], environments: []})
     |> assign(:queue_error, nil)
     |> assign(:queue_empty?, false)
     |> assign(:page_count, 0)
     |> assign(:has_more?, false)
     |> assign(:next_before_id, nil)
     |> assign(:cursor, nil)
     |> assign(:raw_params, %{})
     |> assign(:kev_status, nil)
     |> stream_configure(:cases, dom_id: &"case-#{&1.id}")}
  end

  # The URL is the single source of truth: every queue load — initial mount,
  # patch navigation, manual reload — re-parses the current params here.
  # Invalid input never queries the domain, never widens to All and never
  # keeps previously rendered rows.
  @impl true
  def handle_params(params, _uri, socket) do
    {:noreply, socket |> assign(:raw_params, params) |> load_queue()}
  end

  @impl true
  def handle_event("filter", params, socket) do
    parsed = CaseFilters.parse_event(params)

    if parsed.invalid == [] do
      # A successful scope-filter action discards any old cursor: the new
      # scope starts at the newest page.
      {:noreply,
       push_patch(socket,
         to: newest_path(%{owner: parsed.owner, environment: parsed.environment})
       )}
    else
      # Keep the last valid URL; show the invalid state and no rows.
      {:noreply, queue_error(socket, parsed.owner, parsed.environment)}
    end
  end

  # Manual reload re-runs the CURRENT params query without any patch; no
  # timer or automatic mutation exists in this slice.
  @impl true
  def handle_event("reload", _params, socket) do
    {:noreply, load_queue(socket)}
  end

  # Any other or malformed event body: a visible error, no writes, the
  # channel stays alive.
  def handle_event(_other, _params, socket) do
    filters = socket.assigns.filters

    {:noreply, queue_error(socket, filters[:owner], filters[:environment])}
  end

  defp load_queue(socket) do
    parsed = CaseFilters.parse(socket.assigns.raw_params)

    if parsed.invalid != [] do
      queue_error(socket, parsed.owner, parsed.environment)
    else
      case Cases.list_cases(
             owner: parsed.owner,
             environment: parsed.environment,
             before_id: parsed.before_id
           ) do
        {:ok, %{rows: rows, has_more?: has_more?, next_before_id: next_before_id}} ->
          socket
          |> assign(:queue_error, nil)
          |> assign(:queue_empty?, rows == [])
          |> assign(:page_count, length(rows))
          |> assign(:filter_form, FilterAssigns.filter_form(parsed))
          |> assign(:filters, %{owner: parsed.owner, environment: parsed.environment})
          |> assign(:options, Cases.case_filter_options())
          |> assign(:has_more?, has_more?)
          |> assign(:next_before_id, next_before_id)
          |> assign(:cursor, parsed.before_id)
          |> assign(:kev, Intel.kev_index(Enum.map(rows, & &1.finding.cve)))
          |> assign(:kev_status, Intel.kev_status())
          |> stream(:cases, Exceptions.decorate_rows(rows), reset: true)

        {:error, _reason} ->
          # A queue data-load error must never masquerade as current data.
          queue_error(socket, parsed.owner, parsed.environment)
      end
    end
  end

  # The visible error state: rows, pagination and row links from any previous
  # valid state are cleared; nothing is widened to All.
  defp queue_error(socket, owner, environment) do
    socket
    |> assign(:queue_error, true)
    |> assign(FilterAssigns.cleared_page())
    |> assign(:queue_empty?, false)
    |> assign(:filters, %{owner: owner, environment: environment})
    |> assign(:kev, %{})
    |> assign(:kev_status, nil)
    |> stream(:cases, [], reset: true)
  end

  defp newest_path(filters) do
    qs =
      %{owner: filters[:owner], environment: filters[:environment]}
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()

    if map_size(qs) == 0 do
      ~p"/cases"
    else
      ~p"/cases?#{qs}"
    end
  end

  defp older_path(filters, next_before_id) do
    qs =
      %{owner: filters[:owner], environment: filters[:environment]}
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()
      |> Map.put(:before, next_before_id)

    ~p"/cases?#{qs}"
  end

  # The advisory detail for a queue row, carrying the queue's own scope so the
  # advisory opens on the team and environment the row was read in. The id is the
  # frozen captured one; a blank capture renders as text, never as a link.
  defp cve_path(row, filters) do
    qs =
      %{owner: filters[:owner], environment: filters[:environment]}
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()

    if map_size(qs) == 0 do
      ~p"/cves/#{row.finding.cve}"
    else
      ~p"/cves/#{row.finding.cve}?#{qs}"
    end
  end

  defp image_label(%{repository: repository, tag: tag})
       when is_binary(repository) and repository != "" and is_binary(tag) and tag != "",
       do: repository <> ":" <> tag

  defp image_label(%{repository: repository}) when is_binary(repository) and repository != "",
    do: repository

  defp image_label(%{digest: digest}) when is_binary(digest) and digest != "", do: digest
  defp image_label(_other), do: nil

  defp review_label(:awaiting_review), do: "No assessment recorded"
  defp review_label(:current_review), do: "Assessment recorded"
  defp review_label(:needs_revalidation), do: "Assessment needs revalidation"
  defp review_label(_other), do: "Assessment unavailable"

  defp evidence_label(:current), do: "Local evidence match"
  defp evidence_label(:changed), do: "Local evidence changed"
  defp evidence_label(:source_out_of_scope), do: "Source out of saved scope"
  defp evidence_label(:source_missing), do: "Source unavailable"
  defp evidence_label(_other), do: "Evidence unavailable"

  defp priority_label("expedited_review"), do: "Expedited review"
  defp priority_label("normal_review"), do: "Normal review"
  defp priority_label("insufficient_context"), do: "Insufficient context"
  defp priority_label(_), do: "Not reported"

  defp text(value) when value in [nil, ""], do: "Not captured"
  defp text(value), do: value

  defp case_path(row, filters, cursor) do
    queue =
      %{owner: filters[:owner], environment: filters[:environment], before_id: cursor}
      |> CaseFilters.query_params()
      |> Map.put(:from, "queue")

    ~p"/cases/#{row.id}?#{%{owner: row.owner, environment: row.environment, queue: queue}}"
  end

  # A valid but unsaved scope (for example ?owner=ghost-team) is still the active
  # filter, so the select must keep that value visible and selected. Rendering
  # only the saved options would silently display "All teams" while the queue is
  # actually scoped, which misreports the current view.
  defp scope_options(values, selected, all_label) do
    options = [{all_label, ""} | Enum.map(values, &{&1, &1})]

    if is_binary(selected) and selected != "" and selected not in values do
      options ++ [{selected <> " (not in saved scopes)", selected}]
    else
      options
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="cases">
      <.page_header
        title="Review Queue"
        subtitle="Saved review cases · newest opened first (case ID descending)"
      />
      <p id="queue-banner" class="supporting">
        Browsing does not open cases or write assessments. Recorded assessments are local-operator history, not approval or remediation.
      </p>
      <section class="filter-toolbar" aria-label="Queue filters and actions">
        <.form id="queue-filters" for={@filter_form} phx-change="filter" class="cluster">
          <.input
            type="select"
            label="Team"
            name="owner"
            value={@filters[:owner]}
            options={scope_options(@options[:owners], @filters[:owner], "All teams")}
          />
          <.input
            type="select"
            label="Environment"
            name="environment"
            value={@filters[:environment]}
            options={
              scope_options(@options[:environments], @filters[:environment], "All environments")
            }
          />
        </.form>
        <div class="cluster">
          <button
            id="reload-queue"
            type="button"
            phx-click="reload"
            phx-disable-with="Reloading…"
            class="button button-secondary"
          >Reload queue</button>
          <.link id="clear-filters" patch={~p"/cases"} class="button button-secondary">Clear filters</.link>
        </div>
      </section>
      <.notice :if={@queue_error} id="queue-error" kind="error" role="alert">
        Queue could not be loaded. Invalid parameters never widen scope or retain previous rows. Use plain-text filters (up to 120 characters) and a positive whole-number cursor. Correct the address, clear filters, or retry “Reload queue”.
      </.notice>
      <div :if={is_nil(@queue_error)} id="queue-pagination" class="filter-summary cluster">
        <span>{@page_count} saved cases on this page · Newest opened first · {if @filters[:owner],
          do: @filters[:owner],
          else: "All teams"} · {if @filters[:environment],
          do: @filters[:environment],
          else: "All environments"}</span>
        <.link
          :if={@has_more?}
          id="older-cases"
          patch={older_path(@filters, @next_before_id)}
          class="button button-secondary"
        >Older cases</.link>
        <.link
          :if={@cursor}
          id="newest-cases"
          patch={newest_path(@filters)}
          class="button button-secondary"
        >Newest cases</.link>
      </div>
      <.empty_state
        :if={@queue_empty? and is_nil(@queue_error)}
        id="queue-empty"
        title="No saved review cases for this scope"
        description="An empty result is not proof of a clean estate."
      >
        <:actions>
          <.link patch={~p"/cases"} class="button button-secondary">Show all saved cases</.link>
        </:actions>
      </.empty_state>
      <%!-- Empty/error messages stay outside the stream so patches cannot retain stale static rows. --%>
      <.kev_note id="queue-kev-note" present?={map_size(@kev) > 0} />
      <.kev_source_status id="queue-kev-status" status={@kev_status} />

      <div class="table-region" role="region" tabindex="0" aria-label="Saved review cases">
        <table id="queue-table" class="data-table">
          <thead>
            <tr>
              <th scope="col">Finding / package</th><th scope="col">Image</th><th scope="col">
                Saved scope
              </th><th scope="col">Evidence / capture</th><th scope="col">Assessment</th><th scope="col">
                Action
              </th>
            </tr>
          </thead>
          <tbody id="case-queue" phx-update="stream">
            <tr :for={{id, row} <- @streams.cases} id={id}>
              <th scope="row">
                <.link
                  :if={linkable?(row.finding.cve)}
                  id={"case-cve-#{row.id}"}
                  navigate={cve_path(row, @filters)}
                >
                  <strong>{text(row.finding.cve)}</strong>
                </.link>
                <strong :if={not linkable?(row.finding.cve)}>{text(row.finding.cve)}</strong>
                <p>
                  {text(row.finding.package_name)} <code>{text(row.finding.package_version)}</code>
                </p>
                <p class="supporting">Case #{row.id} · Revision {row.revision}</p>
                <span class="cluster">
                  <.status_badge label={text(row.finding.severity)} kind="severity" />
                  <.kev_marker id={"case-kev-#{row.id}"} kev={@kev[row.finding.cve]} />
                </span>
              </th>
              <td>
                <.technical_value
                  id={"queue-image-#{row.id}"}
                  label="Image reference"
                  value={image_label(row.finding.image)}
                  variant="compact"
                />
              </td>
              <td>
                <p>{row.owner}</p><p class="supporting">{row.environment}</p>
              </td>
              <td>
                <span id={"evidence-status-#{row.id}"}><.status_badge label={
                  evidence_label(row.evidence_status)
                } /></span>
                <p :if={row.snapshot}>Snapshot v{row.snapshot.version}</p>
                <p :if={row.snapshot} class="supporting">
                  Captured <.timestamp value={row.snapshot.captured_at} />
                </p>
                <p :if={is_nil(row.snapshot)} class="muted">No captured snapshot</p>
              </td>
              <td>
                <span id={"review-status-#{row.id}"}><.status_badge
                  label={review_label(row.review_status)}
                  kind={if row.review_status == :needs_revalidation, do: :warning, else: :neutral}
                /></span>
                <p :if={row.latest_review} class="supporting">
                  Saved <.timestamp value={row.latest_review.inserted_at} />
                </p>
                <p :if={row.latest_review}>{priority_label(row.latest_review.priority)}</p>
                <p :if={row.latest_review} class="supporting">
                  {if row.latest_review.snapshot_id == row.current_snapshot_id,
                    do: "Applies to displayed snapshot",
                    else: "Saved against older snapshot"}
                </p>
              </td>
              <td>
                <p id={"case-exception-status-#{row.id}"}>{Exceptions.label(row.exception_status)}</p>
                <.link
                  id={"case-link-#{row.id}"}
                  navigate={case_path(row, @filters, @cursor)}
                  class="button button-secondary"
                >Review case</.link>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <details id="queue-legend" class="disclosure">
        <summary>Evidence and assessment meaning</summary>
        <p>
          Local evidence match means only that the captured hash matches current local source facts, not production freshness. An assessment on the displayed snapshot can still need revalidation when local evidence changes. Assessments do not activate exceptions or verify remediation. Separate local exception decisions have their own reason, expiry and history. Filters select saved case scopes, not access rights.
        </p>
      </details>
    </Layouts.app>
    """
  end
end
