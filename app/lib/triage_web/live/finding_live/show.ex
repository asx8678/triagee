defmodule TriageWeb.FindingLive.Show do
  @moduledoc """
  Detail for one finding occurrence: source facts, deployment scope, lifecycle
  history and other occurrences of the same advisory. Third-party text is always
  rendered as text; scope parameters from the list view are preserved and
  validated with the shared `TriageWeb.FindingFilters` contract.
  """

  use TriageWeb, :live_view

  alias Triage.Cases
  alias Triage.Intel
  alias Triage.Inventory
  alias TriageWeb.{ActivityFilters, FindingFilters}

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(page_title: "Finding detail")
     |> assign(:invalid_scope, [])
     |> assign(:open_case_error, nil)
     |> assign(:data, nil)}
  end

  @impl true
  def handle_params(%{"id" => id} = params, _uri, socket) do
    parsed = FindingFilters.parse(params)
    socket = assign(socket, :activity_return, activity_return(params))

    scope = %{
      owner: parsed.owner,
      environment: parsed.environment,
      q: parsed.q,
      suppressed: parsed.include_suppressed,
      severity: parsed.severity,
      # Result order and position in the list this occurrence was opened from,
      # so the back link returns to the same slice instead of the default view.
      # Kept separate from `scope_qs/1`, which also feeds /cases links.
      sort: parsed.sort,
      before: parsed.before
    }

    if parsed.invalid != [] do
      # No finding data is fetched or rendered for malformed scope values;
      # they are surfaced visibly instead of being coerced or unscoped. Stale
      # data from a previously valid navigation of this same LiveView is
      # cleared so nothing derived from it survives; only the explicit
      # last-valid scope is preserved for the back link, so we never silently
      # broaden the view while retaining old data.
      {:noreply,
       socket
       |> assign(:invalid_scope, parsed.invalid)
       |> assign(:scope, preserved_scope(socket))
       |> assign(:data, nil)}
    else
      case parse_finding_id(id) do
        :error ->
          not_found(socket, scope)

        {:ok, finding_id} ->
          case Inventory.fetch_finding(finding_id,
                 owner: scope.owner,
                 environment: scope.environment
               ) do
            {:ok, data} ->
              {:noreply,
               socket
               |> assign(:invalid_scope, [])
               |> assign(:scope, scope)
               |> assign(:data, data)
               |> assign(:page_title, finding_title(data.finding.cve))
               |> assign(:kev, Intel.kev_row(data.finding.cve))}

            {:error, :out_of_scope} ->
              {:noreply,
               socket
               |> put_flash(:error, "Finding is outside the selected team or environment scope.")
               |> push_navigate(to: back_path(scope))}

            :error ->
              not_found(socket, scope)
          end
      end
    end
  end

  # findings.id is a bigint (bigserial) primary key in the actual local schema.
  # The web layer only parses ids into positive integers; the single runtime
  # upper-bound source of truth is the `Triage.Inventory.fetch_finding/2`
  # guard, which rejects out-of-range ids before any database query. Anything
  # else — malformed, zero, negative or too large — redirects instead of
  # reaching the database, including the client-cast forms the router cannot
  # reject.
  defp parse_finding_id(id) do
    case Integer.parse(id) do
      {finding_id, ""} when finding_id > 0 -> {:ok, finding_id}
      _ -> :error
    end
  end

  # The last explicitly valid scope, or an empty All scope when the first
  # navigation is already invalid. Keeps the back link honest without
  # reusing any stale finding data.
  defp preserved_scope(socket) do
    case socket.assigns[:scope] do
      nil ->
        %{
          owner: nil,
          environment: nil,
          q: nil,
          suppressed: false,
          severity: nil,
          sort: nil,
          before: nil
        }

      scope ->
        scope
    end
  end

  defp not_found(socket, scope) do
    {:noreply,
     socket
     |> put_flash(:error, "Finding not found.")
     |> push_navigate(to: back_path(scope))}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="findings">
      <.page_header
        title={if @data, do: @data.finding.cve, else: "Finding detail"}
        eyebrow={if @data, do: "Findings / #{@data.finding.cve}", else: "Findings / Occurrence"}
        subtitle="Current local inventory for one package occurrence, not saved case evidence."
      >
        <:actions>
          <.link
            :if={@activity_return}
            id="back-to-activity"
            navigate={activity_path(@activity_return)}
            class="button button-secondary"
          >
            ← Back to activity
          </.link>
          <.link id="back-to-findings" navigate={back_path(@scope)} class="button button-secondary">
            ← Back to inventory
          </.link>
          <.link
            :if={advisory_target(@data, @scope)}
            id="finding-cve-action"
            navigate={advisory_target(@data, @scope)}
            class="button button-secondary"
          >
            Advisory page
          </.link>
          <.copy_value id="finding-cve-copy" label="advisory id" value={finding_cve(@data)} />
        </:actions>
      </.page_header>

      <p :if={@invalid_scope != []} id="invalid-scope" class="notice" role="alert">
        Invalid scope parameter{if length(@invalid_scope) == 1, do: "", else: "s"} for
        <strong>{Enum.map_join(@invalid_scope, ", ", &to_string/1)}</strong>
        — no finding details are shown.
        Filters accept plain text of at most 120 characters without control characters; the order
        must be one of the listed choices, and a position must be one the findings list issued.
        A position is never guessed. Return to the inventory to choose valid filters.
      </p>

      <%= if @data do %>
        <p :if={@kev} id="finding-kev" class="cluster">
          <.kev_marker id="finding-kev-badge" kev={@kev} />
          <span class="supporting">
            Cached KEV feed, populated by an explicit operator refresh — current public
            intelligence about this advisory, not saved case evidence. No marker is shown for
            an advisory the cache does not hold.
          </span>
        </p>

        <section id="finding-summary" class="stack" aria-labelledby="finding-summary-title">
          <div>
            <h2 id="finding-summary-title">
              {@data.finding.package_name} <code>{@data.finding.package_version}</code>
            </h2>
            <p class="supporting">Occurrence #{@data.finding.id}</p>
          </div>
          <dl class="evidence-grid key-value finding-identity-strip">
            <div>
              <dt>Scanner severity</dt>
              <dd><.status_badge label={label(@data.finding.severity)} kind="severity" /></dd>
            </div>
            <div>
              <dt>Installed version</dt>
              <dd><code>{reported(@data.finding.package_version)}</code></dd>
            </div>
            <div>
              <dt>Reported fixed version</dt>
              <dd>
                <code>{reported(@data.finding.fix)}</code>
                <span class="supporting">Not verified fixed</span>
              </dd>
            </div>
            <div>
              <dt>Display scope</dt>
              <dd id="finding-display-scope">
                {@scope.owner || "All teams"} · {@scope.environment || "All environments"}
              </dd>
            </div>
            <div>
              <dt>Local observation state</dt>
              <dd>
                {if @data.finding.resolved_at,
                  do: "No longer observed in local inventory",
                  else: "Open in local inventory"}
              </dd>
            </div>
            <div :if={@data.finding.suppressed}>
              <dt>Scanner suppression</dt>
              <dd>Suppressed — not mitigation evidence</dd>
            </div>
            <div :if={@data.finding.reopen_count > 0}>
              <dt>Reopened</dt>
              <dd>{@data.finding.reopen_count} times observed again locally</dd>
            </div>
          </dl>
          <.technical_value
            id="finding-image-reference"
            label="Image reference"
            value={image_reference(@data.finding.image)}
          />
          <.technical_value
            id="finding-image-digest"
            label="Image digest"
            value={@data.finding.image.digest}
          />
          <p :if={@data.finding.resolved_at} id="finding-disappearance-warning" class="notice">
            No longer observed is not verified remediation. This does not establish that a fix was deployed.
          </p>
        </section>

        <%= if explicit_scope?(@scope) do %>
          <section id="open-case-form" class="notice" aria-labelledby="open-case-title">
            <h2 id="open-case-title">Review this occurrence</h2>
            <p>
              Open or create one local case for <strong>{@scope.owner} · {@scope.environment}</strong>.
              Creating a case captures frozen evidence from local inventory; this page itself is not a snapshot.
              Existing cases retain their saved scope and evidence.
            </p>
            <p class="supporting">
              Assessments are recorded by the unauthenticated local-operator, apply only to the saved scope,
              and do not approve an exception, suppress a finding, or verify a fix.
            </p>
            <div class="cluster">
              <button
                id="open-case-btn"
                type="button"
                phx-click="open_case"
                phx-disable-with="Opening local case…"
                data-confirm="Open this local review case? If it does not exist, this creates a case and captures local evidence for the displayed team and environment."
                class="button"
              >
                Open case for {@scope.owner} · {@scope.environment}
              </button>
              <.link navigate={~p"/cases?#{scope_qs(@scope)}"} class="button button-secondary">Browse saved review cases</.link>
            </div>
            <p :if={@open_case_error} id="open-case-error" role="alert">
              {open_case_error_text(@open_case_error)}
            </p>
          </section>
        <% else %>
          <section id="open-case-guidance" class="notice">
            <h2>Review cases need an explicit team and environment</h2>
            <p>
              A manual review binds to one concrete team and environment; neither is guessed from placements.
              Select both on the <.link navigate={back_path(@scope)}>inventory</.link>
              to open a local case.
              Browsing this page does not create a case or refresh saved evidence.
            </p>
          </section>
        <% end %>

        <div class="stack">
          <section
            id="finding-observations"
            class="stack"
            aria-labelledby="finding-observations-title"
          >
            <h2 id="finding-observations-title" class="section-header">Observation context</h2>
            <dl class="evidence-grid key-value">
              <div>
                <dt>First seen</dt><dd><.timestamp value={@data.finding.first_seen} /></dd>
              </div>
              <div>
                <dt>Last seen</dt><dd><.timestamp value={@data.finding.last_seen} /></dd>
              </div>
              <div :if={@data.finding.resolved_at}>
                <dt>No longer observed</dt><dd><.timestamp value={@data.finding.resolved_at} /></dd>
              </div>
            </dl>
            <p class="supporting">
              Observation times are not scan completion, production freshness, or fix verification.
            </p>
            <details id="finding-source" class="disclosure">
              <summary>Scanner description and source details</summary>
              <div class="stack">
                <h3>Scanner description</h3>
                <p id="scanner-description">{reported(@data.finding.description)}</p>
                <.technical_value
                  id="finding-source-reference"
                  label="Source reference (reported text)"
                  value={@data.finding.url}
                />
                <p class="supporting">
                  Scanner identity and collection-run provenance are not captured on this occurrence.
                </p>
                <p :if={@data.finding.image.description}>
                  Image description: {@data.finding.image.description}
                </p>
              </div>
            </details>
          </section>

          <section class="stack" aria-labelledby="placements-title">
            <h2 id="placements-title" class="section-header">Recorded deployment placements</h2>
            <p class="supporting">
              Current local placement records within the display scope, not historical event ownership.
            </p>
            <p :if={@data.placements == []} class="empty-state">No deployment placements recorded.</p>
            <div
              class="table-region"
              role="region"
              tabindex="0"
              aria-label="Recorded deployment placements"
            >
              <table id="placements" class="data-table">
                <thead>
                  <tr>
                    <th scope="col">Team</th><th scope="col">Environment</th><th scope="col">
                      Namespace
                    </th><th scope="col">Placement state</th>
                  </tr>
                </thead>
                <tbody>
                  <tr :for={p <- @data.placements}>
                    <th scope="row">{reported(p.owner)}</th>
                    <td>{reported(p.environment)}</td>
                    <td>
                      {reported(p.namespace)}
                      <span :if={p.namespace == "(unknown)"} class="supporting">deployment context unknown</span>
                    </td>
                    <td>{if p.active, do: "Active", else: "Inactive"}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section id="finding-history" class="stack" aria-labelledby="finding-history-title">
            <h2 id="finding-history-title" class="section-header">Lifecycle history</h2>
            <p class="supporting">
              Recorded observation time, oldest first; ties use record ID. These events do not verify remediation.
            </p>
            <p :if={@data.events == []} class="empty-state">No lifecycle events recorded.</p>
            <ol class="event-list">
              <li :for={event <- @data.events} id={"finding-event-#{event.id}"} class="event-item">
                <h3>{event_label(event.event)}</h3>
                <p>Recorded observation time <.timestamp value={event.occurred_at} /></p>
                <p :if={event.note}>Recorded note: {event.note}</p>
                <span class="supporting">Event #{event.id}</span>
              </li>
            </ol>
          </section>

          <section id="other-occurrences" class="stack" aria-labelledby="other-occurrences-title">
            <h2 id="other-occurrences-title" class="section-header">
              Other occurrences of this advisory
            </h2>
            <p class="supporting">
              Open local occurrences in this scope, including suppressed. Each keeps its own package, image and review scope.
            </p>
            <p :if={@data.other_occurrences == []} class="empty-state">
              No other open occurrences in this scope.
            </p>
            <ul class="event-list">
              <li :for={f <- @data.other_occurrences} id={"occurrence-#{f.id}"} class="event-item">
                <.link
                  id={"occurrence-link-#{f.id}"}
                  navigate={occurrence_path(f.id, @scope, @activity_return)}
                >
                  {f.package_name} {f.package_version}
                </.link>
                <.technical_value
                  id={"occurrence-image-#{f.id}"}
                  label="Image"
                  value={image_reference(f.image) || f.image.digest}
                />
                <span :if={f.suppressed} class="supporting">suppressed — not mitigation evidence</span>
              </li>
            </ul>
          </section>
        </div>
      <% end %>
    </Layouts.app>
    """
  end

  # Opening a case is an explicit action bound to the state the user actually
  # sees: the finding id and scope come from the socket assigns, never from
  # forgeable event parameters. The context re-validates the scope freshly and
  # fails closed when no active scoped placement remains.
  @impl true
  def handle_event("open_case", _params, socket) do
    data = socket.assigns[:data]
    scope = socket.assigns[:scope]

    if is_nil(data) or is_nil(scope) or not explicit_scope?(scope) do
      # A stale or malformed click never opens an unscoped case.
      {:noreply, assign(socket, :open_case_error, :invalid_scope)}
    else
      case Cases.open_case(data.finding.id, owner: scope.owner, environment: scope.environment) do
        {:ok, %{case: review_case}} ->
          {:noreply,
           socket
           |> assign(:open_case_error, nil)
           |> push_navigate(to: ~p"/cases/#{review_case.id}?#{scope_qs(scope)}")}

        {:error, reason}
        when reason in [:invalid_scope, :out_of_scope, :not_found, :invalid_request] ->
          {:noreply, assign(socket, :open_case_error, reason)}
      end
    end
  end

  defp explicit_scope?(%{owner: owner, environment: environment}) do
    is_binary(owner) and owner != "" and is_binary(environment) and environment != ""
  end

  defp open_case_error_text(:invalid_scope) do
    "A case needs one explicit team and environment. Select both on the inventory and try again."
  end

  defp open_case_error_text(:out_of_scope) do
    "No active placement remains in this scope in the source inventory — a case cannot be opened."
  end

  defp open_case_error_text(:not_found) do
    "The finding is no longer available in this scope."
  end

  defp open_case_error_text(:invalid_request) do
    "The request was malformed and nothing was created."
  end

  defp open_case_error_text(_other) do
    "The case could not be opened. Nothing was created."
  end

  # Return navigation is independently validated display context. It never
  # supplies the occurrence's scope or an open-case action's saved scope.
  defp activity_return(%{"activity" => %{"from" => "activity"} = context}) do
    parsed = ActivityFilters.parse(Map.delete(context, "from"))
    if parsed.invalid == [], do: parsed, else: nil
  end

  defp activity_return(_params), do: nil

  defp activity_path(context), do: ~p"/whats-new?#{ActivityFilters.query_params(context)}"

  defp occurrence_path(id, scope, nil), do: ~p"/findings/#{id}?#{findings_list_qs(scope)}"

  defp occurrence_path(id, scope, context) do
    return_context = context |> ActivityFilters.query_params() |> Map.put(:from, "activity")
    qs = Map.put(findings_list_qs(scope), :activity, return_context)
    ~p"/findings/#{id}?#{qs}"
  end

  defp back_path(scope), do: ~p"/findings?#{findings_list_qs(scope)}"

  # The findings list query, including the result order and position. Distinct
  # from `scope_qs/1`, which is also used for /cases links and must stay
  # scope-only.
  # The advisory aggregate for this occurrence, scoped to the display scope the
  # finding was opened in. Only the two scope keys travel: the list's own q,
  # severity, order and cursor params mean nothing to the advisory route, and
  # sending them would be a link that claims a filter it cannot apply. Returns
  # nil — no link at all — when the captured advisory id is blank.
  # The tab title names the advisory, so several findings stay distinguishable in a tab
  # strip. Before the occurrence loads there is no id to name.
  defp finding_title(cve) when is_binary(cve) and cve != "", do: cve <> " · Finding"
  defp finding_title(_cve), do: "Finding detail"

  defp finding_cve(%{finding: %{cve: cve}}), do: cve
  defp finding_cve(_data), do: nil

  # The advisory aggregate for the loaded occurrence in this page's display scope, or nil
  # when no captured id can address the route: absent data, a missing id and a blank id all
  # render no link at all rather than a link to an empty route.
  defp advisory_target(data, scope), do: FindingFilters.advisory_path(finding_cve(data), scope)

  defp findings_list_qs(scope) do
    FindingFilters.query_params(%{
      owner: scope.owner,
      environment: scope.environment,
      q: scope.q,
      include_suppressed: scope.suppressed,
      severity: Map.get(scope, :severity),
      sort: Map.get(scope, :sort),
      before: Map.get(scope, :before)
    })
  end

  defp scope_qs(%{owner: owner, environment: environment, q: q, suppressed: suppressed}) do
    qs =
      %{owner: owner, environment: environment, q: q}
      |> Enum.reject(fn {_key, value} -> is_nil(value) end)
      |> Map.new()

    if suppressed, do: Map.put(qs, :suppressed, "1"), else: qs
  end

  defp reported(value) when value in [nil, ""], do: "Not reported"
  defp reported(value), do: value

  defp label(value) when value in [nil, ""], do: "Not reported"
  defp label(value), do: String.upcase(value)

  defp image_reference(%{repository: repository, tag: tag})
       when is_binary(repository) and repository != "" and is_binary(tag) and tag != "",
       do: repository <> ":" <> tag

  defp image_reference(%{repository: repository}) when is_binary(repository) and repository != "",
    do: repository

  defp image_reference(_image), do: nil

  defp event_label("appeared"), do: "First observed locally"
  defp event_label("resolved"), do: "No longer observed in local inventory"
  defp event_label("reopened"), do: "Observed again locally"
  defp event_label(_event), do: "Unknown lifecycle event"
end
