defmodule TriageWeb.FindingLive.Index do
  @moduledoc """
  CVE inventory grouped by advisory, with URL-restorable team/environment filters.

  Synthetic demo data only (PR 1). Team filtering scopes what is displayed; it is
  not authentication or authorization, and this unauthenticated demo must stay on
  loopback until real identity and roles land.
  """

  use TriageWeb, :live_view

  alias Triage.Inventory
  alias TriageWeb.FindingFilters

  # One page of advisory groups. The list is bounded so a large estate cannot
  # render every group in one response; the total comes from count_groups/1.
  @per_page 25

  @sort_labels %{
    "severity" => "Severity (highest first)",
    "newest" => "Newest first observed",
    "occurrences" => "Most occurrences",
    "cve" => "Advisory id (A–Z)"
  }

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Findings")
      |> assign(:invalid_filters, [])
      |> stream_configure(:groups, dom_id: &"group-#{&1.cve}")

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    parsed = FindingFilters.parse(params)
    invalid = parsed.invalid != []

    # Invalid values are never normalized into a scope, truncated or dropped:
    # nothing is queried and the state is surfaced visibly instead.
    unknown_team? = not invalid and team_unknown?(parsed.owner)
    sort = parsed.sort || default_sort()
    requested_page = parsed.page || 1

    scope_opts = [
      owner: parsed.owner,
      environment: parsed.environment,
      include_suppressed: parsed.include_suppressed,
      search: parsed.q,
      severity: parsed.severity
    ]

    {groups, total, page, pages} =
      if invalid or unknown_team? do
        {[], 0, 1, 1}
      else
        total = Inventory.count_groups(scope_opts)
        pages = page_count(total)
        # A page past the end renders the last page rather than a misleading
        # empty table, and the rendered page number is the effective one.
        page = min(requested_page, pages)

        groups =
          Inventory.list_groups(
            scope_opts ++ [sort: sort, limit: @per_page, offset: (page - 1) * @per_page]
          )

        {groups, total, page, pages}
      end

    {:noreply,
     socket
     |> assign(
       :filters,
       %{
         owner: parsed.owner,
         environment: parsed.environment,
         search: parsed.q,
         include_suppressed: parsed.include_suppressed,
         severity: parsed.severity,
         sort: sort,
         page: page
       }
     )
     |> assign(:invalid_filters, if(invalid, do: parsed.invalid, else: []))
     |> assign(:unknown_team?, unknown_team?)
     |> assign(:teams, Inventory.teams())
     |> assign(:environments, Inventory.environments())
     |> assign(:counts, Inventory.summary_counts())
     |> assign(:advisory_count, total)
     |> assign(:page, page)
     |> assign(:page_count, pages)
     |> assign(:showing_from, if(groups == [], do: 0, else: (page - 1) * @per_page + 1))
     |> assign(:showing_to, (page - 1) * @per_page + length(groups))
     |> assign(:order_note, sort_note(sort))
     |> assign(:sort_options, sort_options())
     |> assign(
       :filter_form,
       to_form(%{
         "owner" => parsed.owner,
         "environment" => parsed.environment,
         "q" => parsed.q,
         "suppressed" => parsed.include_suppressed,
         "severity" => parsed.severity,
         "sort" => sort
       })
     )
     |> assign(:empty?, groups == [])
     |> stream(:groups, groups, reset: true)}
  end

  @impl true
  def handle_event("filter", params, socket) do
    parsed = FindingFilters.parse_event(params)

    if parsed.invalid == [] do
      {:noreply,
       push_patch(socket, to: ~p"/findings?#{FindingFilters.query_params(canonical(parsed))}")}
    else
      # Keep the last valid URL; show the invalid state and no findings.
      {:noreply,
       socket
       |> assign(:invalid_filters, parsed.invalid)
       |> assign(:unknown_team?, false)
       |> assign(:advisory_count, 0)
       |> assign(:page, 1)
       |> assign(:page_count, 1)
       |> assign(:showing_from, 0)
       |> assign(:showing_to, 0)
       |> assign(:empty?, true)
       |> stream(:groups, [], reset: true)}
    end
  end

  defp team_unknown?(nil), do: false

  defp team_unknown?(owner) do
    owner not in Inventory.teams()
  end

  # The default order is the absence of a sort parameter: a filter event that
  # leaves the order at its default keeps the canonical URL instead of pinning
  # `sort=severity` forever. A non-default order is preserved as chosen.
  defp canonical(parsed) do
    if parsed.sort == default_sort(), do: %{parsed | sort: nil}, else: parsed
  end

  defp default_sort, do: Inventory.default_group_sort()

  defp sort_options do
    Enum.map(Inventory.group_sorts(), &{Map.fetch!(@sort_labels, &1), &1})
  end

  defp page_count(0), do: 1
  defp page_count(total), do: div(total + @per_page - 1, @per_page)

  defp sort_note("severity") do
    "Sorted by highest scanner severity, then affected image count (most first), then advisory id (A–Z)."
  end

  defp sort_note("newest") do
    "Sorted by first local observation, newest first — first seen is local observation time, not CVE publication time — then advisory id (A–Z)."
  end

  defp sort_note("occurrences") do
    "Sorted by occurrence count in the selected scope (most first), then advisory id (A–Z)."
  end

  defp sort_note("cve"), do: "Sorted by advisory id (A–Z)."

  # The canonical list query. The default order and the first page stay out of
  # the URL so a shared link keeps its shortest form; both are still applied.
  defp list_query(filters, page_override) do
    page = page_override || filters[:page] || 1
    sort = filters[:sort] || default_sort()

    FindingFilters.query_params(%{
      owner: filters[:owner],
      environment: filters[:environment],
      q: filters[:search],
      include_suppressed: filters[:include_suppressed],
      severity: filters[:severity],
      sort: if(sort == default_sort(), do: nil, else: sort),
      page: if(page == 1, do: nil, else: page)
    })
  end

  defp list_path(filters, page_override) do
    case list_query(filters, page_override) do
      qs when map_size(qs) == 0 -> ~p"/findings"
      qs -> ~p"/findings?#{qs}"
    end
  end

  # Detail links carry the full list scope and result order so team,
  # environment, search, suppression, severity, sort and page all survive the
  # round trip, instead of silently returning to the default view.
  defp detail_path(id, filters) do
    case list_query(filters, nil) do
      qs when map_size(qs) == 0 -> ~p"/findings/#{id}"
      qs -> ~p"/findings/#{id}?#{qs}"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="findings">
      <.page_header
        title="Findings"
        subtitle="Advisories grouped across affected packages and images in local inventory."
      />

      <dl
        id="inventory-totals"
        class="metric-strip metric-strip-compact"
        aria-label="All local inventory counts"
      >
        <div>
          <dt>Open occurrences</dt>
          <dd id="open-occurrence-count">{@counts.open}</dd>
        </div>
        <div>
          <dt>Suppressed occurrences</dt>
          <dd id="suppressed-occurrence-count">{@counts.suppressed}</dd>
        </div>
      </dl>
      <details id="inventory-count-scope" class="disclosure supporting">
        <summary>All local inventory · counts are not filtered</summary>
        <p>
          Independent of filters and active placements. Open excludes suppressed; both counts exclude occurrences no longer observed. Suppression is not mitigation evidence.
        </p>
      </details>

      <.form id="filter-form" for={@filter_form} phx-change="filter" class="filter-toolbar">
        <.input
          field={@filter_form[:owner]}
          type="select"
          label="Team"
          options={display_scope_options(@teams, @filter_form[:owner].value, "All teams")}
        />
        <.input
          field={@filter_form[:environment]}
          type="select"
          label="Environment"
          options={
            display_scope_options(@environments, @filter_form[:environment].value, "All environments")
          }
        />
        <.input
          field={@filter_form[:q]}
          type="search"
          label="Search advisory or package"
          aria-describedby="inventory-search-help"
        />
        <.input
          field={@filter_form[:severity]}
          type="select"
          label="Severity"
          options={[
            {"All severities", ""},
            {"Critical", "CRITICAL"},
            {"High", "HIGH"},
            {"Medium", "MEDIUM"},
            {"Low", "LOW"}
          ]}
        />
        <.input
          field={@filter_form[:sort]}
          type="select"
          label="Sort"
          options={@sort_options}
          aria-describedby="findings-order"
        />
        <.input field={@filter_form[:suppressed]} type="checkbox" label="Include suppressed" />
        <.link id="reset-findings" patch={~p"/findings"} class="button button-secondary">Reset</.link>
        <div :if={@invalid_filters == []} id="findings-summary" class="filter-summary" role="status">
          <strong>{@advisory_count} matching {if @advisory_count == 1,
            do: "advisory",
            else: "advisories"}</strong>
          <span :if={@page_count > 1}>· Page {@page} of {@page_count}</span>
          <span>· {@filters[:owner] || "All teams"} · {@filters[:environment] || "All environments"}</span>
          <span :if={@filters[:search]}>· Search: “{@filters[:search]}”</span>
          <span>· {if @filters[:include_suppressed],
            do: "Including suppressed",
            else: "Suppressed excluded"}</span>
        </div>
      </.form>
      <p id="inventory-search-help" class="supporting">
        Package search matches the whole advisory group; other affected packages remain included.
      </p>

      <p :if={@invalid_filters != []} id="invalid-filters" class="notice" role="alert">
        Invalid filter value{if length(@invalid_filters) == 1, do: "", else: "s"} for
        <strong>{Enum.map_join(@invalid_filters, ", ", &to_string/1)}</strong>
        — no findings were loaded.
        Filters accept plain text of at most 120 characters without control characters; the page must
        be a whole number from 1 up, and the order one of the listed choices.
        Correct the filters or reset to recover.
      </p>
      <p :if={@unknown_team?} id="unknown-team" class="notice">
        Unknown team — showing no findings. Team filters are not authorization boundaries.
      </p>
      <p id="findings-order" class="supporting">
        {@order_note} Counts in each row use the selected scope and active placements; teams can overlap. {if @advisory_count >
                                                                                                                0,
                                                                                                              do:
                                                                                                                "Showing #{@showing_from}–#{@showing_to} of #{@advisory_count} matching advisories.",
                                                                                                              else:
                                                                                                                ""}
      </p>

      <div :if={@empty? and @invalid_filters == []} id="findings-empty" class="empty-state">
        <h2>No matching advisories</h2>
        <p>
          No open findings match this scope and search{if @filters[:include_suppressed],
            do: ", including suppressed occurrences",
            else: ""}.
          An empty result is not proof of a clean estate.
        </p>
        <.link patch={~p"/findings"} class="button button-secondary">Reset filters</.link>
      </div>

      <div
        class="table-region"
        role="region"
        tabindex="0"
        aria-label="Advisory inventory"
        aria-describedby="findings-order"
      >
        <table class="data-table">
          <thead>
            <tr>
              <th scope="col">CVE</th>
              <th scope="col">Scanner severity</th>
              <th scope="col">Affected in scope</th>
              <th scope="col">Reported fix</th>
              <th scope="col">First seen</th>
              <th scope="col">Teams</th>
            </tr>
          </thead>
          <tbody id="groups" phx-update="stream">
            <tr :for={{id, g} <- @streams.groups} id={id}>
              <th scope="row">
                <.link navigate={detail_path(g.first_occurrence_id, @filters)}>{g.cve}</.link>
                <div class="supporting">
                  <.link navigate={~p"/cves/#{g.cve}"}>All occurrences</.link>
                </div>
                <div class="cluster">
                  <.status_badge :if={g.reopened > 0} label="Reopened" />
                  <.status_badge
                    :if={g.suppressed_occurrences > 0}
                    label={"#{g.suppressed_occurrences} suppressed"}
                    kind="warning"
                  />
                </div>
              </th>
              <td data-field="severity">
                <.status_badge
                  label={Inventory.severity_label(g.severity_rank)}
                  kind="severity"
                />
                <span class="supporting">Highest in group</span>
              </td>
              <td>
                <div data-field="packages">
                  {g.packages} {if g.packages == 1, do: "package", else: "packages"}
                </div>
                <div data-field="images">
                  {g.images} {if g.images == 1, do: "image", else: "images"}
                </div>
                <div data-field="occurrences" class="supporting">
                  {g.occurrences} {if g.occurrences == 1, do: "occurrence", else: "occurrences"}
                </div>
              </td>
              <td data-field="fix">
                <%= if g.fixable > 0 do %>
                  {g.fixable} of {g.occurrences} occurrences
                  <span class="supporting">Not verified fixed</span>
                <% else %>
                  Not reported
                <% end %>
              </td>
              <td><.timestamp value={g.first_seen} /></td>
              <td data-field="teams">{g.teams} {if g.teams == 1, do: "team", else: "teams"}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <nav
        :if={@page_count > 1}
        id="findings-pagination"
        class="cluster"
        aria-label="Advisory list pages"
      >
        <.link
          :if={@page > 1}
          id="findings-page-prev"
          patch={list_path(@filters, @page - 1)}
          class="button button-secondary"
        >
          Previous
        </.link>
        <span id="findings-page-status" class="supporting">
          Page {@page} of {@page_count} · showing {@showing_from}–{@showing_to} of {@advisory_count}
        </span>
        <.link
          :if={@page < @page_count}
          id="findings-page-next"
          patch={list_path(@filters, @page + 1)}
          class="button button-secondary"
        >
          Next
        </.link>
      </nav>
      <p class="supporting">
        A CVE link opens one occurrence, not a representative package or a review of the whole advisory.
        Related occurrences are available on its detail page.
      </p>
    </Layouts.app>
    """
  end
end
