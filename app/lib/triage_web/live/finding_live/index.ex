defmodule TriageWeb.FindingLive.Index do
  @moduledoc """
  CVE inventory grouped by advisory, with URL-restorable team/environment filters.

  Synthetic demo data only (PR 1). Team filtering scopes what is displayed; it is
  not authentication or authorization, and this unauthenticated demo must stay on
  loopback until real identity and roles land.
  """

  use TriageWeb, :live_view

  alias Triage.Inventory
  alias Triage.Inventory.GroupCursor
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

    scope_opts = [
      owner: parsed.owner,
      environment: parsed.environment,
      include_suppressed: parsed.include_suppressed,
      search: parsed.q,
      severity: parsed.severity
    ]

    # One row beyond the page says whether an older slice exists. The position
    # kept for that slice is the last row actually shown, so the next page
    # continues exactly after it and can neither repeat nor skip a group.
    {groups, total, has_more?, next_before} =
      if invalid or unknown_team? do
        {[], 0, false, nil}
      else
        total = Inventory.count_groups(scope_opts)

        rows =
          Inventory.list_groups(
            scope_opts ++ [sort: sort, limit: @per_page + 1, before: parsed.before]
          )

        has_more? = length(rows) > @per_page
        groups = Enum.take(rows, @per_page)

        next_before = if has_more?, do: position(sort, List.last(groups))

        {groups, total, has_more?, next_before}
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
         before: parsed.before
       }
     )
     |> assign(:invalid_filters, if(invalid, do: parsed.invalid, else: []))
     |> assign(:unknown_team?, unknown_team?)
     |> assign(:teams, Inventory.teams())
     |> assign(:environments, Inventory.environments())
     |> assign(:counts, Inventory.summary_counts())
     |> assign(:advisory_count, total)
     |> assign(:shown, length(groups))
     |> assign(:per_page, @per_page)
     |> assign(:has_more?, has_more?)
     |> assign(:cursor, parsed.before)
     |> assign(:next_before, next_before)
     |> assign(:beyond_end?, groups == [] and total > 0)
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
       |> assign(:shown, 0)
       |> assign(:has_more?, false)
       |> assign(:cursor, nil)
       |> assign(:next_before, nil)
       |> assign(:beyond_end?, false)
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

  # The position of one row: its own cursor, parsed back so only a value this
  # contract accepts is ever carried into a link.
  defp position(sort, row) do
    {:ok, cursor} = GroupCursor.parse(sort, GroupCursor.encode(sort, row))
    cursor
  end

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

  # The canonical list query. The default order and the newest slice stay out of
  # the URL so a shared link keeps its shortest form; both are still applied.
  #
  # `position` selects the slice: `nil` keeps the one these filters are already
  # on, so a detail link returns to the same place in the list; `:start` drops
  # the position for the newest slice; and a parsed position moves to the slice
  # that continues after it.
  defp list_query(filters, position) do
    sort = filters[:sort] || default_sort()

    before =
      case position do
        :start -> nil
        nil -> filters[:before]
        cursor -> cursor
      end

    FindingFilters.query_params(%{
      owner: filters[:owner],
      environment: filters[:environment],
      q: filters[:search],
      include_suppressed: filters[:include_suppressed],
      severity: filters[:severity],
      sort: if(sort == default_sort(), do: nil, else: sort),
      before: before
    })
  end

  defp list_path(filters, position) do
    case list_query(filters, position) do
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
        Filters accept plain text of at most 120 characters without control characters; the order
        must be one of the listed choices, and a position must be one this list itself issued.
        A position is never guessed. Correct the filters or reset to recover.
      </p>
      <p :if={@unknown_team?} id="unknown-team" class="notice">
        Unknown team — showing no findings. Team filters are not authorization boundaries.
      </p>
      <p :if={@beyond_end?} id="findings-beyond-end" class="notice">
        This position is past the end of the list these filters now select, so no advisories are
        shown. A position belongs to the filters and order it was issued with.
        <.link patch={list_path(@filters, :start)}>Start from the newest slice</.link>
      </p>
      <p id="findings-order" class="supporting">
        {@order_note} Counts in each row use the selected scope and active placements; teams can overlap. One page shows at most {@per_page} advisory groups in this order; the matching total is the unpaged count for this scope.
      </p>

      <div
        :if={@empty? and @invalid_filters == [] and not @beyond_end?}
        id="findings-empty"
        class="empty-state"
      >
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
        :if={@has_more? or @cursor}
        id="findings-pagination"
        class="cluster"
        aria-label="Advisory list position"
      >
        <.link
          :if={@has_more?}
          id="older-advisories"
          patch={list_path(@filters, @next_before)}
          class="button button-secondary"
        >
          Older advisories
        </.link>
        <span id="findings-page-status" class="supporting">
          {@shown} of {@advisory_count} matching advisories · {@per_page} per page · {if @cursor,
            do: "later slice of this order",
            else: "newest slice of this order"}
        </span>
        <.link
          :if={@cursor}
          id="newest-advisories"
          patch={list_path(@filters, :start)}
          class="button button-secondary"
        >
          Newest advisories
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
