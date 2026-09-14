defmodule TriageWeb.TriageLive do
  @moduledoc """
  Triage: the critical advisories that still need a human, one row per advisory,
  with the per-scope work items underneath.

  Everything this page shows is read-only. Admission and lane rules live in
  `Triage.Triage`, so the page never restates a predicate it does not own: the
  only thing it decides is how the rules are presented.

  "Assessed" here always means a saved human review for that exact
  `(finding, owner, environment)` scope. Opening a case is not an assessment,
  and this page never calls an assessment an approval, a remediation or an
  impact field — applicability is the closest thing the schema has, and it is
  labelled as applicability.
  """

  use TriageWeb, :live_view

  alias Triage.Triage

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Triage")
      |> stream_configure(:cves, dom_id: &"triage-row-#{&1.cve}")

    {:ok, socket}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    requested = params["filter"]

    case Triage.list_critical(filter: requested) do
      {:ok, page} ->
        {:noreply, assign_page(socket, page)}

      {:error, :invalid_filter} ->
        {:noreply, assign_failure(socket, :invalid_filter, requested)}

      {:error, :triage_unavailable} ->
        {:noreply, assign_failure(socket, :triage_unavailable, requested)}
    end
  end

  @impl true
  def handle_event("filter", %{"filter" => value}, socket) do
    case Triage.list_critical(filter: value) do
      {:ok, %{filter: filter}} ->
        target =
          if filter == Triage.default_filter(),
            do: ~p"/triage",
            else: ~p"/triage?#{[filter: filter]}"

        {:noreply, push_patch(socket, to: target)}

      {:error, :invalid_filter} ->
        {:noreply, assign_failure(socket, :invalid_filter, value)}

      {:error, :triage_unavailable} ->
        {:noreply, assign_failure(socket, :triage_unavailable, value)}
    end
  end

  defp assign_page(socket, page) do
    socket
    |> assign(:error, nil)
    |> assign(:invalid_filter, nil)
    |> assign(:filter, page.filter)
    |> assign(:filter_options, filter_options())
    |> assign(:filter_form, to_form(%{"filter" => page.filter}))
    |> assign(:total, page.total)
    |> assign(:truncated?, page.truncated?)
    |> assign(:limit, Triage.row_limit())
    |> assign(:summary, Triage.summarize(page.rows))
    |> assign(:lanes, lanes(page.rows))
    |> assign(:empty?, page.rows == [])
    |> stream(:cves, page.rows, reset: true)
  end

  # An invalid filter and an unavailable read are different failures and are
  # never collapsed into an empty, trustworthy-looking page: nothing is shown
  # and the reason is stated.
  defp assign_failure(socket, kind, requested) do
    socket
    |> assign(:error, kind)
    |> assign(:invalid_filter, if(kind == :invalid_filter, do: inspect(requested)))
    |> assign(:filter, nil)
    |> assign(:filter_options, filter_options())
    |> assign(:filter_form, to_form(%{"filter" => nil}))
    |> assign(:total, 0)
    |> assign(:truncated?, false)
    |> assign(:limit, Triage.row_limit())
    |> assign(:summary, Triage.summarize([]))
    |> assign(:lanes, [])
    |> assign(:empty?, true)
    |> stream(:cves, [], reset: true)
  end

  defp filter_options do
    [
      {"Active — needs a human", "active"},
      {"Handled — reviewed, no impact recorded", "handled"},
      {"All critical advisories", "all"}
    ]
  end

  # One section per non-empty lane, most urgent first. The lanes are the same
  # three states the read model publishes, so a row can never be in two lanes
  # or in none of them.
  defp lanes(rows) do
    [
      %{
        id: "triage-lane-impact",
        title: "Impact confirmed by a human",
        note:
          "A saved review on at least one active scope records applicability = affected. This schema has no impact field; applicability is what a human wrote, and a scope it was not written for stays unjudged.",
        rows: Enum.filter(rows, &(&1.state == :impact_confirmed))
      },
      %{
        id: "triage-lane-intake",
        title: "Awaiting assessment",
        note:
          "Critical and active, with no saved human review yet. This lane exists because a case can only be opened from a finding, so a list of already-assessed advisories could never admit its first row.",
        rows: Enum.filter(rows, &(&1.state == :awaiting_assessment))
      },
      %{
        id: "triage-lane-handled",
        title: "Reviewed · no impact recorded",
        note: "Every active scope has a current human review and none of them says affected.",
        rows: Enum.filter(rows, &(&1.state == :assessed_no_impact))
      }
    ]
    |> Enum.reject(&(&1.rows == []))
  end

  defp state_label(:impact_confirmed), do: "applicability: affected"
  defp state_label(:awaiting_assessment), do: "Not assessed"
  defp state_label(:assessed_no_impact), do: "Not affected"

  defp state_kind(:impact_confirmed), do: :severity
  defp state_kind(:awaiting_assessment), do: :warning
  defp state_kind(_state), do: :neutral

  defp item_label(:assessed), do: "Assessed"
  defp item_label(:assessment_superseded), do: "Assessment on earlier evidence"
  defp item_label(:awaiting_assessment), do: "Not assessed"

  defp item_kind(:assessed), do: :neutral
  defp item_kind(_assessment), do: :warning

  defp coverage_label(%{scopes_assessed: assessed, scopes_total: total}) do
    "#{assessed} of #{total} #{if total == 1, do: "scope", else: "scopes"} assessed"
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="triage">
      <.page_header
        title="Triage"
        subtitle="Critical advisories that still need a human, and what a human has already recorded for each scope."
      />

      <p id="triage-banner" class="supporting">
        Critical and active only: unresolved, unsuppressed, with an active placement.
        “Assessed” means a saved human review for that exact team and environment scope —
        opening a case is not an assessment, and this page writes nothing.
      </p>

      <.form id="triage-filter-form" for={@filter_form} phx-change="filter" class="filter-toolbar">
        <.input
          field={@filter_form[:filter]}
          type="select"
          label="Show"
          options={@filter_options}
          aria-describedby="triage-summary"
        />
      </.form>

      <.notice :if={@invalid_filter} id="triage-invalid-filter" kind="error" role="alert">
        Invalid filter {@invalid_filter} — no advisories were loaded. The filter must be
        one of the values this page offers; it is never assumed or swapped for a default.
      </.notice>

      <.notice :if={@error == :triage_unavailable} id="triage-unavailable" kind="error" role="alert">
        The triage read failed, so no advisories are shown. An empty page here is never
        a report that nothing needs attention.
      </.notice>

      <dl :if={is_nil(@error)} class="metric-strip metric-strip-compact" aria-label="Triage totals">
        <div>
          <dt>Critical in this filter</dt>
          <dd id="triage-cve-count">{@total}</dd>
        </div>
        <div>
          <dt>Impact confirmed</dt>
          <dd id="triage-impact-count">{@summary.impact_confirmed}</dd>
        </div>
        <div>
          <dt>Awaiting assessment</dt>
          <dd id="triage-intake-count">{@summary.awaiting_assessment}</dd>
        </div>
        <div>
          <dt>Scopes assessed</dt>
          <dd id="triage-scope-count">{@summary.scopes_assessed} of {@summary.scopes_total}</dd>
        </div>
      </dl>

      <p :if={is_nil(@error)} id="triage-summary" class="filter-summary" role="status">
        Showing {length(@lanes)} lanes · {length(List.flatten(Enum.map(@lanes, & &1.rows)))} advisories ·
        filter: {if @filter == "handled",
          do: "handled",
          else: if(@filter == "all", do: "all critical", else: "active")}
      </p>

      <p :if={@truncated?} id="triage-truncated" class="notice">
        This page is capped at {@limit} advisories and the filter matches more than that,
        so it shows the most recently observed {@limit}. The total above is the unpaged count.
      </p>

      <.empty_state
        :if={@empty? and is_nil(@error)}
        id="triage-empty"
        title="No critical advisories in this filter"
        description="An empty result is not proof of a clean estate: it means no critical, unresolved, unsuppressed finding with an active placement matches, in local inventory only."
      />

      <section
        :for={lane <- @lanes}
        id={lane.id}
        class="triage-lane"
        aria-labelledby={"#{lane.id}-title"}
      >
        <h2 id={"#{lane.id}-title"}>{lane.title} · {length(lane.rows)}</h2>
        <p class="supporting">{lane.note}</p>

        <div class="table-region" role="region" tabindex="0" aria-label={lane.title}>
          <table class="data-table">
            <thead>
              <tr>
                <th scope="col">Advisory</th>
                <th scope="col">Affected in active scopes</th>
                <th scope="col">Human coverage</th>
                <th scope="col">Assessment state</th>
                <th scope="col">Last observed</th>
                <th scope="col">Work items</th>
              </tr>
            </thead>
            <tbody id={"#{lane.id}-rows"} phx-update="stream">
              <tr :for={{id, row} <- @streams.cves} id={id}>
                <th scope="row">
                  <strong>{row.cve}</strong>
                  <div class="cluster">
                    <.status_badge label={row.severity} kind="severity" />
                    <.status_badge
                      :if={row.reopened > 0}
                      label={"reopened #{row.reopened}"}
                      kind="warning"
                    />
                  </div>
                  <div class="supporting">
                    <.link navigate={~p"/cves/#{row.cve}"}>Deep dive</.link>
                  </div>
                </th>
                <td>
                  <div>{row.packages} {if row.packages == 1, do: "package", else: "packages"}</div>
                  <div class="supporting">
                    {row.images} {if row.images == 1, do: "image", else: "images"} · {row.occurrences} {if row.occurrences ==
                                                                                                             1,
                                                                                                           do:
                                                                                                             "occurrence",
                                                                                                           else:
                                                                                                             "occurrences"}
                  </div>
                  <div class="supporting">
                    {row.teams} {if row.teams == 1, do: "team", else: "teams"}
                  </div>
                </td>
                <td>
                  <div id={"triage-coverage-#{row.cve}"}>{coverage_label(row)}</div>
                  <div :if={row.scopes_reviewed > row.scopes_assessed} class="supporting">
                    {row.scopes_reviewed - row.scopes_assessed} recorded on earlier evidence
                  </div>
                  <div class="supporting">
                    {row.scopes_impacted} {if row.scopes_impacted == 1,
                      do: "scope says affected",
                      else: "scopes say affected"}
                  </div>
                </td>
                <td>
                  <span id={"triage-state-#{row.cve}"}>
                    <.status_badge label={state_label(row.state)} kind={state_kind(row.state)} />
                  </span>
                </td>
                <td><.timestamp value={row.last_seen} /></td>
                <td>
                  <details id={"triage-scopes-#{row.cve}"}>
                    <summary>
                      {row.scopes_total} {if row.scopes_total == 1, do: "scope", else: "scopes"}
                    </summary>
                    <ul class="triage-scope-list">
                      <li
                        :for={item <- row.work_items}
                        id={"triage-scope-#{row.cve}-#{item.owner}-#{item.environment}-#{item.finding_id}"}
                      >
                        <div>
                          <strong>{item.owner}</strong> · <span>{item.environment}</span>
                        </div>
                        <div class="supporting">
                          {item.package_name} <code>{item.package_version}</code>
                          · {item.image_repository}:{item.image_tag}
                        </div>
                        <div class="cluster">
                          <.status_badge
                            label={item_label(item.assessment)}
                            kind={item_kind(item.assessment)}
                          />
                          <.status_badge
                            :if={item.applicability}
                            label={"applicability: #{item.applicability}"}
                          />
                          <.status_badge :if={item.priority} label={item.priority} />
                          <.status_badge :if={item.next_action} label={item.next_action} />
                        </div>
                        <div :if={item.reviewed_at} class="supporting">
                          Assessed <.timestamp value={item.reviewed_at} />
                        </div>
                        <div class="cluster">
                          <.link
                            :if={item.case_id}
                            id={"triage-case-#{item.finding_id}"}
                            navigate={~p"/cases/#{item.case_id}"}
                            class="button button-secondary"
                          >Review case</.link>
                          <.link
                            :if={is_nil(item.case_id)}
                            id={"triage-open-#{item.finding_id}"}
                            navigate={~p"/findings/#{item.finding_id}"}
                            class="button button-secondary"
                          >Open case</.link>
                        </div>
                      </li>
                    </ul>
                  </details>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <details id="triage-legend" class="disclosure">
        <summary>What the states mean</summary>
        <p>
          A scope is <strong>assessed</strong> when its latest saved review is bound to the
          case's current evidence snapshot. A review recorded before a later recapture is shown
          as <em>assessment on earlier evidence</em> and never counted as current — the case page
          decides which of the two it is from the canonical hash.
        </p>
        <p>
          Applicability is the only judgement a human can record here, and it is not an impact
          field. Nothing on this page suppresses a finding, approves an exception or verifies a
          fix; a review is local-operator history.
        </p>
      </details>
    </Layouts.app>
    """
  end
end
