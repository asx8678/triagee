defmodule TriageWeb.TriageLive do
  @moduledoc """
  Triage: the critical advisories that still need a human, one row per advisory,
  with the per-scope work items underneath.

  Admission and lane rules live in `Triage.Triage`, so the page never restates a
  predicate it does not own: the only thing it decides is how the rules are
  presented.

  The page reads the work list and can record one thing: an operator decision
  (`accepted_risk`, `not_affected` or `mitigated`, via `Triage.Decisions`). That
  is the only write here. It never touches a finding, never saves a review and
  never suppresses anything, so an advisory that leaves this list by decision is
  still in Findings, still on its CVE page and still unexplained by any review.

  "Assessed" here always means a saved human review for that exact
  `(finding, owner, environment)` scope. Opening a case is not an assessment.
  Applicability is the closest judgement field the schema has and is labelled as
  applicability; real impact is shown only as operator-declared impact
  evidence, with its source and observation time.
  """

  use TriageWeb, :live_view

  alias Triage.{Decisions, Triage}

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Triage")
      |> assign(:decision_options, decision_options())
      |> assign(:decision_form, decision_form(%{}))
      |> assign(:decision_errors, [])

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

  # The only write on this page. Failures are shown in place and never silently
  # dropped: a refused decision must not look like a recorded one.
  @impl true
  def handle_event("record_decision", %{"record" => params}, socket) do
    attrs = %{
      cve: params["cve"],
      decision: params["decision"],
      reason: params["reason"],
      actor: params["actor"],
      decided_at: DateTime.utc_now()
    }

    case parse_last_covered_day(params["expires_on"]) do
      {:ok, expires_at} ->
        case Decisions.record(Map.put(attrs, :expires_at, expires_at)) do
          {:ok, decision} ->
            {:noreply,
             socket
             |> put_flash(
               :info,
               "#{Decisions.label(decision.decision)} recorded for #{decision.cve} — it left the active work list; the “Covered by a decision” filter explains it."
             )
             |> assign(:decision_form, decision_form(%{}))
             |> assign(:decision_errors, [])
             |> reload()}

          {:error, %Ecto.Changeset{} = changeset} ->
            {:noreply, assign(socket, :decision_errors, form_errors(changeset))}

          {:error, :unknown_cve} ->
            {:noreply,
             assign(socket, :decision_errors, [
               "cve: no finding in this inventory carries that CVE, so no decision was recorded"
             ])}

          {:error, _other} ->
            {:noreply, assign(socket, :decision_errors, ["The decision was refused."])}
        end

      {:error, message} ->
        {:noreply, assign(socket, :decision_errors, [message])}
    end
  end

  defp reload(socket) do
    case Triage.list_critical(filter: socket.assigns.filter) do
      {:ok, page} ->
        assign_page(socket, page)

      {:error, :invalid_filter} ->
        assign_failure(socket, :invalid_filter, socket.assigns.filter)

      {:error, :triage_unavailable} ->
        assign_failure(socket, :triage_unavailable, socket.assigns.filter)
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
    |> assign(:shown_total, length(page.rows))
    |> assign(:empty?, page.rows == [])
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
    |> assign(:shown_total, 0)
    |> assign(:empty?, true)
  end

  defp filter_options do
    [
      {"Active — needs a human", "active"},
      {"Covered by a decision", "whitelisted"},
      {"Handled — reviewed, nothing says affected", "handled"},
      {"All critical advisories", "all"}
    ]
  end

  defp decision_options do
    Enum.map(Decisions.decisions(), &{Decisions.label(&1), &1})
  end

  defp decision_form(params) do
    params
    |> Map.take(["cve", "decision", "reason", "actor", "expires_on"])
    |> Map.put_new("decision", "accepted_risk")
    |> Map.put_new("actor", "local-operator")
    |> to_form(as: :record)
  end

  # A date means the last day the decision covers: it stops covering the next
  # day, so `2026-12-31` covers all of the 31st and nothing of January 1st.
  defp parse_last_covered_day(nil), do: {:ok, nil}
  defp parse_last_covered_day(""), do: {:ok, nil}

  defp parse_last_covered_day(value) when is_binary(value) do
    case Date.from_iso8601(String.trim(value)) do
      {:ok, date} ->
        {:ok, DateTime.new!(Date.add(date, 1), ~T[00:00:00], "Etc/UTC")}

      {:error, _} ->
        {:error,
         "expires_on: use a date like 2026-12-31 — the last day the decision covers. Nothing was recorded."}
    end
  end

  defp parse_last_covered_day(_other),
    do: {:error, "expires_on: use a date like 2026-12-31. Nothing was recorded."}

  defp form_errors(changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, opts} ->
      Regex.replace(~r/%{(\w+)}/, message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.flat_map(fn {field, messages} -> Enum.map(messages, &"#{field} #{&1}") end)
  end

  # One section per non-empty lane, most urgent first. The lanes are the same
  # four states the read model publishes, so a row can never be in two lanes or
  # in none of them.
  defp lanes(rows) do
    [
      %{
        id: "triage-lane-applicability",
        title: "Applicability confirmed by a human",
        note: "A saved review on at least one active scope records applicability = affected.",
        detail:
          "That is the judgement a human wrote, not an impact assessment: a schema without an impact field cannot be told what impact was.",
        rows: Enum.filter(rows, &(&1.state == :applicability_confirmed))
      },
      %{
        id: "triage-lane-intake",
        title: "Awaiting assessment",
        note: "Critical and active, with no saved human review yet.",
        detail:
          "This lane exists because a case can only be opened from a finding, so a list of already-assessed advisories could never admit its first row.",
        rows: Enum.filter(rows, &(&1.state == :awaiting_assessment))
      },
      %{
        id: "triage-lane-decision",
        title: "Covered by an operator decision",
        note: "An active decision removes these advisories from the work list.",
        detail:
          "A decision is not resolution: the finding keeps its severity and its lifecycle events, and the CVE page keeps the full append-only history.",
        rows: Enum.filter(rows, &(&1.state == :decision_recorded))
      },
      %{
        id: "triage-lane-handled",
        title: "Reviewed · nothing says affected",
        note: "Every active scope has a current human review and none of them says affected.",
        detail: nil,
        rows: Enum.filter(rows, &(&1.state == :assessed_no_impact))
      }
    ]
    |> Enum.reject(&(&1.rows == []))
  end

  # count_label/2 (imported from TriageWeb.UIComponents) is shared with Findings,
  # so the same phrase is never spelled two ways on two pages.
  defp filter_label("handled"), do: "handled"
  defp filter_label("whitelisted"), do: "covered by a decision"
  defp filter_label("all"), do: "all critical"
  defp filter_label(_other), do: "active"

  defp state_label(:applicability_confirmed), do: "applicability: affected"
  defp state_label(:awaiting_assessment), do: "Not assessed"
  defp state_label(:decision_recorded), do: "Covered by a decision"
  defp state_label(:assessed_no_impact), do: "Not affected"

  defp state_kind(:applicability_confirmed), do: :severity
  defp state_kind(:awaiting_assessment), do: :state
  defp state_kind(_state), do: :neutral

  defp decision_state_label(:active), do: "active"
  defp decision_state_label(:expired), do: "expired — back in the work list"

  defp item_label(:assessed), do: "Assessed"
  defp item_label(:assessment_superseded), do: "Assessment on earlier evidence"
  defp item_label(:awaiting_assessment), do: "Not assessed"

  defp item_kind(:assessed), do: :neutral
  defp item_kind(_assessment), do: :state

  defp coverage_label(%{scopes_assessed: assessed, scopes_total: total}) do
    "#{assessed} of #{total} #{if total == 1, do: "scope", else: "scopes"} assessed"
  end

  defp impact_label(%{state: :active} = impact), do: "impact: #{impact.label}"
  defp impact_label(%{state: :expired}), do: "impact evidence expired"

  defp impact_kind(%{state: :active}), do: :neutral
  defp impact_kind(_impact), do: :state

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="triage">
      <.page_header
        title="Triage"
        subtitle="Critical advisories that still need a human, what a human has already recorded for each scope, and which operator decisions cover them."
      />

      <p id="triage-banner" class="supporting">
        Critical and active only: unresolved, unsuppressed, with an active placement.
      </p>

      <details id="triage-banner-details" class="disclosure">
        <summary>How assessment and decisions affect this list</summary>
        <p>
          “Assessed” means a saved human review for that exact team and environment scope —
          opening a case is not an assessment. This page writes exactly one thing: an operator
          decision, which removes an advisory from this list without changing the finding.
        </p>
      </details>

      <.filter_bar id="triage-filter-form" form={@filter_form} change="filter">
        <.input
          field={@filter_form[:filter]}
          type="select"
          label="Show"
          options={@filter_options}
          aria-describedby="triage-summary"
        />
        <:summary>
          <p :if={is_nil(@error)} id="triage-summary" class="filter-summary" role="status">
            <strong>
              {@shown_total} {if @shown_total == 1, do: "advisory", else: "advisories"} shown
            </strong>
            <span>· {length(@lanes)} {if length(@lanes) == 1, do: "lane", else: "lanes"}</span>
            <span>· filter: {filter_label(@filter)}</span>
          </p>
        </:summary>
      </.filter_bar>

      <.notice :if={@invalid_filter} id="triage-invalid-filter" kind="error" role="alert">
        Invalid filter {@invalid_filter} — no advisories were loaded. The filter must be
        one of the values this page offers; it is never assumed or swapped for a default.
      </.notice>

      <.notice :if={@error == :triage_unavailable} id="triage-unavailable" kind="error" role="alert">
        The triage read failed, so no advisories are shown. An empty page here is never
        a report that nothing needs attention.
      </.notice>

      <dl
        :if={is_nil(@error)}
        class="metric-strip metric-strip-compact"
        aria-label="Shown advisories by assessment state"
      >
        <div>
          <dt>Awaiting assessment</dt>
          <dd id="triage-intake-count">{@summary.awaiting_assessment}</dd>
        </div>
        <div>
          <dt>Applicability confirmed</dt>
          <dd id="triage-applicability-count">{@summary.applicability_confirmed}</dd>
        </div>
        <div>
          <dt>Covered by a decision</dt>
          <dd id="triage-decision-count">{@summary.decision_recorded}</dd>
        </div>
        <div>
          <dt>Scopes assessed</dt>
          <dd id="triage-scope-count">{@summary.scopes_assessed} of {@summary.scopes_total}</dd>
        </div>
        <div>
          <dt>Scopes with impact evidence</dt>
          <dd id="triage-impact-count">{@summary.scopes_with_impact}</dd>
        </div>
      </dl>

      <p :if={is_nil(@error)} id="triage-counts-note" class="supporting">
        Every count above describes only the {@shown_total} shown {if @shown_total == 1,
          do: "advisory",
          else: "advisories"} and the lanes below.
        Local inventory holds <strong id="triage-cve-count">{@total}</strong>
        critical {if @total == 1, do: "advisory", else: "advisories"} in total: an unpaged
        count this filter does not narrow.
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
        <.explain :if={lane.detail} id={"#{lane.id}-note"} summary={lane.note}>
          <p>{lane.detail}</p>
        </.explain>
        <p :if={is_nil(lane.detail)} class="supporting">{lane.note}</p>

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
            <tbody id={"#{lane.id}-rows"}>
              <tr :for={row <- lane.rows} id={"triage-row-#{row.cve}"}>
                <th scope="row">
                  <%!-- The CVE id is itself the link to its detail page. A second
                       "Deep dive" link beside it pointed at the same route, so it
                       named a destination that was already named. --%>
                  <.link
                    id={"triage-cve-#{row.cve}"}
                    navigate={~p"/cves/#{row.cve}"}
                    class="triage-cve"
                  >{row.cve}</.link>
                  <div class="cluster">
                    <.status_badge label={row.severity} kind="severity" />
                    <.status_badge
                      :if={row.reopened > 0}
                      label={"reopened #{row.reopened}"}
                      kind="warning"
                    />
                  </div>
                </th>
                <td>
                  <div data-field="packages">{count_label(row.packages, "package")}</div>
                  <div class="supporting">
                    <span data-field="images">{count_label(row.images, "image")}</span>
                    ·
                    <span data-field="occurrences">
                      {count_label(row.occurrences, "occurrence")}
                    </span>
                    · <span data-field="teams">{count_label(row.teams, "team")}</span>
                  </div>
                </td>
                <td>
                  <div id={"triage-coverage-#{row.cve}"}>{coverage_label(row)}</div>
                  <div :if={row.scopes_reviewed > row.scopes_assessed} class="supporting">
                    {row.scopes_reviewed - row.scopes_assessed} recorded on earlier evidence
                  </div>
                  <div class="supporting">
                    <span data-field="applicable">
                      {row.scopes_applicable} {if row.scopes_applicable == 1,
                        do: "scope says affected",
                        else: "scopes say affected"}
                    </span>
                    <span :if={row.scopes_with_impact > 0}>
                      ·
                      <span data-field="impact">
                        {row.scopes_with_impact} {if row.scopes_with_impact == 1,
                          do: "scope has impact evidence",
                          else: "scopes have impact evidence"}
                      </span>
                    </span>
                  </div>
                </td>
                <td>
                  <span id={"triage-state-#{row.cve}"}>
                    <.status_badge label={state_label(row.state)} kind={state_kind(row.state)} />
                  </span>
                  <div :if={row.decision} id={"triage-decision-#{row.cve}"} class="supporting">
                    <strong>{row.decision.label}</strong>
                    · {decision_state_label(row.decision.state)} ·
                    by {row.decision.actor}
                    <div :if={row.decision.expires_at}>
                      {if row.decision.state == :active, do: "covers until", else: "expired on"}
                      <.timestamp value={row.decision.expires_at} />
                    </div>
                    <div>{row.decision.reason}</div>
                  </div>
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
                        <div :if={item.impact} id={"triage-impact-#{item.finding_id}"} class="cluster">
                          <.status_badge
                            label={impact_label(item.impact)}
                            kind={impact_kind(item.impact)}
                          />
                          <span class="supporting">
                            {item.impact.source} · observed
                            <.timestamp value={item.impact.observed_at} />
                          </span>
                        </div>
                        <div :if={is_nil(item.impact)} class="supporting">
                          Impact not recorded for this placement.
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

      <details id="triage-decision-panel" class="disclosure">
        <summary>Record a decision — accepted risk, not affected, or mitigated</summary>
        <p class="supporting">
          A decision takes an advisory out of the work list above. It is <strong>not</strong>
          resolution: the finding keeps its severity, its lifecycle events and its place in
          Findings, no review is written, and the advisory comes back when the decision
          expires. An accepted risk must carry an end date, because an acceptance without one
          is forever.
        </p>
        <.form
          id="triage-decision-form"
          for={@decision_form}
          phx-submit="record_decision"
          class="stack"
        >
          <.input field={@decision_form[:cve]} type="text" label="CVE" placeholder="CVE-2026-12345" />
          <.input
            field={@decision_form[:decision]}
            type="select"
            label="Decision"
            options={@decision_options}
          />
          <.input field={@decision_form[:reason]} type="textarea" label="Reason (kept as history)" />
          <.input
            field={@decision_form[:expires_on]}
            type="text"
            label="Last covered day (YYYY-MM-DD)"
            placeholder="2026-12-31"
          />
          <.input field={@decision_form[:actor]} type="text" label="Actor" />
          <button type="submit" id="triage-decision-submit" class="button">Record decision</button>
        </.form>
        <ul :if={@decision_errors != []} id="triage-decision-errors" class="notice" role="alert">
          <li :for={error <- @decision_errors}>{error}</li>
        </ul>
      </details>

      <details id="triage-legend" class="disclosure">
        <summary>What the states mean</summary>
        <p>
          A scope is <strong>assessed</strong> when its latest saved review is bound to the
          case's current evidence snapshot. A review recorded before a later recapture is shown
          as <em>assessment on earlier evidence</em> and never counted as current — the case page
          decides which of the two it is from the canonical hash.
        </p>
        <p>
          Applicability is a judgement a human records. Impact is separate and only ever an
          operator-declared evidence row with a source; when there is none, this page says
          "impact not recorded" rather than guessing from severity, exposure or namespace.
        </p>
        <p>
          A decision is the one thing this page can write, and it removes the advisory from
          these lanes only. Nothing here suppresses a finding, approves an exception in the
          inventory or verifies a fix.
        </p>
      </details>
    </Layouts.app>
    """
  end
end
