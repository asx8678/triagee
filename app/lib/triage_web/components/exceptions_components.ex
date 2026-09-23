defmodule TriageWeb.ExceptionsComponents do
  @moduledoc "Compact, read-only risk decision history with exact deployment records preserved."
  use TriageWeb, :html
  alias Triage.RiskDecisionHistory
  alias TriageWeb.WorkspaceLive, as: Routes

  attr :decisions, :list, required: true
  attr :params, :map, required: true

  def exceptions_register(assigns) do
    history = RiskDecisionHistory.build(assigns.decisions, assigns.params)

    assigns =
      assign(assigns, history: history, filter_form: to_form(history.filters, as: :risk_filters))

    ~H"""
    <section class="risk-decisions" id="exceptions-register" aria-labelledby="exceptions-title">
      <header class="risk-decisions-header">
        <div>
          <h1 id="exceptions-title">Risk decisions</h1>
          <p>Temporary exceptions, review dates and the people behind them.</p>
        </div>
        <.link
          class="risk-review-link"
          id="risk-decisions-open-review"
          patch={Routes.nav_path(@params, "findings")}
        >Back to Review <span aria-hidden="true">↗</span></.link>
      </header>

      <nav class="risk-metrics" aria-label="Filter by expiry status">
        <.link
          :for={
            {key, label, hint} <- [
              {"all", "All decisions", "Recorded in the last 365 days"},
              {"valid", "Not expired", "Including upcoming expiries"},
              {"expiring", "Expiring soon", "Within the next 7 days"},
              {"expired", "Expired", "Check the latest CVE status"}
            ]
          }
          id={"risk-status-#{key}"}
          class={[
            "risk-metric",
            "risk-metric-#{key}",
            @history.filters["risk_status"] == key && "is-selected"
          ]}
          aria-current={if @history.filters["risk_status"] == key, do: "true"}
          patch={history_path(@params, %{"risk_status" => key, "risk_page" => nil})}
        >
          <span class="risk-metric-label"><span class="risk-dot" aria-hidden="true"></span>{label}</span>
          <strong>{@history.counts[key]}</strong><span class="risk-metric-hint">{hint}</span>
        </.link>
      </nav>

      <div class="risk-register-panel">
        <.form
          for={@filter_form}
          id="risk-decision-filters"
          phx-change="risk-filter"
          phx-submit="risk-filter"
          class="risk-filterbar"
        >
          <.input
            field={@filter_form[:risk_q]}
            type="search"
            label="Search decisions"
            placeholder="CVE, reason, reviewer…"
            phx-debounce="250"
          />
          <.input
            field={@filter_form[:risk_team]}
            type="select"
            label="Team"
            options={filter_options(@history.teams, @history.filters["risk_team"], "All teams")}
          />
          <.input
            field={@filter_form[:risk_environment]}
            type="select"
            label="Environment"
            options={
              filter_options(
                @history.environments,
                @history.filters["risk_environment"],
                "All environments"
              )
            }
          />
          <.link
            :if={@history.filtered?}
            id="risk-clear-filters"
            class="risk-clear"
            patch={history_path(Map.drop(@params, RiskDecisionHistory.filter_keys()), %{})}
          >Clear filters</.link>
        </.form>
        <div class="risk-list-meta">
          <span id="exceptions-count" role="status"><strong>{@history.total}</strong> {if @history.total ==
                                                                                            1,
                                                                                          do:
                                                                                            "decision",
                                                                                          else:
                                                                                            "decisions"}
          <span>· {@history.records} underlying records</span></span>
          <span>Newest first · dates in UTC</span>
        </div>

        <ul
          :if={@history.rows != []}
          id="risk-decision-list"
          class="risk-decision-list"
          aria-label="Recorded risk decisions"
        >
          <li
            :for={d <- @history.rows}
            id={"exception-#{d.id}"}
            class={"risk-entry risk-entry-#{d.status}"}
          >
            <div class="risk-entry-main">
              <div class="risk-entry-identity">
                <div class="risk-entry-title">
                  <.link class="risk-cve-link" patch={review_path(@history.filters, d.cve)}>{d.cve}</.link>
                  <span class="risk-action-tag">{action_label(d.decision)}</span>
                </div>
                <p class="risk-reason-preview">{reason(d)}</p>
              </div>
              <div class="risk-entry-scope">
                <span class="risk-field-label">Scope</span>
                <strong>{scope_count(d)}</strong>
                <span class="risk-team-label">{if d.teams == [],
                  do: "Team not recorded",
                  else: Enum.join(d.teams, ", ")}</span>
                <div class="risk-environments">
                  <span
                    :for={environment <- d.environments}
                    class={"risk-environment #{if environment == "prod", do: "is-prod"}"}
                  >{environment}</span>
                </div>
              </div>
              <div class="risk-entry-expiry">
                <span class={"risk-status risk-status-#{d.status}"}><span
                  class="risk-dot"
                  aria-hidden="true"
                ></span>{d.status_label}</span>
                <time
                  :if={d.expires_at}
                  datetime={DateTime.to_iso8601(d.expires_at)}
                  title={full_time(d.expires_at)}
                >{date(d.expires_at)}</time>
                <span class="risk-expiry-relative">{d.relative_expiry}</span>
              </div>
              <div class="risk-entry-reviewer">
                <span class="risk-field-label">Decided by</span>
                <strong>{if d.actor == "", do: "Not recorded", else: d.actor}</strong>
                <span>{date(d.decided_at)}</span>
              </div>
              <.link
                id={"risk-review-#{d.id}"}
                class="risk-row-review"
                aria-label={"Review #{d.cve}"}
                patch={review_path(@history.filters, d.cve)}
              >Review <span aria-hidden="true">↗</span></.link>
            </div>
            <details id={"risk-details-#{d.id}"} class="risk-record-details">
              <summary>
                Reason &amp; deployment details
                <span>{length(d.records)} {if length(d.records) == 1, do: "record", else: "records"}</span>
              </summary>
              <div class="risk-details-body">
                <div>
                  <h3>Recorded reason</h3><p class="risk-full-reason">{reason(d)}</p>
                  <dl class="risk-audit-dates">
                    <dt>Decided at</dt><dd>{full_time(d.decided_at)} UTC</dd>
                    <dt>Expires at</dt><dd>
                      {if d.expires_at,
                        do: full_time(d.expires_at) <> " UTC",
                        else: "No expiry recorded"}
                    </dd>
                  </dl>
                  <p class="risk-record-note">{expiry_help(hd(d.records))}</p>
                </div>
                <div>
                  <h3>Exact recorded scope</h3>
                  <ul class="risk-scope-details">
                    <li :for={scope <- d.scopes} id={"risk-record-#{scope.record_id}"}>
                      <strong>{if is_nil(scope.placement_id),
                        do: "All deployments for this CVE · legacy record",
                        else: "Deployment ##{scope.placement_id}"}</strong>
                      <span :if={not is_nil(scope.placement_id)}>{if scope.team == "",
                        do: "Unknown team",
                        else: scope.team} · {if scope.environment == "",
                        do: "Unknown environment",
                        else: scope.environment}</span>
                      <span :if={scope.namespace != ""}>{scope.namespace}</span>
                      <small>Record #{scope.record_id}<span :if={scope.supersedes_id}> · replaces record #{scope.supersedes_id}</span></small>
                    </li>
                  </ul>
                </div>
              </div>
            </details>
          </li>
        </ul>

        <div :if={@history.rows == []} id="exceptions-empty" class="risk-empty">
          <h2>
            {if @history.empty?, do: "No risk decisions yet", else: "No decisions match these filters"}
          </h2>
          <p>
            {if @history.empty?,
              do: "Decisions recorded in Review will appear here with their scope and expiry.",
              else: "Try another CVE, team or environment, or clear the filters."}
          </p>
          <.link
            :if={@history.filtered?}
            patch={history_path(Map.drop(@params, RiskDecisionHistory.filter_keys()), %{})}
          >Clear filters</.link>
        </div>
        <nav :if={@history.pages > 1} class="risk-pagination" aria-label="Risk decision pages">
          <.link
            :if={@history.page > 1}
            id="risk-previous"
            patch={history_path(@params, %{"risk_page" => to_string(@history.page - 1)})}
          >← Previous</.link>
          <span>Page {@history.page} of {@history.pages}</span>
          <.link
            :if={@history.page < @history.pages}
            id="risk-next"
            patch={history_path(@params, %{"risk_page" => to_string(@history.page + 1)})}
          >Next →</.link>
        </nav>
      </div>
      <p id="risk-decisions-expiry-help" class="risk-decisions-footer">
        Expiry describes the recorded decision—not whether a CVE is fixed or still covered. Older decisions are retained; open Review for the current status.
      </p>
    </section>
    """
  end

  defp filter_options(values, selected, all_label) do
    values = if selected != "" and selected not in values, do: [selected | values], else: values
    [{all_label, ""} | Enum.map(values, &{&1, &1})]
  end

  defp history_path(params, changes),
    do: Routes.workspace_path(params, Map.put(changes, "page", "exceptions"))

  defp review_path(filters, cve),
    do:
      Routes.review_path(
        %{"team" => filters["risk_team"], "environment" => filters["risk_environment"]},
        cve
      )

  defp action_label("accepted_risk"), do: "Temporary whitelist"
  defp action_label("not_affected"), do: "Not affected"
  defp reason(%{reason: ""}), do: "No reason saved in this older record."
  defp reason(d), do: d.reason
  defp scope_count(%{legacy?: true}), do: "All deployments · legacy"

  defp scope_count(d) do
    count = d.scopes |> Enum.map(& &1.placement_id) |> Enum.uniq() |> length()
    if count == 1, do: "1 deployment", else: "#{count} deployments"
  end

  defp date(nil), do: "Not recorded"
  defp date(datetime), do: Calendar.strftime(datetime, "%d %b %Y")
  defp full_time(nil), do: "Not recorded"
  defp full_time(datetime), do: Calendar.strftime(datetime, "%d %b %Y, %H:%M:%S")

  defp expiry_help(%{expires_at: nil}),
    do: "No time limit was recorded. This is not proof of current coverage."

  defp expiry_help(d) do
    if (d.metadata || %{})["expiry_boundary"] == "exclusive",
      do: "This approval stops applying at the expiry time shown above.",
      else: "Older record: the expiry time is inclusive."
  end
end
