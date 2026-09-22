defmodule TriageWeb.WorkspaceComponents do
  @moduledoc "Approved workspace composition and one shared scope-aware inspector."
  use TriageWeb, :html
  alias Triage.{Decisions, Workspace}
  alias TriageWeb.WorkspaceLive, as: Routes

  # Work actions (Decisions.work_actions/0) record a request with an owner,
  # a follow-up date and a required justification; they never change or
  # suppress findings.
  defp work_details_missing?(fields),
    do:
      fields["owner"] in ["", nil] or fields["due_on"] in ["", nil] or
        fields["reason"] in ["", nil]

  attr :metrics, :map, required: true
  attr :teams, :list, required: true
  attr :targets, :list, required: true
  attr :params, :map, required: true

  def overview(assigns) do
    assigns =
      assign(assigns,
        urgent: assigns.targets |> Workspace.select("urgent") |> Workspace.rows() |> Enum.take(3)
      )

    ~H"""
    <header class="overview-heading">
      <h1>Overview</h1>
      <.link
        :if={@metrics["needs"].value > 0}
        id="start-review"
        class="primary button-link"
        patch={Routes.drill(@params, "needs")}
      >Start review</.link>
      <.link
        :if={@metrics["needs"].value == 0}
        class="button-link"
        patch={Routes.drill(@params, "active")}
      >Browse vulnerabilities</.link>
    </header>
    <div class="metrics" aria-label="Current scoped totals">
      <.link
        :for={
          {mode, label, sub, class} <- [
            {"active", "Active CVEs", "Distinct vulnerabilities in this scope", ""},
            {"needs", "Needs a decision", "Unreviewed or expired decisions", ""},
            {"urgent", "Immediate priority", "Local review priority · not confirmed exploitation",
             "alert-top"},
            {"unknown", "Unknown exposure", "Deployment scopes, not CVEs", ""}
          ]
        }
        id={"metric-#{mode}"}
        class={["metric", class]}
        patch={Routes.drill(@params, mode)}
      >
        <span class="metric-label">{label}<span aria-hidden="true">↗</span></span>
        <span class="value">{@metrics[mode].value}</span><span class="sub">{sub}</span>
      </.link>
    </div>
    <details id="overview-data-note" class="data-note">
      <summary>About these numbers</summary>
      <p>
        Counts use the latest recorded evidence, not live monitoring. Scan coverage is unverified. Unknown exposure counts deployment scopes; the other totals count distinct CVEs. Priority follows local policy and is not a claim of compromise.
      </p>
    </details>
    <div class="dashboard-grid">
      <section class="panel ownership-panel" aria-labelledby="ownership-heading">
        <div class="panel-head">
          <h2 id="ownership-heading">By team</h2><span class="muted small">Active inventory</span>
        </div>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Vulnerabilities by team">
          <table class="data-table">
            <caption class="sr-only">Team counts are not additive</caption>
            <thead>
              <tr>
                <th>Team</th><th>Active</th><th>Immediate</th><th>Needs decision</th><th>
                  Unknown exposure
                </th>
              </tr>
            </thead>
            <tbody>
              <tr :for={team <- @teams}>
                <td><span class="team-name">{team_name(team.name)}</span></td>
                <td>
                  <.link patch={Routes.drill(@params, "active", %{"team" => team.name})}>{team.metrics[
                    "active"
                  ].value}</.link>
                </td>
                <td>
                  <.link class="red" patch={Routes.drill(@params, "urgent", %{"team" => team.name})}>{team.metrics[
                    "urgent"
                  ].value}</.link>
                </td>
                <td>
                  <.link
                    id={"team-review-#{team.name}"}
                    patch={Routes.drill(@params, "needs", %{"team" => team.name})}
                  >{team.metrics["needs"].value}</.link>
                </td>
                <td>
                  <.link patch={Routes.drill(@params, "unknown", %{"team" => team.name})}>{team.metrics[
                    "unknown"
                  ].value} scopes</.link>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="panel-foot">
          A CVE can affect more than one team. Team totals cannot be added together.
        </p>
      </section>
      <section class="panel priority-findings" aria-labelledby="priority-heading">
        <div class="panel-head">
          <h2 id="priority-heading">Priority findings</h2><.link patch={
            Routes.drill(@params, "urgent")
          }>View all</.link>
        </div>
        <div class="table-wrap" tabindex="0" role="region" aria-label="Priority findings">
          <table class="data-table">
            <thead>
              <tr>
                <th>CVE / decision</th><th>Package</th><th>Severity</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={row <- @urgent}>
                <td>
                  <.link class="cve-link" patch={Routes.review_path(@params, row.cve)}>{row.cve}</.link><span class="subline">{work_status(
                    row.scopes
                  )}</span>
                </td>
                <td>{row.packages}</td><td><.severity value={row.severity} /></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p :if={@urgent == []} class="empty">
          No immediate-priority records in this scope. This is not evidence of safety.
        </p>
      </section>
    </div>
    <p :if={@metrics["active"].value == 0} class="empty">
      No matching inventory. Try a different team or environment. Public advisories do not count as deployment evidence.
    </p>
    """
  end

  attr :rows, :list, required: true
  attr :total, :integer, required: true
  attr :offset, :integer, required: true
  attr :params, :map, required: true
  attr :selected, :list, required: true
  attr :mode, :string, required: true
  attr :search_form, :any, required: true
  attr :compact, :boolean, default: false

  def inventory(assigns) do
    ~H"""
    <section class="panel">
      <div class="inventory-controls">
        <nav class="tabs" aria-label="Vulnerability views">
          <.link
            :for={
              {mode, label} <- [
                {"active", "Active"},
                {"accepted", "Whitelisted"},
                {"history", "Observation history"},
                {"all", "All"}
              ]
            }
            patch={Routes.workspace_path(@params, %{"mode" => mode, "offset" => nil})}
            class={[@mode == mode && "active"]}
            aria-current={if @mode == mode, do: "page"}
          >{label}</.link>
        </nav>
        <div class="inventory-actions">
          <button
            id="inventory-density"
            class="quiet"
            phx-click="density"
            aria-pressed={to_string(@compact)}
          >{if @compact,
            do: "Comfortable rows",
            else: "Compact rows"}</button>
          <button id="manual-cve-open" class="quiet" phx-click="manual-open">Research a CVE</button>
        </div>
      </div>
      <.form
        for={@search_form}
        id="workspace-search"
        phx-change="search"
        phx-submit="search"
        class="toolbar"
      >
        <.input
          field={@search_form[:q]}
          type="search"
          placeholder="Search CVE, package or service"
          aria-label="Search vulnerabilities"
          phx-debounce="200"
        />
        <.input
          field={@search_form[:severity]}
          type="select"
          aria-label="Severity"
          options={[{"All severities", ""}, "CRITICAL", "HIGH", "MEDIUM", "LOW"]}
        />
        <.input
          field={@search_form[:sort]}
          type="select"
          aria-label="Sort"
          options={[{"Priority first", "priority"}, {"Oldest first seen", "age"}]}
        />
        <.link
          :if={
            @params["q"] not in [nil, ""] or @params["severity"] not in [nil, ""] or
              @params["sort"] == "age" or @mode in ["unknown", "urgent"]
          }
          id="clear-inventory-filters"
          class="link"
          patch={
            Routes.workspace_path(@params, %{
              "q" => nil,
              "severity" => nil,
              "sort" => nil,
              "offset" => nil,
              "mode" => "active"
            })
          }
        >Clear filters</.link>
      </.form>
      <div :if={@selected != []} class="batchbar" role="status">
        <strong>{length(@selected)} selected</strong><span class="muted">Up to 25 CVEs</span><span class="spacer" />
        <button id="review-selected" phx-click="review-selected">Review selected</button><button
          class="quiet"
          phx-click="clear-selection"
        >Clear selection</button>
      </div>
      <div class="filter-summary">
        <strong id="inventory-result-count" role="status">{@total} matching CVEs</strong>
        <span :if={@mode in ["unknown", "urgent"]}>{if @mode == "unknown",
          do: "Unknown exposure",
          else: "Immediate priority"}</span>
        <span class="spacer" /><span>Local inventory only</span>
      </div>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Vulnerability results">
        <table id="workspace-inventory" class="data-table">
          <caption class="sr-only">
            Operational vulnerabilities. Selection does not submit a decision. Reported fixes are not verified deployments.
          </caption>
          <thead>
            <tr>
              <th>Select</th><th>Advisory / package</th><th>Affected</th><th>Why now</th><th>
                Next action
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              :for={row <- @rows}
              id={"inventory-#{row.cve}"}
              class={[
                whitelist_state(row) == "Whitelisted" && "whitelisted-row",
                row.cve in @selected && "selected"
              ]}
            >
              <td>
                <input
                  type="checkbox"
                  aria-label={"Select #{row.cve}"}
                  checked={row.cve in @selected}
                  phx-click="select"
                  phx-value-cve={row.cve}
                />
              </td>
              <td>
                <.link class="cve-link" patch={Routes.review_path(@params, row.cve)}>{row.cve}</.link><span class="subline">{row.packages}</span>
                <div class="row"><.severity value={row.severity} /></div>
                <span
                  :if={Enum.any?(row.scopes, &Enum.any?(&1.findings, fn f -> f.suppressed end))}
                  class="subline"
                >Scanner-suppressed · approval unknown</span>
              </td>
              <td>
                {row.scopes
                |> Enum.map(&team_name(&1.placement.owner))
                |> Enum.uniq()
                |> Enum.join(", ")}<span class="subline">{row.scopes
                |> Enum.map(& &1.placement.environment)
                |> Enum.uniq()
                |> Enum.join(", ")} · {length(row.scopes)} {if length(row.scopes) ==
                                                                 1,
                                                               do: "scope",
                                                               else: "scopes"}</span>
              </td>
              <td class="why-now">{why_now(row)}</td>
              <td>
                {next_action(row)}<span class="subline">Scanner fix: {fix_summary(row)}</span>
                <a
                  :if={ticket_url(row)}
                  class="subline"
                  href={ticket_url(row)}
                  target="_blank"
                  rel="noopener noreferrer"
                >Azure DevOps ticket</a>
              </td>
            </tr>
          </tbody>
        </table>
        <div :if={@rows == []} id="inventory-empty" class="empty">
          <h2>No matching vulnerabilities</h2><p>
            Try clearing the search or changing the team and environment. An empty result does not confirm safety.
          </p>
        </div>
      </div>
      <.pagination params={@params} offset={@offset} total={@total} />
    </section>
    """
  end

  attr :rows, :list, required: true
  attr :total, :integer, required: true
  attr :offset, :integer, required: true
  attr :row, :any, required: true
  attr :params, :map, required: true
  attr :draft, :any, required: true
  attr :form, :any, required: true
  attr :mode, :string, required: true
  attr :error, :any, required: true
  attr :hidden_targets, :list, required: true
  attr :queue_shown, :boolean, default: false
  attr :can_review, :boolean, default: false
  attr :draft_error, :boolean, default: false
  attr :pending_operation, :any, default: nil
  attr :history, :list, default: []

  def review(assigns) do
    ~H"""
    <div class="review-topbar">
      <div class="review-tools">
        <nav class="tabs" aria-label="Review queues">
          <.link
            :for={
              {mode, label} <- [
                {"needs", "Needs decision"},
                {"progress", "In progress"},
                {"accepted", "Whitelisted"},
                {"fixed", "Fixed"}
              ]
            }
            patch={Routes.workspace_path(@params, %{"mode" => mode, "offset" => nil})}
            class={[@mode == mode && "active"]}
            aria-current={if @mode == mode, do: "page"}
          >{label}</.link>
        </nav><button
          id="review-queue-toggle"
          class="queue-toggle quiet"
          phx-click="queue-toggle"
          aria-expanded={to_string(@queue_shown)}
          aria-controls="review-queue"
        >{if @queue_shown, do: "Back to decision", else: "Show queue (#{@total})"}</button><span
          :if={@params["batch"]}
          class="tag"
        >Selected-only review</span><span class="spacer" />
      </div>
    </div>
    <div class="review-grid">
      <section id="review-queue" class="panel queue-panel" aria-label="Review queue">
        <div class="queue-heading"><strong>{@total} CVEs</strong></div><div class="queue-list">
          <.link
            :for={row <- @rows}
            id={"queue-#{row.cve}"}
            class={[
              "queue-item",
              @row && @row.cve == row.cve && "active",
              fixed_scopes?(row.scopes) && "fixed-item",
              whitelist_state(row) == "Whitelisted" && "whitelisted-item"
            ]}
            aria-current={if @row && @row.cve == row.cve, do: "true"}
            patch={Routes.workspace_path(@params, %{"item" => row.cve})}
          ><div class="row">
            <span class="queue-id grow">{row.cve}</span><.severity value={row.severity} />
          </div><span class="queue-package" title={row.packages}>{row.packages}</span></.link>
          <p :if={@rows == []} class="empty">
            No decisions waiting here. Active exposure or evidence gaps may remain.
          </p>
        </div><.pagination params={@params} offset={@offset} total={@total} />
      </section>
      <section
        :if={@row}
        id="workspace-review"
        class="panel review-workspace"
        aria-label="Current assessment"
      >
        <header class={[
          "review-heading",
          fixed_scopes?(@row.scopes) && "fixed-heading",
          whitelist_state(@row) == "Whitelisted" && "whitelisted-heading"
        ]}>
          <strong :if={fixed_scopes?(@row.scopes)} class="fixed-banner">FIXED</strong>
          <strong :if={whitelist_state(@row) == "Whitelisted"} class="whitelisted-banner">WHITELISTED</strong>
          <div class="between">
            <div>
              <div class="row">
                <h2>{@row.cve}</h2><.severity value={@row.severity} />
              </div><p class="subtitle">
                {@row.packages} · {length(@row.scopes)} scopes in view · coverage unverified
              </p>
            </div><div>
              <.saved_status scopes={@row.scopes} />
            </div>
          </div>
        </header>
        <.form
          for={@form}
          id="workspace-decision"
          phx-change="draft"
          phx-submit="save"
          class="review-content"
        >
          <div class="evidence-column">
            <div class="block-title">
              <h3>Summary</h3>
            </div>
            <p class="summary-copy long-value">{description(@row)}</p>
            <dl class="reported-fix">
              <dt>Scanner-reported fix</dt><dd>{reported_fixes(@row)}</dd>
            </dl>
            <p class="form-note">A reported fix is not proof it has been deployed.</p>
            <div class="block-title">
              <h3>Affected deployments</h3><span>{length(@draft.targets)} selected</span>
            </div>
            <p :if={@hidden_targets != []} class="form-error">
              {length(@hidden_targets)} selected targets are hidden by this scope. Restore the original scope; selection has not changed.
            </p>
            <.scope_table targets={@row.scopes} selected={@draft.targets} selectable={@can_review} />
            <p class="coverage-note">
              Select the deployments this decision applies to. Production and staging are separate targets.
            </p>
            <details>
              <summary>Why this priority?</summary><p>
                Priority sets review order. It does not change scanner severity or confirm exploitation.
              </p><p :for={reason <- if(@row.risk, do: @row.risk.reasons, else: [])}>
                {reason}
              </p>
            </details>
            <details>
              <summary>Technical evidence and provenance</summary><div :for={scope <- @row.scopes}>
                <p class="long-value">
                  {scope.image.digest} · placement {scope.id} · last recorded {time(scope.last_seen)}
                </p><p :for={f <- scope.findings}>
                  {f.package_name} {f.package_version} · finding {f.id} · scanner suppression {if f.suppressed,
                    do: "present; approval unknown",
                    else: "not recorded"}
                </p>
              </div>
            </details>
            <details id="decision-history-section">
              <summary>Decision history</summary>
              <p class="form-note">
                Append-only. Legacy global decisions keep their original labels; scanner suppression is not a human decision.
              </p>
              <.history_entries history={@history} />
            </details>
          </div>
          <div class="decision-column">
            <p :if={not @can_review} id="viewer-read-only">
              Read-only viewer. A reviewer or administrator must make decisions.
            </p>
            <div class="decision-head">
              <h3>Decision</h3><span class="muted small">{length(@draft.targets)} selected</span>
            </div>
            <p class="form-note" id="why-now">Why now: {why_now(@row)}</p>
            <p
              :if={@can_review and @draft.targets == []}
              id="decision-no-targets"
              class="form-error"
              role="status"
            >
              Select at least one deployment to continue.
            </p>
            <p :if={@error} id="decision-error" role="alert" class="form-error">{@error}</p>
            <.input
              field={@form[:action]}
              disabled={not @can_review}
              type="select"
              label="Next action"
              options={[
                {"Choose an action…", ""},
                {"Mark as fixed", "fixed"},
                {"Whitelist temporarily", "accepted_risk"},
                {"Create Azure DevOps ticket", "create_ticket"},
                {"Request investigation", "investigate"},
                {"Request remediation", "request_remediation"},
                {"Request verification", "request_verification"}
              ]}
            />
            <.input
              :if={@draft.fields["action"] == "accepted_risk"}
              field={@form[:due_on]}
              disabled={not @can_review}
              type="date"
              label="Whitelist through (UTC)"
              aria-describedby="whitelist-expiry-help"
            />
            <.input
              :if={@draft.fields["action"] == "accepted_risk"}
              field={@form[:reason]}
              disabled={not @can_review}
              type="textarea"
              label="Reason for accepting the risk (optional)"
              maxlength="2000"
            />
            <p :if={@draft.fields["action"] == "fixed"} class="form-note">
              Marks selected scopes Fixed with today's date. No comment required.
            </p>
            <p
              :if={@draft.fields["action"] == "accepted_risk"}
              id="whitelist-expiry-help"
              class="form-note"
            >
              Risk is accepted through the selected date, until midnight UTC at the start of the next day.
              Then these deployments return to Needs decision unless a newer decision applies.
              Defaults to three months from today.
            </p>
            <p :if={@draft.fields["action"] == "create_ticket"} class="form-note">
              Creates an Azure DevOps ticket with CVE and selected deployment evidence. Requires server configuration.
            </p>
            <.input
              :if={@draft.fields["action"] in Decisions.work_actions()}
              field={@form[:owner]}
              disabled={not @can_review}
              type="text"
              label="Responsible owner"
            />
            <.input
              :if={@draft.fields["action"] in Decisions.work_actions()}
              field={@form[:due_on]}
              disabled={not @can_review}
              type="date"
              label="Follow-up by (UTC)"
            />
            <.input
              :if={@draft.fields["action"] in Decisions.work_actions()}
              field={@form[:reason]}
              disabled={not @can_review}
              type="textarea"
              label="Justification (required)"
              maxlength="2000"
            />
            <p :if={@draft.fields["action"] in Decisions.work_actions()} class="form-note">
              Records a work request for the selected scopes with an owner, a follow-up date and a justification. It does not change or suppress the findings.
            </p>
            <div class="decision-actions">
              <button
                :if={@can_review && (@error || @draft.stale)}
                id="reload-evidence"
                type="button"
                phx-click="reconcile"
              >Reload current evidence</button>
            </div>
          </div>
        </.form>
        <footer class="review-footer">
          <span id="draft-state" class="save-state">{if @draft.saved,
            do: "Decision saved",
            else:
              if(@draft_error,
                do: "Draft NOT saved · keep this tab open",
                else: if(@draft.dirty, do: "Draft saved to your account", else: "No unsaved changes")
              )}</span><div class="row wrap">
            <button
              id="cancel-decision"
              disabled={not @can_review or not is_nil(@pending_operation) or not @draft.dirty}
              type="button"
              phx-click="cancel-decision"
            >Discard draft</button>
            <button
              id="save-decision"
              class="primary"
              type="submit"
              form="workspace-decision"
              phx-disable-with="Working…"
              disabled={
                not @can_review or @draft.targets == [] or not is_nil(@pending_operation) or
                  @draft_error or @draft.stale or
                  @hidden_targets != [] or
                  @draft.fields["action"] not in (~w(fixed accepted_risk create_ticket) ++
                                                    Decisions.work_actions()) or
                  (@draft.fields["action"] in Decisions.work_actions() and
                     work_details_missing?(@draft.fields))
              }
            >{case @draft.fields["action"] do
              "fixed" -> "Mark as fixed"
              "accepted_risk" -> "Whitelist now"
              "create_ticket" -> "Create Azure DevOps ticket"
              "investigate" -> "Request investigation"
              "request_remediation" -> "Request remediation"
              "request_verification" -> "Request verification"
              _ -> "Select an action"
            end}</button>
          </div>
        </footer>
      </section>
      <section :if={is_nil(@row)} class="panel review-workspace">
        <div class="empty">
          <h2>No matching assessment</h2><p>
            The requested advisory is outside the current scope or no work is waiting. No other target has been substituted.
          </p><.link patch={Routes.drill(@params, "active")}>Open active inventory</.link>
        </div>
      </section>
    </div>
    """
  end

  defp reported_fixes(row) do
    fixes =
      row.scopes
      |> Enum.flat_map(& &1.findings)
      |> Enum.map(& &1.fix)
      |> Enum.reject(&(&1 in [nil, ""]))
      |> Enum.uniq()

    if fixes == [], do: "Not reported", else: Enum.join(fixes, ", ")
  end

  attr :targets, :list, required: true
  attr :selected, :list, default: []
  attr :selectable, :boolean, default: false

  def scope_table(assigns) do
    ~H"""
    <div class="table-wrap">
      <table class="scope-table">
        <thead>
          <tr>
            <th :if={@selectable}>Select</th><th>Team / environment</th><th>Service / target</th><th>
              Exposure / state
            </th>
          </tr>
        </thead><tbody>
          <tr :for={scope <- @targets} data-target-id={scope.id}>
            <td :if={@selectable}>
              <label><input
                type="checkbox"
                id={"scope-target-#{scope.id}"}
                aria-label={"Select #{scope.placement.owner} #{scope.placement.environment} placement #{scope.id}"}
                checked={scope.id in @selected}
                disabled={not scope.active?}
                phx-click="target"
                phx-value-id={scope.id}
              /></label>
            </td>
            <td>
              <strong>{team_name(scope.placement.owner)}</strong><br />{scope.placement.environment}
            </td><td>
              {scope.image.repository}<br /><span class="mono">Placement {scope.id} · {scope.placement.namespace}</span>
            </td><td>{exposure(scope.exposure)}<br /><small>{work_status([scope])}</small></td>
          </tr>
        </tbody>
      </table>
    </div>
    """
  end

  attr :row, :map, required: true
  attr :draft, :map, required: true

  def risk_confirmation(assigns) do
    ~H"""
    <dialog
      id="risk-confirmation"
      class="confirm"
      phx-hook="WorkspaceDialog"
      data-close-event="cancel-risk"
      aria-labelledby="risk-title"
    >
      <div class="confirmation-layout">
        <header class="modal-head">
          <h2 id="risk-title">Whitelist temporarily?</h2>
        </header><div class="modal-body">
          <strong>{@row.cve} · {length(@draft.targets)} exact targets</strong><.scope_table targets={
            Enum.filter(@row.scopes, &(&1.id in @draft.targets))
          } /><p>{@draft.fields["reason"]}</p><p>
            Valid through {@draft.fields["due_on"]}, UTC; expires at the following midnight.
          </p><p>
            Recorded locally with the current date.
          </p><p>This does not mark the CVE fixed or create an external ticket.</p>
        </div><footer class="modal-foot">
          <button id="cancel-risk" phx-click="cancel-risk">Cancel</button><button
            id="confirm-risk"
            class="primary"
            phx-click="confirm-risk"
            phx-disable-with="Saving…"
          >Confirm whitelist</button>
        </footer>
      </div>
    </dialog>
    """
  end

  attr :row, :map, required: true
  attr :draft, :map, required: true
  attr :error, :any, default: nil

  def ticket_confirmation(assigns) do
    targets = Enum.filter(assigns.row.scopes, &(&1.id in assigns.draft.targets))
    payload = Triage.AzureDevOps.payload(assigns.row.cve, targets, assigns.draft.operation)

    assigns =
      assign(
        assigns,
        :ticket_description,
        Enum.find(payload, &(&1.path == "/fields/System.Description")).value
      )

    ~H"""
    <dialog
      id="ticket-confirmation"
      class="confirm"
      phx-hook="WorkspaceDialog"
      data-close-event="cancel-risk"
      aria-labelledby="ticket-title"
    >
      <div class="confirmation-layout">
        <header class="modal-head">
          <h2 id="ticket-title">Preview Azure DevOps ticket</h2>
        </header>
        <div class="modal-body">
          <p>This will create a ticket in: <strong>{Triage.AzureDevOps.backlog()}</strong></p>
          <h3>{@row.cve} needs to be fixed</h3>
          <p>Team: {Triage.AzureDevOps.team()} (routed through the team's area path)</p>
          <div style="white-space: normal; overflow-wrap: anywhere; overflow: auto;">
            {Phoenix.HTML.raw(@ticket_description)}
          </div>
          <p :if={@error} role="alert">{@error}</p>
        </div>
        <footer class="modal-foot">
          <button phx-click="cancel-risk">Cancel</button>
          <button
            id="confirm-ticket"
            class="primary"
            phx-click="confirm-ticket"
            phx-disable-with="Creating…"
          >Create ticket</button>
        </footer>
      </div>
    </dialog>
    """
  end

  def settings_dialog(assigns) do
    ~H"""
    <dialog
      id="workspace-settings-dialog"
      class="confirm"
      phx-hook="WorkspaceDialog"
      data-close-event="close-settings"
      aria-labelledby="settings-title"
    >
      <div class="confirmation-layout">
        <header class="modal-head">
          <h2 id="settings-title">Data &amp; help</h2>
        </header><div class="modal-body">
          <dl class="data-help">
            <div>
              <dt>Inventory is recorded evidence</dt><dd>
                Counts describe local deployments, not public advisories. Scan completeness and current production coverage are unverified.
              </dd>
            </div>
            <div>
              <dt>Your work is saved to your account</dt><dd>
                Drafts survive reloads and server restarts. A draft is not a decision: use the action button to commit it. Discard draft only clears the current draft.
              </dd>
            </div>
            <div>
              <dt>Changed evidence needs another look</dt><dd>
                If another reviewer changes the same CVE, your draft is preserved. Reload the evidence before saving.
              </dd>
            </div>
            <div>
              <dt>Research does not add affected deployments</dt><dd>
                Research a CVE fetches its description from NVD. News shows public advisories and headlines. Neither changes your inventory.
              </dd>
            </div>
            <div>
              <dt>Azure DevOps is configured by an administrator</dt><dd>
                Ticket creation requires server configuration and confirmation. Imports and connection settings are not editable here.
              </dd>
            </div>
          </dl>
        </div><footer class="modal-foot"><button phx-click="close-settings">Close</button></footer>
      </div>
    </dialog>
    """
  end

  attr :params, :map, required: true
  attr :offset, :integer, required: true
  attr :total, :integer, required: true

  def pagination(assigns) do
    ~H"""
    <div class="panel-foot">
      <span>{if @total == 0 or @offset >= @total,
        do: "0 of #{@total} CVEs",
        else: "#{@offset + 1}–#{min(@offset + 50, @total)} of #{@total} CVEs"}</span><span class="row"><.link
        :if={@offset > 0}
        patch={Routes.workspace_path(@params, %{"offset" => max(@offset - 50, 0)})}
      >Previous</.link><.link
        :if={@offset + 50 < @total}
        patch={Routes.workspace_path(@params, %{"offset" => @offset + 50})}
      >Next</.link></span>
    </div>
    """
  end

  attr :value, :any, required: true

  def severity(assigns) do
    ~H"""
    <span class={["badge", String.downcase(@value || "unknown")]}>{@value || "Unknown"}</span>
    """
  end

  attr :risk, :any, required: true
  attr :severity, :any, default: nil

  def priority(assigns) do
    ~H"""
    <span class={[
      "badge",
      String.downcase(displayed_priority(@risk, @severity))
    ]}>{displayed_priority(@risk, @severity)}</span>
    """
  end

  # The displayed review priority never contradicts the scanner severity: a
  # "Critical" priority belongs to critical advisories only, and a critical
  # advisory never shows a lesser label beside its severity. Without a
  # recorded severity the computed review priority stands on its own.
  defp displayed_priority(nil, _severity), do: "No active scope"

  defp displayed_priority(risk, severity) do
    case to_string(severity || "") |> String.downcase() do
      known when known in ["critical", "high", "medium", "low"] -> String.capitalize(known)
      _other -> String.capitalize(risk.priority)
    end
  end

  def team_name(name) when name in [nil, "", "(unknown)", "unassigned", "__unassigned__"],
    do: "Unassigned"

  def team_name(name), do: name

  def exposure("internet_exposed"), do: "Internet"
  def exposure("internal"), do: "Internal"
  def exposure(_), do: "Unknown"
  def time(nil), do: "Unknown"
  def time(dt), do: Calendar.strftime(dt, "%d %b %Y %H:%M UTC")

  def description(row) do
    row.scopes
    |> Enum.flat_map(& &1.findings)
    |> Enum.map(& &1.description)
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.uniq()
    |> Enum.join("\n")
    |> then(fn text ->
      if text == "",
        do:
          "No vulnerability description recorded. Inspect affected packages and evidence before deciding.",
        else: text
    end)
  end

  attr :scopes, :list, required: true

  def saved_status(assigns) do
    states =
      assigns.scopes
      |> Enum.map(fn s ->
        if s.covered?, do: s.decision.decision, else: "needs"
      end)
      |> Enum.uniq()

    state = if length(states) == 1, do: hd(states), else: "mixed"

    label =
      case state do
        "fixed" -> "Fixed"
        "accepted_risk" -> "Whitelisted"
        "create_ticket" -> "In progress — ticket created"
        "needs" -> "Needs decision"
        "mixed" -> "Mixed scope statuses"
        _ -> "In progress"
      end

    assigns = assign(assigns, state: state, label: label)

    ~H"""
    <span :if={@state != "accepted_risk"} class={"badge saved-status status-#{@state}"}>{@label}</span>
    """
  end

  def fixed_scopes?(scopes) do
    scopes != [] and Enum.all?(scopes, &(&1.covered? and &1.decision.decision == "fixed"))
  end

  def work_status(scopes) do
    scopes
    |> Enum.map(fn scope ->
      cond do
        not scope.active? -> "No longer observed"
        scope.covered? -> Decisions.label(scope.decision.decision)
        true -> "Needs decision"
      end
    end)
    |> Enum.uniq()
    |> Enum.join(" / ")
  end

  @doc """
  Visibility state of the current assessment's active whitelist decisions:
  `nil` when nothing is whitelisted, `"Whitelisted"` when every active scope is,
  `"Partially whitelisted"` when only some are.
  """
  def whitelist_state(nil), do: nil

  def whitelist_state(row) do
    active = Enum.filter(row.scopes, & &1.active?)

    whitelisted =
      Enum.count(active, &(&1.covered? and &1.decision.decision == "accepted_risk"))

    cond do
      active == [] or whitelisted == 0 -> nil
      whitelisted == length(active) -> "Whitelisted"
      true -> "Partially whitelisted"
    end
  end

  def history_scope(%{placement_id: nil}),
    do: "Legacy global advisory decision · scope not narrowed"

  def history_scope(d) do
    target = d.metadata["target"] || %{}

    "Placement #{d.placement_id} · #{target["team"] || "historical team unknown"} · #{target["environment"] || "historical environment unknown"}"
  end

  # T03: source-backed "Why now" from the deterministic risk policy. The
  # strongest classified target's reason leads; no opaque score is invented.
  defp why_now(row) do
    cond do
      row.risk && row.risk.reasons != [] -> hd(row.risk.reasons)
      Enum.any?(row.scopes, &(!&1.active?)) -> "No longer observed in local inventory"
      true -> "No recorded attention reason; coverage is unverified"
    end
  end

  # T03: concrete next step derived from recorded work, never a safety claim.
  defp next_action(row) do
    cond do
      ticket_url(row) ->
        "Ticket created · track existing work"

      fixed_scopes?(row.scopes) ->
        "Reported fixed · verify deployment"

      whitelist_state(row) in ["Whitelisted", "Partially whitelisted"] ->
        "Risk accepted · review at expiry"

      Enum.any?(row.scopes, &(&1.covered? and &1.decision.decision in Decisions.work_actions())) ->
        "Work in progress · follow up with the owner"

      Enum.any?(row.scopes, &(!&1.active?)) ->
        "Historical record · no current action"

      true ->
        "Choose an action for exact scopes"
    end
  end

  defp fix_summary(row) do
    fixes =
      row.scopes
      |> Enum.flat_map(& &1.findings)
      |> Enum.map(& &1.fix)
      |> Enum.reject(&(&1 in [nil, ""]))
      |> Enum.uniq()

    if fixes == [], do: "not reported", else: Enum.join(fixes, ", ")
  end

  defp ticket_url(row),
    do: Enum.find_value(row.scopes, &(&1.decision && &1.decision.metadata["ticket_url"]))

  attr :history, :list, required: true

  @doc """
  T03: the shared detail's append-only decision history, reused from the
  retired inspector. Exact scope, reason and ticket links stay explicit.
  """
  def history_entries(assigns) do
    ~H"""
    <article :for={d <- @history} id={"decision-history-#{d.id}"} class="history-entry">
      <time>{time(d.decided_at)}</time><div>
        <strong>{d.label} · {d.state}</strong><p>{history_scope(d)}</p><p>
          {d.reason}
          <a
            :if={d.metadata["ticket_url"]}
            href={d.metadata["ticket_url"]}
            target="_blank"
            rel="noopener noreferrer"
          >Azure DevOps ticket</a>
        </p><p :if={d.expires_at}>
          {if d.metadata["expiry_boundary"] == "exclusive", do: "Expires at", else: "Valid through"}
          {time(d.expires_at)}
        </p>
      </div>
    </article><p :if={@history == []}>No recorded decisions for these scopes.</p>
    """
  end
end
