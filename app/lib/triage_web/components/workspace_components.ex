defmodule TriageWeb.WorkspaceComponents do
  @moduledoc "Approved workspace composition and one shared scope-aware inspector."
  use TriageWeb, :html
  alias Triage.{Decisions, Workspace}
  alias TriageWeb.WorkspaceLive, as: Routes

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
    <section
      class={["callout", @metrics["urgent"].value == 0 && "caution"]}
      aria-label="Attention and evidence confidence"
    >
      <div class="symbol">!</div><div class="grow">
        <h2>
          {if @metrics["urgent"].value > 0,
            do: "Immediate attention required",
            else: "Review current evidence"}
        </h2><p>
          {@metrics["urgent"].value} immediate-priority CVEs in this scope. Priority is not a claim of compromise.
        </p>
      </div><div class="confidence">
        <strong>Confidence: limited</strong><br /><span class="muted">{@metrics["unknown"].value} unknown-exposure scopes · scan coverage unverified</span>
      </div><div class="row page-actions">
        <.link
          class="primary button-link"
          patch={Routes.drill(@params, "needs")}
        >Start review →</.link>
      </div>
    </section>
    <div class="metrics" aria-label="Current scoped totals">
      <.link
        :for={
          {mode, label, sub, class} <- [
            {"active", "Active CVEs", "Affected scopes · latest recorded state", ""},
            {"needs", "Need a decision", "Distinct CVEs · uncovered or expired scopes", ""},
            {"urgent", "Immediate priority", "Critical review priority · local policy v1",
             "alert-top"},
            {"unknown", "Exposure unknown", "Affected scopes · evidence needed", "warn-top"}
          ]
        }
        id={"metric-#{mode}"}
        class={["metric", class]}
        patch={Routes.drill(@params, mode)}
      >
        <span class="metric-label">{label}<span aria-hidden="true">↗</span></span><span class="value">{@metrics[
          mode
        ].value}</span><span class="sub">{sub}</span>
      </.link>
    </div>
    <div class="dashboard-grid">
      <section class="panel ownership-panel">
        <div class="panel-head">
          <h2>Ownership by team</h2><span class="tag">Active CVEs</span>
        </div>
        <div class="table-wrap">
          <table class="data-table">
            <caption class="sr-only">Team counts are not additive</caption><thead>
              <tr>
                <th>Team</th><th>Active</th><th>Immediate</th><th>Needs decision</th><th>
                  Exposure unknown
                </th>
              </tr>
            </thead><tbody>
              <tr :for={team <- @teams}>
                <td>
                  <div class="row">
                    <span class="team-icon">{String.slice(team_name(team.name), 0, 2)
                    |> String.upcase()}</span><span class="team-name">{team_name(team.name)}</span>
                  </div>
                </td><td>
                  <.link patch={Routes.drill(@params, "active", %{"team" => team.name})}>{team.metrics[
                    "active"
                  ].value}</.link>
                </td><td class="red">{team.metrics["urgent"].value}</td><td>
                  <.link
                    id={"team-review-#{team.name}"}
                    patch={Routes.drill(@params, "needs", %{"team" => team.name})}
                  >{team.metrics["needs"].value}</.link>
                </td><td class="amber">
                  <.link patch={Routes.drill(@params, "unknown", %{"team" => team.name})}>{team.metrics[
                    "unknown"
                  ].value} scopes</.link>
                </td>
              </tr>
            </tbody>
          </table>
        </div><div class="panel-foot">
          A CVE can affect several teams; team totals are not additive.
        </div>
      </section>
    </div>
    <div class="dashboard-secondary">
      <section class="panel">
        <div class="panel-head">
          <h2>Priority findings</h2><.link patch={Routes.drill(@params, "urgent")}>Open priority view →</.link>
        </div><div class="table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>Advisory</th><th>Package</th><th>Scopes</th><th>Severity</th>
              </tr>
            </thead><tbody>
              <tr :for={row <- @urgent}>
                <td><.link patch={Routes.inspector_path(@params, row.cve)}>{row.cve}</.link></td><td>
                  {row.packages}
                </td><td>{length(row.scopes)}</td><td><.severity value={row.severity} /></td>
              </tr>
            </tbody>
          </table>
        </div><p :if={@urgent == []} class="empty">
          No immediate-priority records in this scope. This is not evidence of safety.
        </p>
      </section>
    </div>
    <p :if={@targets == []} class="empty">
      No matching operational inventory. Public advisories are not deployment evidence. Check scope or import local evidence in Data &amp; settings.
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

  def inventory(assigns) do
    ~H"""
    <section class="panel">
      <div class="tabs">
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
        >{label}</.link><span :if={@mode in ["unknown", "urgent"]} class="tag">{if @mode == "unknown",
          do: "Unknown exposure scopes",
          else: "Immediate priority scopes"}</span><button class="density-toggle" phx-click="density">Toggle row density</button><button
          id="manual-cve-open"
          phx-click="manual-open"
        >Add CVE</button>
      </div>
      <.form for={@search_form} id="workspace-search" phx-change="search" class="toolbar">
        <.input
          field={@search_form[:q]}
          type="search"
          placeholder="Search CVE, package or service…"
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
      </.form>
      <div :if={@selected != []} class="batchbar">
        <strong>{length(@selected)} CVEs selected · maximum 25</strong><span class="spacer" /><button
          id="review-selected"
          phx-click="review-selected"
        >Review selected</button><button phx-click="clear-selection">Clear</button>
      </div>
      <div class="filter-summary">
        <strong>{@total} matching CVEs</strong><span>· exact matching scopes only</span><span class="spacer" /><span>Reference advisories excluded</span>
      </div>
      <div class="table-wrap">
        <table id="workspace-inventory" class="data-table">
          <caption class="sr-only">
            Operational vulnerabilities. Selection does not submit a decision.
          </caption><thead>
            <tr>
              <th>Select</th><th>Advisory / package</th><th>Severity</th><th>
                Affected
              </th><th>Exposure</th><th>Work status</th><th>Age</th><th>Fix info</th>
            </tr>
          </thead><tbody>
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
              </td><td>
                <.link class="cve-link" patch={Routes.inspector_path(@params, row.cve)}>{row.cve}</.link><span class="subline">{row.packages}</span><span
                  :if={Enum.any?(row.scopes, &Enum.any?(&1.findings, fn f -> f.suppressed end))}
                  class="subline"
                >Scanner-suppressed · approval unknown</span>
              </td><td><.severity value={row.severity} /></td><td>
                {row.scopes |> Enum.map(& &1.placement.owner) |> Enum.uniq() |> Enum.join(", ")}<span class="subline">{length(
                  row.scopes
                )} scopes</span>
              </td><td>
                {row.scopes |> Enum.map(&exposure(&1.exposure)) |> Enum.uniq() |> Enum.join(", ")}
              </td><td>{work_status(row.scopes)}</td><td>
                {max(Date.diff(Date.utc_today(), DateTime.to_date(row.first_seen)), 0)}d
              </td><td>
                {if Enum.any?(
                      row.scopes,
                      &Enum.any?(&1.findings, fn f -> f.fix not in [nil, ""] end)
                    ), do: "Reported · not verified deployed", else: "Not reported"}
              </td>
            </tr>
          </tbody>
        </table><p :if={@rows == []} class="empty">
          No matching vulnerabilities. This is not evidence of safety.
        </p>
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

  def review(assigns) do
    ~H"""
    <div class="review-topbar">
      <div class="review-tools">
        <div class="tabs">
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
          >{label}</.link>
        </div><button class="queue-toggle quiet" phx-click="queue-toggle">{if @queue_shown,
          do: "Assessment",
          else: "Queue"}</button><span
          :if={@params["batch"]}
          class="tag"
        >Selected-only review</span><.link
          :if={@row}
          class="link history-link"
          patch={Routes.workspace_path(@params, %{"inspect" => @row.cve, "tab" => "history"})}
        >Decision history</.link>
      </div>
    </div>
    <div class="review-grid">
      <section class="panel queue-panel" aria-label="Review queue">
        <div class="queue-heading"><strong>{@total} CVEs</strong></div><div class="queue-list">
          <.link
            :for={row <- @rows}
            id={"queue-#{row.cve}"}
            class={["queue-item", @row && @row.cve == row.cve && "active", fixed_scopes?(row.scopes) && "fixed-item", whitelist_state(row) == "Whitelisted" && "whitelisted-item"]}
            aria-current={if @row && @row.cve == row.cve, do: "true"}
            patch={Routes.workspace_path(@params, %{"item" => row.cve})}
          ><div class="row">
            <span class="queue-id grow">{row.cve}</span>
          </div></.link>
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
        <header class={["review-heading", fixed_scopes?(@row.scopes) && "fixed-heading", whitelist_state(@row) == "Whitelisted" && "whitelisted-heading"]}>
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
              <.saved_status scopes={@row.scopes} /><.link patch={
                Routes.inspector_path(@params, @row.cve)
              }>Full evidence ↗</.link>
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
            <div class="policy-strip">
              <strong>Local policy v1</strong><span>Severity is unchanged by exposure or work decisions.</span>
            </div>
            <div class="block-title">
              <h3>What matters</h3><span>Scanner + scoped evidence</span>
            </div>
            <p class="summary-copy long-value">{description(@row)}</p>
            <div class="fact-grid">
              <dl class="fact">
                <dt>Exploitation intelligence</dt><dd>Cached evidence only · see Evidence</dd>
              </dl><dl class="fact">
                <dt>Scanner-reported fix</dt><dd>Not verified deployed</dd>
              </dl>
            </div>
            <div class="block-title">
              <h3>Affected scopes</h3><span>{length(@draft.targets)} selected</span>
            </div>
            <p :if={@hidden_targets != []} class="form-error">
              {length(@hidden_targets)} selected targets are hidden by this scope. Restore the original scope; selection has not changed.
            </p>
            <.scope_table targets={@row.scopes} selected={@draft.targets} selectable />
            <p class="coverage-note">
              One target is this CVE on an immutable placement, including every listed package occurrence. Production does not include staging.
            </p>
            <details>
              <summary>Why this priority?</summary><p :for={
                reason <- if(@row.risk, do: @row.risk.reasons, else: [])
              }>
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
          </div>
          <div class="decision-column">
            <div class="decision-head">
              <h3>Decision</h3><.saved_status scopes={@row.scopes} /><span class="tag">{length(
                @draft.targets
              )} scopes</span>
            </div><p class="intro">Applies only to the selected scopes.</p>
            <p :if={@error} id="decision-error" role="alert" class="form-error">{@error}</p>
            <.input
              field={@form[:action]}
              type="select"
              label="Next action"
              options={[
                {"Mark as fixed", "fixed"},
                {"Whitelist temporarily", "accepted_risk"},
                {"Create Azure DevOps ticket", "create_ticket"}
              ]}
            />
            <.input
              :if={@draft.fields["action"] == "accepted_risk"}
              field={@form[:due_on]}
              type="date"
              label="Whitelist through (UTC)"
            />
            <.input
              :if={@draft.fields["action"] == "accepted_risk"}
              field={@form[:reason]}
              type="textarea"
              label="Comment (optional)"
              maxlength="2000"
            />
            <p :if={@draft.fields["action"] == "fixed"} class="form-note">
              Marks selected scopes Fixed with today's date. No comment required.
            </p>
            <p :if={@draft.fields["action"] == "accepted_risk"} class="form-note">
              Defaults to three calendar months from today. Expired whitelists return to Needs decision.
            </p>
            <p :if={@draft.fields["action"] == "create_ticket"} class="form-note">
              Creates an Azure DevOps ticket with CVE and selected deployment evidence. Requires server configuration.
            </p>
            <div class="decision-actions">
              <button :if={@error} type="button" phx-click="reconcile">Reload current evidence</button>
            </div>
          </div>
        </.form>
        <footer class="review-footer">
          <span id="draft-state" class="save-state">{if @draft.saved,
            do: "Decision committed locally",
            else: "Draft · this live connection only"}</span><div class="row wrap">
            <button
              id="cancel-decision"
              type="button"
              phx-click="cancel-decision"
            >Cancel</button>
            <button
              id="save-decision"
              class="primary"
              type="submit"
              form="workspace-decision"
              phx-disable-with="Working…"
              disabled={
                @hidden_targets != [] or
                  @draft.fields["action"] not in ~w(fixed accepted_risk create_ticket)
              }
            >{case @draft.fields["action"] do
              "fixed" -> "Mark as fixed"
              "accepted_risk" -> "Whitelist now"
              "create_ticket" -> "Create Azure DevOps ticket"
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

  attr :row, :any, required: true
  attr :requested, :string, required: true
  attr :targets, :list, required: true
  attr :history, :list, required: true
  attr :params, :map, required: true
  attr :expanded, :boolean, required: true

  def inspector(assigns) do
    ~H"""
    <dialog
      id="workspace-inspector"
      class={["inspector", @expanded && "expanded"]}
      phx-hook="WorkspaceDialog"
      data-close-event="close-inspector"
      aria-labelledby="inspector-title"
    >
      <div class="inspector-layout">
        <header class="inspector-head">
          <div class="between">
            <span class="scope-label">Advisory inspector · scoped evidence</span><div class="row">
              <button
                id="expand-inspector"
                phx-click="expand"
                aria-label="Expand or restore inspector"
              >{if @expanded, do: "Restore", else: "Expand"}</button><button
                id="close-inspector"
                phx-click="close-inspector"
                aria-label="Close inspector"
              >Close</button>
            </div>
          </div><h2 id="inspector-title">{@requested}</h2><div :if={@row} class="row">
            <.severity value={@row.severity} /><p>
              {@row.packages} · {length(@targets)} visible scopes
            </p>
          </div>
        </header>
        <nav class="tabs" aria-label="Inspector sections">
          <.link
            :for={
              {tab, label} <- [
                {"summary", "Summary"},
                {"assets", "Affected assets"},
                {"history", "History"},
                {"evidence", "Evidence"}
              ]
            }
            id={"inspector-tab-#{tab}"}
            class={[(@params["tab"] || "summary") == tab && "active"]}
            patch={Routes.workspace_path(@params, %{"tab" => tab})}
          >{label}</.link>
        </nav>
        <div class="inspector-body">
          <p :if={is_nil(@row)} class="empty">
            No matching scopes for this advisory. No out-of-scope evidence has been substituted.
          </p>
          <%= if @row do %>
            <%= case @params["tab"] || "summary" do %>
              <% "assets" -> %>
                <.scope_table targets={@targets} /><div :for={target <- @targets} class="section">
                  <h3>Placement {target.id}</h3><p class="long-value">{target.image.digest}</p><p :for={
                    f <- target.findings
                  }>
                    {f.package_name} {f.package_version} · finding {f.id}
                  </p>
                </div>
              <% "history" -> %>
                <div class="section">
                  <h3>Scoped decision history</h3><p>
                    Global legacy decisions are labeled explicitly. Scanner suppression is not a human decision.
                  </p>
                </div><article
                  :for={d <- @history}
                  id={"decision-history-#{d.id}"}
                  class="history-entry"
                >
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
                      Expires {time(d.expires_at)} · {if d.metadata["expiry_boundary"] == "exclusive",
                        do: "exclusive boundary",
                        else: "legacy inclusive boundary"}
                    </p>
                  </div>
                </article><p :if={@history == []}>No recorded decisions for these scopes.</p><div class="section">
                  <h3>Observation evidence</h3><p :for={scope <- @targets}>
                    Placement {scope.id}: first recorded {time(scope.first_seen)}; last recorded {time(
                      scope.last_seen
                    )}. {if scope.active?,
                      do: "Still recorded affected.",
                      else: "No longer observed, not verified remediated."}
                  </p>
                </div>
              <% "evidence" -> %>
                <div class="section">
                  <h3>Evidence &amp; provenance</h3><p>
                    Local inventory records, not a verified current scan. Coverage completeness and production freshness are unknown. No intelligence fetch occurs when opening this view.
                  </p><p>
                    Priority: Triage.Risk policy v1; positive exploitation input comes from the cached KEV source. Missing cache is not a negative result.
                  </p><div :for={scope <- @targets}>
                    <h3>Placement {scope.id}</h3><p>
                      Observed {time(scope.last_seen)} · exposure {exposure(scope.exposure)}
                    </p><p class="long-value">Immutable image: {scope.image.digest}</p><p :for={
                      f <- scope.findings
                    }>
                      Finding {f.id}: {f.package_name} {f.package_version}; scanner fix {f.fix ||
                        "not reported"}; suppression {if f.suppressed,
                        do: "present, approval and date unknown",
                        else: "not recorded"}.
                    </p>
                  </div>
                </div>
              <% _ -> %>
                <div class="section">
                  <h3>At a glance</h3><p class="long-value">{description(@row)}</p>
                </div><div class="facts">
                  <dl class="fact">
                    <dt>Work status</dt><dd>{work_status(@targets)}</dd>
                  </dl><dl class="fact">
                    <dt>Affected scopes in view</dt><dd>{length(@targets)}</dd>
                  </dl><dl class="fact">
                    <dt>Coverage</dt><dd>Unverified</dd>
                  </dl>
                </div><.scope_table targets={@targets} /><div class="note">
                  Whitelisting and scanner suppression do not remove active exposure. A reported fix is not verified remediation.
                </div>
            <% end %>
          <% end %>
        </div>
        <footer class="inspector-foot">
          <span class="grow small muted">Only current shared-scope targets shown.</span><button phx-click="close-inspector">Close</button><.link
            :if={@row && Enum.any?(@targets, & &1.active?)}
            id="inspector-review"
            class="primary button-link"
            patch={Routes.review_path(@params, @row.cve)}
          >Review this CVE →</.link>
        </footer>
      </div>
    </dialog>
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
    assigns = assign(assigns, :ticket_description, Enum.find(payload, &(&1.path == "/fields/System.Description")).value)
    ~H"""
    <dialog id="ticket-confirmation" class="confirm" phx-hook="WorkspaceDialog" data-close-event="cancel-risk" aria-labelledby="ticket-title">
      <div class="confirmation-layout">
        <header class="modal-head"><h2 id="ticket-title">Preview Azure DevOps ticket</h2></header>
        <div class="modal-body">
          <p>This will create a ticket in: <strong>{Triage.AzureDevOps.backlog()}</strong></p>
          <h3>{@row.cve} needs to be fixed</h3>
          <p>Team: {Triage.AzureDevOps.team()} (routed through the team's area path)</p>
          <div style="white-space: normal; overflow-wrap: anywhere; overflow: auto;">{Phoenix.HTML.raw(@ticket_description)}</div>
          <p :if={@error} role="alert">{@error}</p>
        </div>
        <footer class="modal-foot">
          <button phx-click="cancel-risk">Cancel</button>
          <button id="confirm-ticket" class="primary" phx-click="confirm-ticket" phx-disable-with="Creating…">Create ticket</button>
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
          <h2 id="settings-title">Data &amp; settings</h2>
        </header><div class="modal-body">
          <p>Local workspace · No sign-in · keep the service on loopback.</p><p>
            Operational inventory excludes public-reference records. Scan completeness and current production coverage are unverified.
          </p><p>
            Drafts survive navigation within this live connection, not reload or server restart. Local decisions are durable. Leaving this workspace may discard drafts.
          </p><p>
            Add CVE fetches a requested description from NVD. Opening News or choosing Refresh retrieves public CVEs and headlines. Research and news do not change affected inventory. Ticket creation requires Azure DevOps server configuration. Imports, replay and AI controls are not available in this workspace.
          </p>
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
      <span>{@total} CVEs · page {div(@offset, 50) + 1}</span><span class="row"><.link
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
end
