defmodule TriageWeb.WorkspaceComponents do
  @moduledoc "Approved workspace composition and one shared scope-aware inspector."
  use TriageWeb, :html
  alias Triage.Decisions
  alias TriageWeb.WorkspaceLive, as: Routes

  alias Triage.Workspace.Commit

  defp draft_status(%{saved: true}), do: "Decision saved"
  defp draft_status(%{dirty: false}), do: "No unsaved changes"
  defp draft_status(%{persisted: true}), do: "Draft saved to your account"
  defp draft_status(_draft), do: "Draft not saved. Keep this tab open."

  defp decision_blocker(%{draft: nil}), do: nil

  defp decision_blocker(assigns) do
    cond do
      not assigns.can_review ->
        "Reviewer access is required to make a decision."

      not is_nil(assigns.pending_operation) ->
        "A ticket operation is already pending. Wait for its result."

      assigns.draft_error ->
        "The draft could not be saved. Keep this tab open and retry."

      assigns.draft.stale ->
        "Evidence changed. Reload current evidence before continuing."

      assigns.hidden_targets != [] ->
        "Selected deployments are hidden. Restore the original scope to continue."

      assigns.draft.fields["action"] not in Commit.review_actions() ->
        "Choose one of the three actions in the Decision panel."

      assigns.draft.targets == [] ->
        "Select at least one deployment to enable this action."

      true ->
        nil
    end
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
  attr :ai_configured, :boolean, default: false
  attr :ai_assessing, :boolean, default: false
  attr :ai_assessment, :map, default: nil
  attr :ai_assessment_error, :string, default: nil
  attr :ai_rows, :map, default: %{}
  attr :classify_all, :map, default: nil
  attr :metrics, :map, default: %{}
  attr :search_form, :any, required: true

  def review(assigns) do
    assigns =
      assigns
      |> assign(:decision_blocker, decision_blocker(assigns))
      |> assign(
        :decision_error,
        assigns.error || (assigns.draft && assigns.draft[:persistence_error])
      )

    ~H"""
    <div class="review-topbar">
      <div class="review-tools">
        <nav class="triage-counts" aria-label="CVE lists">
          <.link
            :for={
              {mode, label} <- [
                {"needs", "Need a decision"},
                {"active", "Active CVEs"},
                {"accepted", "Whitelisted"}
              ]
            }
            id={"triage-count-#{mode}"}
            patch={Routes.drill(@params, mode)}
            class={["triage-count", @mode == mode && "active"]}
            aria-current={if @mode == mode, do: "page"}
          >
            <span class="triage-count-value">{count(@metrics, mode)}</span>
            <span class="triage-count-label">{label}</span>
          </.link>
        </nav>
        <span class="spacer" />
        <div class="classify-all">
          <button
            id="classify-all"
            type="button"
            phx-click="classify-all"
            disabled={not @ai_configured or not @can_review}
            title={
              cond do
                not @ai_configured ->
                  "AI classification is off. Connect Kiro to enable it."

                not @can_review ->
                  "Reviewer access is required to classify."

                true ->
                  "Classifies every critical CVE that needs a decision in this team and environment. Nothing is decided automatically."
              end
            }
          >
            <.icon name="hero-sparkles" class="size-4" /> Classify all critical with AI
          </button>
          <p :if={@classify_all} id="classify-all-result" class="classify-all-result" role="status">
            {classify_all_message(@classify_all)}
          </p>
        </div>
        <button
          id="review-queue-toggle"
          class="queue-toggle quiet"
          phx-click="queue-toggle"
          aria-expanded={to_string(@queue_shown)}
          aria-controls="review-queue"
        >{if @queue_shown, do: "Back to CVE", else: "Show list (#{@total})"}</button>
      </div>
    </div>
    <div class="review-grid">
      <section id="review-queue" class="panel queue-panel" aria-label="CVE list">
        <.form
          for={@search_form}
          id="triage-search"
          class="queue-search"
          phx-change="search"
          phx-submit="search"
        >
          <.input
            field={@search_form[:q]}
            type="search"
            placeholder="Search CVE or package"
            aria-label="Search CVEs"
            phx-debounce="250"
          />
        </.form>
        <div class="queue-heading">
          <strong>{@total} CVEs</strong><span>{list_label(@mode)}</span>
        </div>
        <div class="queue-list">
          <.link
            :for={row <- @rows}
            id={"queue-#{row.cve}"}
            class={[
              "queue-item",
              "sev-#{severity_key(row.severity)}",
              @row && @row.cve == row.cve && "active"
            ]}
            aria-current={if @row && @row.cve == row.cve, do: "true"}
            patch={Routes.workspace_path(@params, %{"item" => row.cve})}
          ><div class="queue-line">
            <span class="queue-id cve-id">{row.cve}</span><.severity value={row.severity} />
          </div><span class="queue-package" title={row.packages}>{row.packages}</span><span class="queue-meta">
            <.exposure_chip value={row_exposure(row.scopes)} /><span>{deployment_count(row.scopes)}</span><span :if={
              whitelisted_until(row)
            }>Until {whitelisted_until(row)}</span><span :if={
              is_nil(whitelisted_until(row)) and age(row.first_seen)
            }>{age(row.first_seen)}</span><.ai_row_state state={@ai_rows[row.cve]} />
          </span></.link>
          <p :if={@rows == []} class="empty">
            {if @params["q"] not in [nil, ""],
              do: "No CVEs match this search.",
              else: "Nothing in this list for the current team and environment."}
          </p>
        </div>
        <.pagination params={@params} offset={@offset} total={@total} />
      </section>
      <section
        :if={@row}
        id="workspace-review"
        class="panel review-workspace"
        aria-label="Selected CVE"
      >
        <header class={["review-heading", "sev-#{severity_key(@row.severity)}"]}>
          <div class="review-summary">
            <div class="review-title-row">
              <h2 class="cve-id">{@row.cve}</h2><.severity value={@row.severity} /><.saved_status scopes={
                @row.scopes
              } /><strong
                :if={whitelist_state(@row) == "Whitelisted"}
                class="whitelisted-banner status-pill"
              >Whitelisted{if whitelisted_until(@row), do: " until #{whitelisted_until(@row)}"}</strong>
            </div>
            <p class="subtitle">
              <span class="package-name">{@row.packages}</span><span>{deployment_count(@row.scopes)} in this scope</span><span :if={
                age(@row.first_seen)
              }>{age(@row.first_seen)}</span>
            </p>
          </div>
        </header>
        <.form
          for={@form}
          id="workspace-decision"
          phx-change="draft"
          phx-submit="save"
          class="review-content"
        >
          <div class="decision-column">
            <p :if={not @can_review} id="viewer-read-only" class="inline-notice">
              Read-only viewer. A reviewer or administrator must make decisions.
            </p>
            <h3 class="decision-title">Decision</h3>
            <fieldset id="decision-action" class="action-choice" disabled={not @can_review}>
              <legend class="sr-only">Action</legend>
              <label
                :for={
                  {value, label, hint} <- [
                    {"accepted_risk", "Whitelist", "Accept the risk until a date"},
                    {"fixed", "Mark as fixed", "The fix is deployed"},
                    {"create_ticket", "Create ticket", "Send to Azure DevOps"}
                  ]
                }
                id={"decision-action-#{value}"}
                class={["action-option", @draft.fields["action"] == value && "selected"]}
              >
                <input
                  type="radio"
                  name="decision[action]"
                  value={value}
                  checked={@draft.fields["action"] == value}
                />
                <span class="action-label">{label}</span>
                <span class="action-hint">{hint}</span>
              </label>
            </fieldset>
            <div :if={@draft.fields["action"] == "accepted_risk"} class="decision-fields">
              <.input
                field={@form[:reason]}
                disabled={not @can_review}
                type="textarea"
                label="Why is this safe to accept? (required)"
                maxlength="2000"
              />
              <.input
                field={@form[:due_on]}
                disabled={not @can_review}
                type="date"
                label="Whitelist until (UTC)"
                aria-describedby="whitelist-expiry-help"
              />
              <p id="whitelist-expiry-help" class="form-note">
                Defaults to three months. Afterwards the CVE needs a decision again.
              </p>
            </div>
            <p :if={@draft.fields["action"] == "create_ticket"} class="form-note">
              Creates an Azure DevOps ticket with the CVE and the selected deployments.
            </p>
            <p class="decision-targets">
              Applies to
              <a href="#review-deployments">
                {length(@draft.targets)} of {length(@row.scopes)} deployments
              </a>
            </p>
            <p :if={@decision_error} id="decision-error" role="alert" class="form-error">
              {@decision_error}
            </p>
            <div class="decision-bar" role="group" aria-label="Decision actions">
              <button
                :if={@can_review && (@decision_error || @draft.stale)}
                id="reload-evidence"
                type="button"
                phx-click="reconcile"
              >Reload current evidence</button>
              <div class="decision-buttons">
                <button
                  id="cancel-decision"
                  disabled={not @can_review or not is_nil(@pending_operation) or not @draft.dirty}
                  type="button"
                  phx-click="cancel-decision"
                >Discard</button>
                <button
                  id="save-decision"
                  class="primary"
                  type="submit"
                  phx-disable-with="Working…"
                  disabled={not is_nil(@decision_blocker)}
                  aria-describedby={if @decision_blocker, do: "decision-action-help"}
                  title={@decision_blocker}
                >{case @draft.fields["action"] do
                  "fixed" -> "Mark as fixed"
                  "accepted_risk" -> "Whitelist"
                  "create_ticket" -> "Create ticket"
                  _ -> "Choose an action"
                end}</button>
              </div>
              <p
                :if={@decision_blocker}
                id="decision-action-help"
                class="decision-action-help"
                role="status"
              >
                {@decision_blocker}
                <a
                  :if={
                    @can_review and @draft.targets == [] and
                      @draft.fields["action"] in Commit.review_actions()
                  }
                  href="#review-deployments"
                >Select deployments</a>
              </p>
              <span id="draft-state" class="save-state">{draft_status(@draft)}</span>
            </div>
          </div>
          <div class="evidence-column">
            <section id="cve-description" class="triage-section" aria-labelledby="description-title">
              <h3 id="description-title">Description</h3>
              <p class="summary-copy long-value">{description(@row)}</p>
              <dl class="reported-fix">
                <dt>Fixed in</dt><dd>{reported_fixes(@row)}</dd>
              </dl>
            </section>
            <section
              id="review-deployments"
              class="triage-section"
              tabindex="-1"
              aria-labelledby="infrastructure-title"
            >
              <div class="block-title">
                <h3 id="infrastructure-title">Your infrastructure</h3><span>{exposure_summary(
                  @row.scopes
                )}</span>
              </div>
              <p :if={@hidden_targets != []} class="form-error">
                {length(@hidden_targets)} selected deployments are hidden by this team or environment. Restore the original scope; the selection has not changed.
              </p>
              <.scope_table
                targets={@row.scopes}
                selected={@draft.targets}
                selectable={@can_review}
                focus_target={@params["focus_target"]}
                row_id_prefix="review-target"
              />
              <p class="coverage-note">
                External deployments are reachable from the internet; internal ones are not. Tick the deployments your decision applies to.
              </p>
            </section>
            <.ai_triage_panel
              cve={@row.cve}
              can_review={@can_review}
              configured={@ai_configured}
              assessing={@ai_assessing}
              assessment={@ai_assessment}
              error={@ai_assessment_error}
            />
            <details id="decision-history-section">
              <summary>Decision history</summary>
              <.history_entries history={@history} />
            </details>
          </div>
        </.form>
      </section>
      <section :if={is_nil(@row)} class="panel review-workspace">
        <div class="empty">
          <h2>No CVE selected</h2><p>
            Pick a CVE from the list. Nothing here matches the current team, environment or search.
          </p>
        </div>
      </section>
    </div>
    """
  end

  defp count(metrics, mode) do
    case metrics[mode] do
      %{value: value} when is_integer(value) -> value
      _ -> 0
    end
  end

  defp list_label("active"), do: "all active"
  defp list_label("accepted"), do: "whitelisted"
  defp list_label(_mode), do: "need a decision"

  defp classify_all_message(%{error: message}), do: message

  defp classify_all_message(%{queued: 0, current: 0, skipped: 0}),
    do: "No critical CVEs need a decision in this team and environment."

  defp classify_all_message(counts) do
    [
      counts.queued > 0 &&
        "#{counts.queued} critical CVEs queued. Results appear in the list as they finish.",
      counts.current > 0 && "#{counts.current} already have a current result.",
      counts.skipped > 0 &&
        "#{counts.skipped} could not be classified; narrow the team or environment and retry."
    ]
    |> Enum.filter(&is_binary/1)
    |> Enum.join(" ")
  end

  attr :state, :any, default: nil

  defp ai_row_state(%{state: nil} = assigns), do: ~H""

  defp ai_row_state(%{state: :classifying} = assigns) do
    ~H"""
    <span class="ai-row-state classifying">AI classifying…</span>
    """
  end

  defp ai_row_state(%{state: %{"danger_score" => score, "danger_level" => level}} = assigns)
       when is_integer(score) do
    assigns = assign(assigns, score: score, level: level)

    ~H"""
    <span class={["ai-row-state", "level-#{@level}"]} title="Latest AI risk score in this scope">AI risk {@score}</span>
    """
  end

  defp ai_row_state(assigns), do: ~H""

  attr :value, :string, required: true

  def exposure_chip(assigns) do
    ~H"""
    <span class={["exposure-chip", "exposure-#{@value}"]}>{exposure(@value)}</span>
    """
  end

  # Row summary: external when any active deployment is internet-facing,
  # internal only when every active deployment is known to be internal.
  defp row_exposure(scopes) do
    exposures = scopes |> Enum.filter(& &1.active?) |> Enum.map(& &1.exposure) |> Enum.uniq()

    cond do
      "internet_exposed" in exposures -> "internet_exposed"
      exposures == ["internal"] -> "internal"
      true -> "unknown"
    end
  end

  defp exposure_summary(scopes) do
    active = Enum.filter(scopes, & &1.active?)
    external = Enum.count(active, &(&1.exposure == "internet_exposed"))
    internal = Enum.count(active, &(&1.exposure == "internal"))
    unknown = length(active) - external - internal

    [
      external > 0 && "#{external} external",
      internal > 0 && "#{internal} internal",
      unknown > 0 && "#{unknown} unknown"
    ]
    |> Enum.filter(&is_binary/1)
    |> Enum.join(" · ")
  end

  # Earliest expiry among the active whitelisted deployments.
  defp whitelisted_until(row) do
    row.scopes
    |> Enum.filter(
      &(&1.active? and &1.covered? and &1.decision.decision == "accepted_risk" and
          not is_nil(&1.decision.expires_at))
    )
    |> Enum.map(& &1.decision.expires_at)
    |> Enum.min(DateTime, fn -> nil end)
    |> case do
      nil -> nil
      expires_at -> Calendar.strftime(expires_at, "%d %b %Y")
    end
  end

  defp severity_key(severity) when is_binary(severity), do: String.downcase(severity)
  defp severity_key(_severity), do: "unknown"

  defp deployment_count([_one]), do: "1 deployment"
  defp deployment_count(scopes), do: "#{length(scopes)} deployments"

  defp age(nil), do: nil

  defp age(first_seen) do
    case DateTime.diff(DateTime.utc_now(), first_seen, :day) do
      days when days < 1 -> "New today"
      days -> "#{days}d open"
    end
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
  attr :focus_target, :string, default: nil
  attr :row_id_prefix, :string, default: nil

  def scope_table(assigns) do
    ~H"""
    <div class="table-wrap">
      <table class="scope-table">
        <thead>
          <tr>
            <th :if={@selectable}><span class="sr-only">Select</span></th><th>Exposure</th><th>
              Team / environment
            </th><th>Service</th><th>Package</th><th>Status</th>
          </tr>
        </thead><tbody>
          <tr
            :for={scope <- @targets}
            id={@row_id_prefix && "#{@row_id_prefix}-#{scope.id}"}
            data-target-id={scope.id}
            class={to_string(scope.id) == @focus_target && "focused-target"}
            aria-current={if to_string(scope.id) == @focus_target, do: "true"}
            tabindex={if to_string(scope.id) == @focus_target, do: "-1"}
          >
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
            <td><.exposure_chip value={scope.exposure} /></td>
            <td>
              <strong>{team_name(scope.placement.owner)}</strong><span class="subline">{scope.placement.environment}</span>
            </td><td>
              {scope.image.repository}<span class="subline">{scope.placement.namespace} · deployment {scope.id}</span>
            </td><td>
              <span
                :for={f <- Enum.uniq_by(scope.findings, &{&1.package_name, &1.package_version})}
                class="package-line"
              >
                {f.package_name} {f.package_version}
              </span>
            </td><td>{work_status([scope])}</td>
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
          <strong>{@row.cve}: {length(@draft.targets)} selected deployments</strong><.scope_table targets={
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
                Drafts survive reloads and server restarts. A draft is not a decision: use the action button to commit it. Discard only clears the current draft.
              </dd>
            </div>
            <div>
              <dt>Changed evidence needs another look</dt><dd>
                If another reviewer changes the same CVE, your draft is preserved. Reload the evidence before saving.
              </dd>
            </div>
            <div>
              <dt>AI classification only advises</dt><dd>
                Classify with AI scores one CVE; Classify all critical with AI queues every critical CVE that needs a decision in the current team and environment. Results never whitelist, fix or ticket anything.
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

  def exposure("internet_exposed"), do: "External"
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
        "fixed" -> "Reported fix (unverified)"
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
  @doc "Inline Kiro classification. Scores are model assessments, not authorization."
  attr :cve, :string, required: true
  attr :can_review, :boolean, default: false
  attr :configured, :boolean, default: false
  attr :assessing, :boolean, default: false
  attr :assessment, :map, default: nil
  attr :error, :string, default: nil

  def ai_triage_panel(%{configured: false} = assigns) do
    ~H"""
    <section id="ai-triage" class="review-classification is-off" aria-label="Kiro classification">
      <div class="classification-off">
        <span class="classification-off-title">AI classification is off</span>
        <details id="classification-setup" class="classification-setup">
          <summary>Connect Kiro to enable classification</summary>
          <p>
            Set <code>TRIAGE_ANALYSIS_ENABLED=true</code>
            and <code>TRIAGE_KIRO_CLI</code>
            to your authenticated Kiro executable, then restart Phoenix. No model API key is required by this app.
          </p>
        </details>
        <button id="classify-now" type="button" class="ai-analyze-btn" disabled>
          Classify with AI
        </button>
      </div>
    </section>
    """
  end

  def ai_triage_panel(assigns) do
    ~H"""
    <section
      id="ai-triage"
      class="review-classification"
      aria-label="Kiro classification"
      aria-busy={to_string(@assessing)}
    >
      <div class="classification-heading">
        <h3>AI classification</h3>
        <button
          id="classify-now"
          type="button"
          phx-click="classify-now"
          class="ai-analyze-btn"
          disabled={not @can_review or @assessing}
        >
          <.icon name="hero-sparkles" class="size-4" />
          {if @assessing, do: "Classifying…", else: "Classify with AI"}
        </button>
      </div>
      <p class="classification-scope">
        Covers every deployment of {@cve} in the current team and environment.
      </p>
      <p :if={not @can_review} class="form-note">
        Reviewer access is required to start classification.
      </p>
      <div :if={@assessing} class="ai-assessing" role="status" aria-live="polite">
        <span class="spinner" aria-hidden="true"></span>
        Kiro is classifying the evidence. You can leave this page; the result is saved.
      </div>
      <div :if={@error} class="ai-error form-error" role="alert">{@error}</div>
      <div :if={is_nil(@assessment) and not @assessing} class="classification-empty">
        <span>No current classification</span><p>
          Run Kiro to get scored guidance before making your decision.
        </p>
      </div>
      <div :if={@assessment} class="ai-result" id="classification-result">
        <div class="classification-scores">
          <div class="classification-score-card" id="classification-risk">
            <span class="classification-score-label">Risk score</span>
            <div class="classification-score-number">
              <strong class={"level-" <> @assessment["danger_level"]}>{@assessment["danger_score"]}</strong><span>/100</span>
            </div>
            <meter
              min="0"
              max="100"
              low="40"
              high="70"
              optimum="0"
              value={@assessment["danger_score"]}
              aria-label="Kiro risk score"
            />
            <span class="classification-score-help">{String.capitalize(@assessment["danger_level"])} · higher is riskier</span>
          </div>
          <div class="classification-score-card" id="classification-whitelist">
            <span class="classification-score-label">Whitelist suitability</span>
            <div class="classification-score-number">
              <strong>{if is_integer(@assessment["whitelist_score"]),
                do: @assessment["whitelist_score"],
                else: "—"}</strong><span :if={is_integer(@assessment["whitelist_score"])}>/100</span>
            </div>
            <meter
              :if={is_integer(@assessment["whitelist_score"])}
              min="0"
              max="100"
              low="40"
              high="70"
              optimum="100"
              value={@assessment["whitelist_score"]}
              aria-label="Kiro whitelist suitability"
            />
            <span class="classification-score-help">{if is_integer(@assessment["whitelist_score"]),
              do: "Higher means stronger support",
              else: "Blocked · verification required"}</span>
          </div>
        </div>
        <p class="classification-recommendation">
          {ai_recommendation_label(@assessment["recommendation"])}
        </p>
        <p class="classification-rationale">
          {String.slice(@assessment["rationale"], 0, 360)}<span :if={
            String.length(@assessment["rationale"]) > 360
          }>…</span>
        </p>
        <details :if={String.length(@assessment["rationale"]) > 360} class="classification-reasoning">
          <summary>Read full Kiro reasoning</summary>
          <p class="classification-rationale">{@assessment["rationale"]}</p>
        </details>
        <div :if={@assessment["guard_reasons"] != []} id="classification-guards" class="inline-notice">
          <p :for={reason <- @assessment["guard_reasons"]}>{reason}</p>
          <small>Kiro's original suitability score: {@assessment["raw_whitelist_score"]}/100. It is not accepted as a whitelist recommendation.</small>
        </div>
        <p class="classification-timestamp">
          Scored by Kiro ·
          <time datetime={@assessment["assessed_at"]}>{@assessment["assessed_at"]}</time>
        </p>
      </div>
      <details class="classification-disclosure">
        <summary>What is sent to Kiro?</summary>
        <p>
          The CVE's complete stored findings and descriptions, packages, fixes, images, deployments, exposure, intelligence and existing decisions in this scope. No draft, login token or application credentials. Kiro has no action tools.
        </p>
      </details>
      <p class="classification-footnote">
        AI guidance, not a probability or approval. Classification does not approve, whitelist, or commit anything.
      </p>
    </section>
    """
  end

  defp ai_recommendation_label("investigate"), do: "Investigate this CVE"
  defp ai_recommendation_label("remediate"), do: "Remediate (schedule a fix)"

  defp ai_recommendation_label("suggest_risk_acceptance"),
    do: "Whitelist candidate (review before accepting)"

  defp ai_recommendation_label("request_verification"), do: "Request verification"
  defp ai_recommendation_label(_), do: "Investigate this CVE"

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
