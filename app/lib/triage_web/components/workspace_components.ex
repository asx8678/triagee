defmodule TriageWeb.WorkspaceComponents do
  @moduledoc "Approved workspace composition and one shared scope-aware inspector."
  use TriageWeb, :html
  alias Triage.Decisions
  alias TriageWeb.WorkspaceLive, as: Routes

  alias Triage.Workspace.Commit

  defp draft_status(%{saved: true}), do: "Decision saved"
  defp draft_status(%{dirty: false}), do: "No unsaved changes"
  defp draft_status(%{persisted: true}), do: "Draft saved to your account"
  defp draft_status(_draft), do: "Draft not saved yet. Keep this tab open."

  # Everything still missing before the decision can be saved, in form order.
  # The action button stays disabled until the list is empty, so a click never
  # ends in a validation error.
  defp decision_blockers(%{draft: nil}), do: []

  defp decision_blockers(assigns) do
    case state_blocker(assigns) do
      nil -> missing_fields(assigns.draft)
      message -> [{:other, message}]
    end
  end

  # A state that rules out any decision until it is resolved.
  defp state_blocker(assigns) do
    cond do
      not assigns.can_review ->
        "Reviewer access is required to make a decision."

      not is_nil(assigns.pending_operation) ->
        "A ticket request for this CVE is still open. Check it before deciding again."

      assigns.draft_error ->
        "Your draft could not be saved. Keep this tab open and try again."

      assigns.draft.stale ->
        "This CVE changed after you started. Reload it before continuing."

      assigns.hidden_targets != [] ->
        "Some ticked deployments are hidden by the team or environment filter. Clear the filter to continue."

      true ->
        action_blocker(assigns.draft.fields["action"], assigns.ticket_ready)
    end
  end

  defp action_blocker("create_ticket", false),
    do: "Azure DevOps is not configured on this server, so a ticket cannot be created yet."

  defp action_blocker(action, _ticket_ready) do
    if action in Commit.review_actions(),
      do: nil,
      else: "Choose Create ticket, Mark as fixed or Whitelist."
  end

  @doc "Whether the server can create Azure DevOps tickets right now."
  def ticket_ready?, do: match?({:ok, _destination}, Triage.AzureDevOps.destination())

  defp missing_fields(%{targets: targets, fields: fields}) do
    whitelist? = fields["action"] == "accepted_risk"

    [
      targets == [] && {:targets, "Tick at least one deployment."},
      (whitelist? and String.length(String.trim(fields["reason"] || "")) < 3) &&
        {:reason, "Write why this is safe to accept."},
      (whitelist? and past_date?(fields["due_on"])) && {:date, "Pick today or a later date."}
    ]
    |> Enum.filter(& &1)
  end

  defp past_date?(value) do
    case Date.from_iso8601(value || "") do
      {:ok, date} -> Date.compare(date, Date.utc_today()) == :lt
      _ -> false
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
    assigns = assign(assigns, :ticket_ready, ticket_ready?())

    assigns =
      assigns
      |> assign(:decision_blockers, decision_blockers(assigns))
      |> assign(
        :decision_error,
        assigns.error || (assigns.draft && assigns.draft[:persistence_error])
      )
      |> assign(:searching, assigns.params["q"] not in [nil, ""])

    ~H"""
    <div class="review-toolbar">
      <nav class="list-tabs" aria-label="CVE lists">
        <.link
          :for={
            {mode, label} <- [
              {"needs", "Need a decision"},
              {"accepted", "Whitelisted"},
              {"active", "All active"}
            ]
          }
          id={"triage-count-#{mode}"}
          patch={Routes.drill(@params, mode)}
          class={["list-tab", @mode == mode && "active"]}
          aria-current={if @mode == mode, do: "page"}
        >
          {label}<span class="list-tab-count">{count(@metrics, mode)}</span>
        </.link>
      </nav>
      <button
        id="whitelist-overview-open"
        type="button"
        class="whitelist-open"
        phx-click="repo-whitelist"
        title="What is whitelisted and until when, in the repository list and in Triage."
      >
        Whitelist overview
      </button>
      <div :if={@ai_configured and @can_review} class="classify-all">
        <button
          id="classify-all"
          type="button"
          phx-click="classify-all"
          title="Classifies every critical CVE that needs a decision in this team and environment. Nothing is decided automatically."
        >
          <.icon name="hero-sparkles" class="size-4" /> Classify all critical with AI
        </button>
        <p :if={@classify_all} id="classify-all-result" class="classify-all-result" role="status">
          {classify_all_message(@classify_all)}
        </p>
      </div>
      <button
        id="review-queue-toggle"
        type="button"
        class="queue-toggle quiet"
        phx-click="queue-toggle"
        aria-expanded={to_string(@queue_shown)}
        aria-controls="review-queue"
      >{if @queue_shown, do: "Back to CVE", else: "Show list"}</button>
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
        <p :if={@mode == "active"} class="queue-heading">
          Includes whitelisted and in-progress CVEs.
        </p>
        <p class="sr-only">Use the up and down arrow keys to move between CVEs.</p>
        <div id="queue-list" class="queue-list" phx-hook="QueueKeys">
          <.link
            :for={{row, index} <- Enum.with_index(@rows)}
            id={"queue-#{row.cve}"}
            class={["queue-item", @row && @row.cve == row.cve && "active"]}
            aria-current={if @row && @row.cve == row.cve, do: "true"}
            tabindex={queue_tabindex(row, index, @rows, @row)}
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
          <div :if={@rows == []} class="empty">
            <p>
              {if @searching,
                do: "No CVEs match “#{@params["q"]}”.",
                else: "Nothing in this list for the current team and environment."}
            </p>
            <.link
              :if={@searching}
              id="clear-search"
              patch={Routes.workspace_path(@params, %{"q" => nil, "offset" => nil, "item" => nil})}
            >Clear search</.link>
          </div>
        </div>
        <.pagination :if={@total > 0} params={@params} offset={@offset} total={@total} />
      </section>
      <section
        :if={@row}
        id="workspace-review"
        class="panel review-workspace"
        aria-label="Selected CVE"
      >
        <header class="review-heading">
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
          <div class="evidence-column">
            <section id="cve-description" class="triage-section" aria-labelledby="description-title">
              <h3 id="description-title">Description</h3>
              <p class="summary-copy long-value">{description(@row)}</p>
              <dl class="reported-fix">
                <div :if={installed_packages(@row.scopes)}>
                  <dt>Installed</dt><dd>{installed_packages(@row.scopes)}</dd>
                </div>
                <div>
                  <dt>Fixed in</dt><dd>{reported_fixes(@row)}</dd>
                </div>
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
              <p :if={@can_review} class="table-instruction">
                Tick the deployments your decision applies to.
              </p>
              <p :if={@hidden_targets != []} class="form-error">
                {length(@hidden_targets)} ticked deployments are hidden by the team or environment filter. Clear the filter to see them; they are still ticked.
              </p>
              <.scope_table
                targets={@row.scopes}
                selected={@draft.targets}
                selectable={@can_review}
                focus_target={@params["focus_target"]}
                row_id_prefix="review-target"
              />
              <p class="coverage-note">
                External deployments are reachable from the internet; internal ones are not.
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
          <div class="decision-column">
            <p :if={not @can_review} id="viewer-read-only" class="inline-notice">
              Read-only viewer. A reviewer or administrator must make decisions.
            </p>
            <.current_decision scopes={@row.scopes} />
            <h3 class="decision-title">
              {if current_decisions(@row.scopes) == [], do: "Decision", else: "Change decision"}
            </h3>
            <fieldset id="decision-action" class="action-choice" disabled={not @can_review}>
              <legend class="sr-only">Action</legend>
              <label
                :for={
                  {value, label, hint} <- [
                    {"create_ticket", "Create ticket",
                     if(@ticket_ready, do: "Send to Azure DevOps", else: "Azure DevOps is not set up")},
                    {"fixed", "Mark as fixed", "The fix is deployed"},
                    {"accepted_risk", "Whitelist", "Accept the risk until a date"}
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
                phx-debounce="250"
              />
              <.input
                field={@form[:due_on]}
                disabled={not @can_review}
                type="date"
                label="Whitelist until (UTC)"
                aria-describedby="whitelist-expiry-help"
                phx-debounce="250"
              />
              <p id="whitelist-expiry-help" class="form-note">
                {expiry_note(@draft.fields["due_on"])}
              </p>
            </div>
            <p :if={@draft.fields["action"] == "create_ticket" and @ticket_ready} class="form-note">
              Creates an Azure DevOps ticket with the CVE and the ticked deployments.
            </p>
            <p
              :if={@draft.fields["action"] == "create_ticket" and not @ticket_ready}
              id="ticket-not-configured"
              class="inline-notice"
            >
              Tickets are off until an administrator sets <code>ADO_ORG_URL</code>, <code>ADO_PROJECT</code>,
              <code>ADO_PAT</code>
              and <code>ADO_WORK_ITEM_TYPE</code>
              on the server and restarts it.
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
              >Reload this CVE</button>
              <p class="decision-targets">
                Applies to
                <a href="#review-deployments">
                  {length(@draft.targets)} of {deployment_count(@row.scopes)}
                </a>
              </p>
              <button
                id="save-decision"
                class="primary"
                type="submit"
                phx-disable-with="Working…"
                disabled={@decision_blockers != []}
                aria-describedby={if @decision_blockers != [], do: "decision-action-help"}
              >{case @draft.fields["action"] do
                "fixed" -> "Mark as fixed"
                "accepted_risk" -> "Whitelist"
                "create_ticket" -> "Create ticket"
                _ -> "Choose an action"
              end}</button>
              <div
                :if={@decision_blockers != []}
                id="decision-action-help"
                class="decision-action-help"
                role="status"
              >
                <p :for={{kind, text} <- @decision_blockers}>
                  {text}
                  <a :if={kind == :targets} href="#review-deployments">Show deployments</a>
                </p>
              </div>
              <div class="decision-foot">
                <span id="draft-state" class="save-state">{draft_status(@draft)}</span>
                <button
                  id="cancel-decision"
                  class="link"
                  disabled={not @can_review or not is_nil(@pending_operation) or not @draft.dirty}
                  type="button"
                  phx-click="cancel-decision"
                  data-confirm="Discard this draft? The action, reason and ticked deployments are cleared."
                >Discard draft</button>
              </div>
            </div>
          </div>
        </.form>
      </section>
      <section :if={is_nil(@row)} class="panel review-workspace">
        <div class="empty">
          <%= cond do %>
            <% @rows != [] -> %>
              <h2>No CVE selected</h2>
              <p>Pick a CVE from the list.</p>
            <% @searching -> %>
              <h2>No CVEs match “{@params["q"]}”</h2>
              <p>
                Search looks at CVE IDs and package names in the current team and environment.
                <.link patch={
                  Routes.workspace_path(@params, %{"q" => nil, "offset" => nil, "item" => nil})
                }>
                  Clear search
                </.link>
              </p>
            <% true -> %>
              <h2>Nothing to review here</h2>
              <p>No CVEs in this list match the current team and environment.</p>
          <% end %>
        </div>
      </section>
    </div>
    """
  end

  # The list is one Tab stop: the open CVE (or the first row) takes focus and
  # the QueueKeys hook moves between rows with the arrow keys.
  defp queue_tabindex(row, index, rows, selected) do
    focus =
      if selected && Enum.any?(rows, &(&1.cve == selected.cve)),
        do: row.cve == selected.cve,
        else: index == 0

    if focus, do: "0", else: "-1"
  end

  defp expiry_note(due_on) do
    case Date.from_iso8601(due_on || "") do
      {:ok, date} -> "Needs a decision again after #{format_date(date)}."
      _ -> "Defaults to three months, then it needs a decision again."
    end
  end

  @doc "A calendar date as shown everywhere in the workspace: 30 Dec 2026."
  def format_date(date), do: Calendar.strftime(date, "%d %b %Y")

  defp due_date(value) do
    case Date.from_iso8601(value || "") do
      {:ok, date} -> format_date(date)
      _ -> value
    end
  end

  defp count(metrics, mode) do
    case metrics[mode] do
      %{value: value} when is_integer(value) -> value
      _ -> 0
    end
  end

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

  # Earliest expiry among the active whitelisted deployments, as the last day
  # the whitelist still applies (the date picked in the form).
  defp whitelisted_until(row) do
    row.scopes
    |> Enum.filter(
      &(&1.active? and &1.covered? and &1.decision.decision == "accepted_risk" and
          not is_nil(&1.decision.expires_at))
    )
    |> Enum.map(& &1.decision.expires_at)
    |> Enum.min(DateTime, fn -> nil end)
    |> last_valid_day()
  end

  # A whitelist expires at the start of its `expires_at`, so the last day it
  # applies is the day before a midnight expiry.
  defp last_valid_day(nil), do: nil
  defp last_valid_day(expires_at), do: expires_at |> DateTime.add(-1, :second) |> format_date()

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

  defp package_lines(scope),
    do:
      scope.findings
      |> Enum.map(&{&1.package_name, &1.package_version})
      |> Enum.uniq()
      |> Enum.sort()

  # The package versions every deployment shares, or nil when they differ. The
  # deployments table shows a Package column only when they differ.
  defp uniform_packages(scopes) do
    case scopes |> Enum.map(&package_lines/1) |> Enum.uniq() do
      [[_ | _] = lines] -> lines
      _ -> nil
    end
  end

  defp installed_packages(scopes) do
    case uniform_packages(scopes) do
      nil -> nil
      lines -> Enum.map_join(lines, ", ", fn {name, version} -> "#{name} #{version}" end)
    end
  end

  # Image paths may break after a slash, never inside a name.
  defp path_parts(path) do
    parts = String.split(path || "", "/")
    Enum.map(Enum.drop(parts, -1), &(&1 <> "/")) ++ [List.last(parts)]
  end

  attr :targets, :list, required: true
  attr :selected, :list, default: []
  attr :selectable, :boolean, default: false
  attr :focus_target, :string, default: nil
  attr :row_id_prefix, :string, default: nil

  def scope_table(assigns) do
    assigns = assign(assigns, :show_packages, is_nil(uniform_packages(assigns.targets)))

    ~H"""
    <div class="table-wrap">
      <table class="scope-table">
        <thead>
          <tr>
            <th :if={@selectable}><span class="sr-only">Select</span></th><th>Exposure</th><th>
              Team / environment
            </th><th>Service</th><th :if={@show_packages}>Package</th><th>Status</th>
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
                aria-label={"Select #{team_name(scope.placement.owner)}, #{scope.placement.environment}, #{scope.placement.namespace} (#{scope.image.repository})"}
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
              <span :for={part <- path_parts(scope.image.repository)}>{part}<wbr /></span><span class="subline">{scope.placement.namespace}</span>
            </td><td :if={@show_packages}>
              <span :for={{name, version} <- package_lines(scope)} class="package-line">
                {name} {version}
              </span>
            </td><td class="status-cell">{work_status([scope])}</td>
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
          <h2 id="risk-title">Whitelist {@row.cve}?</h2>
        </header><div class="modal-body">
          <strong>{deployment_count(Enum.filter(@row.scopes, &(&1.id in @draft.targets)))}</strong><.scope_table targets={
            Enum.filter(@row.scopes, &(&1.id in @draft.targets))
          } /><p><strong>Reason:</strong> {@draft.fields["reason"]}</p><p>
            Whitelisted through {due_date(@draft.fields["due_on"])} (UTC). After that the CVE needs a decision again.
          </p><p>This doesn't mark the CVE as fixed or create a ticket.</p>
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

    destination =
      case Triage.AzureDevOps.destination() do
        {:ok, destination} -> destination
        {:error, _message} -> nil
      end

    assigns =
      assign(assigns,
        ticket_description: Enum.find(payload, &(&1.path == "/fields/System.Description")).value,
        destination: destination,
        labels: Triage.AzureDevOps.display_labels()
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
          <p :if={@destination}>
            This will create a <strong>{@destination["type"]}</strong>
            in the Azure DevOps project <strong>{@destination["project"]}</strong>.
          </p>
          <p :if={is_nil(@destination)} role="alert" class="form-error">
            Azure DevOps is not configured on this server, so this ticket cannot be created.
          </p>
          <p :if={@labels.backlog}>Backlog: {@labels.backlog}</p>
          <p :if={@labels.team}>Team: {@labels.team}</p>
          <h3>{@row.cve} needs to be fixed</h3>
          <div class="ticket-preview">
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
                Drafts are saved as you work and survive reloads and server restarts. A draft is not a decision: use the action button to save it. Discard draft only clears the draft.
              </dd>
            </div>
            <div>
              <dt>Changed evidence needs another look</dt><dd>
                If another reviewer changes the same CVE, your draft is kept. Reload the CVE before saving.
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
        "create_ticket" -> "Ticket created"
        "needs" -> "Needs decision"
        "mixed" -> "Mixed statuses"
        _ -> "In progress"
      end

    assigns = assign(assigns, state: state, label: label)

    ~H"""
    <span :if={@state != "accepted_risk"} class={"badge saved-status status-#{@state}"}>{@label}</span>
    """
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
    do: "All deployments (recorded before decisions were made per deployment)"

  def history_scope(d) do
    target = d.metadata["target"] || %{}

    [
      if(target["team"], do: team_name(target["team"]), else: "Unknown team"),
      target["environment"] || "unknown environment",
      target["namespace"]
    ]
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.join(" · ")
  end

  defp history_state(:active), do: "in effect"
  defp history_state(:expired), do: "expired"
  defp history_state(:pending), do: "scheduled"
  defp history_state(state), do: to_string(state)

  # The recorded decisions that cover this CVE's active deployments now,
  # grouped so one whitelist across several deployments reads as one line.
  defp current_decisions(scopes) do
    active = Enum.filter(scopes, & &1.active?)

    active
    |> Enum.filter(& &1.covered?)
    |> Enum.group_by(&{&1.decision.decision, &1.decision.reason, &1.decision.actor})
    |> Enum.map(fn {{decision, reason, actor}, covered} ->
      %{
        label: Decisions.label(decision),
        reason: reason,
        actor: actor,
        decided_at: covered |> Enum.map(& &1.decision.decided_at) |> Enum.max(DateTime),
        until:
          if(decision == "accepted_risk",
            do:
              covered
              |> Enum.map(& &1.decision.expires_at)
              |> Enum.reject(&is_nil/1)
              |> Enum.min(DateTime, fn -> nil end)
              |> last_valid_day()
          ),
        count: length(covered),
        total: length(active)
      }
    end)
    |> Enum.sort_by(& &1.decided_at, {:desc, DateTime})
  end

  attr :scopes, :list, required: true

  # What is already decided, so a reviewer sees an existing whitelist or ticket
  # before choosing again.
  defp current_decision(assigns) do
    assigns = assign(assigns, :decisions, current_decisions(assigns.scopes))

    ~H"""
    <section :if={@decisions != []} id="current-decision" class="current-decision">
      <h3 class="decision-title">Current decision</h3>
      <div :for={d <- @decisions} class="current-decision-item">
        <p>
          <strong>{d.label}{if d.until, do: " until #{d.until}"}</strong>
          · {d.count} of {d.total} {if d.total == 1, do: "deployment", else: "deployments"}
        </p>
        <p :if={d.reason not in [nil, ""]} class="current-decision-reason">{d.reason}</p>
        <p class="current-decision-meta">
          By {d.actor || "an unknown reviewer"} on {format_date(d.decided_at)}
        </p>
      </div>
    </section>
    """
  end

  @doc "Inline Kiro classification. Scores are model assessments, not authorization."
  attr :cve, :string, required: true
  attr :can_review, :boolean, default: false
  attr :configured, :boolean, default: false
  attr :assessing, :boolean, default: false
  attr :assessment, :map, default: nil
  attr :error, :string, default: nil

  def ai_triage_panel(%{configured: false} = assigns) do
    ~H"""
    <section id="ai-triage" class="review-classification is-off" aria-label="AI classification">
      <div class="classification-off">
        <span class="classification-off-title">AI classification is off.</span>
        <details id="classification-setup" class="classification-setup">
          <summary>How to turn it on</summary>
          <p>
            Set <code>TRIAGE_ANALYSIS_ENABLED=true</code>
            and <code>TRIAGE_KIRO_CLI</code>
            to your authenticated Kiro executable, then restart Phoenix. No model API key is required by this app.
          </p>
        </details>
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
  The CVE's append-only decision history. Exact deployment, reviewer, reason
  and ticket links stay explicit.
  """
  def history_entries(assigns) do
    ~H"""
    <article :for={d <- @history} id={"decision-history-#{d.id}"} class="history-entry">
      <time>{time(d.decided_at)}</time><div>
        <strong>{d.label} · {history_state(d.state)}</strong><p>{history_scope(d)}</p><p :if={d.actor}>
          By {d.actor}
        </p><p>
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
    </article><p :if={@history == []}>No decisions recorded for these deployments yet.</p>
    """
  end
end
