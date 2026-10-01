defmodule TriageWeb.WorkspaceLive do
  @moduledoc """
  Primary workspace over real inventory and advisory decisions.

  Two pages: Triage (the CVE list and one CVE's decision) and Timeline. This
  LiveView owns routing, shared state (drafts, confirmations) and the page
  shell. Page behaviour lives in plain modules it delegates to: `Params` (URLs)
  and `Review` (drafts, decisions, tickets, classification). They are not
  LiveComponents, so every event still passes `TriageWeb.Auth`'s per-event
  authorization hook.
  """
  use TriageWeb, :live_view
  alias Triage.Workspace
  alias TriageWeb.{TimelineFilters, TimelineLive}
  alias TriageWeb.WorkspaceLive.{Params, Review}
  import TriageWeb.WorkspaceComponents
  import Params, only: [nav_active?: 2]

  # Pages that list no workspace CVEs: they need only the nav count and scope options.
  @summary_pages ~w(daily timeline statistics)

  @impl true
  def mount(_params, _session, socket) do
    socket = TimelineLive.initialize(socket)

    if connected?(socket) do
      Phoenix.PubSub.subscribe(Triage.PubSub, "workspace:changes")
      Phoenix.PubSub.subscribe(Triage.PubSub, "review:classification")
    end

    {:ok,
     assign(socket,
       page_title: "Triage",
       demo_mode: Application.get_env(:triage, :demo_mode, false),
       drafts: %{},
       stale_cves: MapSet.new(),
       draft_error: false,
       pending_operation: nil,
       ticket_evidence: nil,
       confirmation: nil,
       error: nil,
       message: nil,
       action_toast: nil,
       queue_shown: false,
       settings: false,
       daily_before: nil,
       daily_data: nil,
       ai_assessing: false,
       ai_assessment: nil,
       ai_assessment_error: nil,
       ai_rows: %{},
       classify_all: nil,
       classification_tick: false,
       statistics: nil,
       repo_whitelist: nil
     )}
  end

  @impl true
  def handle_params(params, uri, socket) do
    raw_params = params
    timeline? = URI.parse(uri).path == "/timeline" or params["page"] == "timeline"
    invalid_params = not Params.valid_params?(raw_params)

    timeline_params =
      if Map.has_key?(params, "team"), do: Map.put(params, "owner", params["team"]), else: params

    # Timeline normalisation runs twice on purpose: first to map `owner` onto
    # `team` before unknown keys are dropped, then to restore the Timeline page
    # after invalid parameters or a retired page reset it.
    params =
      params
      |> Params.normalize_timeline_params(timeline?)
      |> Params.normalize_valid_params()
      |> Params.normalize_retired_page()
      |> Params.normalize_timeline_params(timeline?)
      |> Params.normalize_inspect_deep_link()
      |> Params.preserve_invalid_focus(raw_params, invalid_params)

    page = if params["page"] in Params.pages(), do: params["page"], else: "findings"
    params = Map.put(params, "page", page) |> pin_review_item(socket)

    {:noreply,
     socket
     |> assign(
       params: params,
       timeline_params:
         if(Params.valid_params?(params), do: timeline_params, else: %{"filters" => "invalid"}),
       page: page,
       page_title: Params.page_title(page),
       queue_shown:
         if(params["item"] != socket.assigns[:item], do: false, else: socket.assigns.queue_shown),
       invalid_params: invalid_params,
       confirmation: nil,
       repo_whitelist: nil
     )
     |> load()}
  end

  defp pin_review_item(%{"page" => "review"} = params, %{assigns: %{page: "review", item: item}})
       when not is_nil(item), do: Map.put_new(params, "item", item)

  defp pin_review_item(params, _socket), do: params

  # Daily feed: an error (e.g. malformed cursor) renders the honest empty
  # feed rather than a widened view.
  defp load_daily_data(params, before) do
    case Triage.DailyTimeline.list(before: before, scope: params["scope"] || "all") do
      {:ok, data} ->
        data

      {:error, _} ->
        %{
          days: [],
          has_more?: false,
          next_before: nil,
          total_cves: 0,
          event_count: 0,
          earlier?: true
        }
    end
  end

  # Public only for the page modules, which reload after a commit.
  @doc false
  def load(socket) do
    params = socket.assigns.params

    # SQL selects complete CVEs before evidence hydration; no full-estate side path.
    page =
      cond do
        socket.assigns.invalid_params -> empty_page(params)
        socket.assigns.page in @summary_pages -> Workspace.summary(params)
        true -> Workspace.page(page_params(params))
      end

    page = exact_target_page(page, params)

    history =
      if page.row,
        do:
          Workspace.history(
            page.row.cve,
            Enum.filter(page.targets, &(&1.cve == page.row.cve)),
            params
          ),
        else: []

    daily_data =
      if socket.assigns.page == "daily" do
        load_daily_data(params, socket.assigns[:daily_before])
      else
        nil
      end

    # Only what the templates render stays in the socket: the hydrated targets
    # are already inside `page_rows`, and the team and inspector projections
    # belong to retired screens.
    socket
    |> assign(
      Map.take(page, [:page_rows, :total, :metrics, :options, :mode, :offset, :item, :row])
    )
    |> assign(
      page_title: browser_title(socket.assigns.page, page.row),
      row_history: history,
      daily_data: daily_data,
      statistics: statistics(socket.assigns, params),
      scope_form: scope_form(params),
      search_form: search_form(params)
    )
    |> Review.prepare_draft(page.row, page.matching)
    |> Review.load_classification()
    |> Review.load_list_classifications()
    |> load_timeline()
  end

  # Triage lists CVEs that need a decision unless another list is chosen.
  defp page_params(%{"page" => "findings"} = params) do
    params
    |> Map.take(~w(page team environment q severity sort offset item batch))
    |> Map.merge(%{"mode" => params["mode"] || "needs", "page" => "review"})
  end

  defp page_params(params), do: params

  defp empty_page(params) do
    %{
      targets: [],
      matching: [],
      page_rows: [],
      total: 0,
      metrics: Workspace.metrics([]),
      teams: [],
      options: %{teams: [], environments: []},
      mode: params["mode"] || if(params["page"] == "review", do: "needs", else: "active"),
      offset: 0,
      item: nil,
      row: nil,
      inspector: nil,
      inspector_targets: []
    }
  end

  defp load_timeline(%{assigns: %{page: "timeline"}} = socket) do
    socket = TimelineLive.load(socket, socket.assigns.timeline_params)
    options = socket.assigns.timeline_options

    assign(socket, :options, %{
      teams:
        Enum.uniq(
          socket.assigns.options.teams ++ options.owners ++ [socket.assigns.params["team"]]
        )
        |> Enum.reject(&(&1 in [nil, ""])),
      environments:
        Enum.uniq(
          socket.assigns.options.environments ++
            options.environments ++ [socket.assigns.params["environment"]]
        )
        |> Enum.reject(&(&1 in [nil, ""]))
    })
  end

  # Other pages do not render the chart: drop what the last chart view loaded.
  defp load_timeline(%{assigns: %{timeline: nil, detail: nil}} = socket), do: socket

  defp load_timeline(socket) do
    assign(socket,
      timeline: nil,
      detail: nil,
      selected_cve: nil,
      detail_error: nil,
      view_error: nil,
      expanded_cases: %{},
      kev: %{},
      kev_status: nil
    )
  end

  defp statistics(%{page: "statistics", invalid_params: false}, params),
    do:
      Triage.Statistics.report(
        Map.take(params, ~w(team environment)),
        TriageWeb.StatisticsComponents.period(params)
      )

  defp statistics(_assigns, _params), do: nil

  # The browser tab names the open CVE so several tabs stay distinguishable.
  defp browser_title(page, %{cve: cve}) when page in ~w(findings review), do: cve
  defp browser_title(page, _row), do: Params.page_title(page)

  defp scope_form(params),
    do:
      to_form(%{"team" => params["team"] || "", "environment" => params["environment"] || ""},
        as: :scope
      )

  defp search_form(params), do: to_form(%{"q" => params["q"] || ""}, as: :search)

  @impl true
  def handle_event(event, params, socket) when event in unquote(Review.events()),
    do: Review.handle_event(event, params, socket)

  def handle_event("filter", params, %{assigns: %{page: "timeline"}} = socket),
    do: TimelineLive.handle_event("filter", params, socket)

  def handle_event("timeline-case", params, %{assigns: %{page: "timeline"}} = socket),
    do: TimelineLive.handle_event("timeline-case", params, socket)

  def handle_event("plot_width", params, %{assigns: %{page: "timeline"}} = socket),
    do: TimelineLive.handle_event("plot_width", params, socket)

  def handle_event("scope", %{"scope" => params}, %{assigns: %{page: "timeline"}} = socket) do
    {:noreply,
     push_patch(socket,
       to:
         TimelineFilters.path(socket.assigns.filters, %{
           owner: params["team"],
           environment: params["environment"],
           cve: nil
         })
     )}
  end

  def handle_event("scope", %{"scope" => params}, socket) do
    {:noreply,
     push_patch(socket,
       to:
         workspace_path(
           socket.assigns.params,
           Map.merge(Map.take(params, ~w(team environment)), %{"offset" => nil})
         )
     )}
  end

  def handle_event("search", %{"search" => params}, socket) do
    {:noreply,
     push_patch(socket,
       to:
         workspace_path(
           socket.assigns.params,
           Map.merge(Map.take(params, ~w(q)), %{"offset" => nil, "item" => nil})
         )
     )}
  end

  def handle_event("cancel-risk", _, socket), do: {:noreply, assign(socket, confirmation: nil)}

  def handle_event("queue-toggle", _, socket),
    do: {:noreply, assign(socket, queue_shown: not socket.assigns.queue_shown)}

  def handle_event("settings", _, socket), do: {:noreply, assign(socket, settings: true)}

  def handle_event("close-settings", _, socket), do: {:noreply, assign(socket, settings: false)}

  def handle_event("dismiss-action-toast", _, socket),
    do: {:noreply, assign(socket, action_toast: nil)}

  # The whitelist overview reads a file from Azure DevOps, so it loads off the
  # socket process: the dialog opens at once and fills in when the read ends.
  def handle_event("repo-whitelist", params, socket) do
    scope = Map.take(socket.assigns.params, ~w(team environment))
    reload? = params["reload"] == "true"
    shown = socket.assigns.repo_whitelist

    {:noreply,
     socket
     |> assign(repo_whitelist: %{loading: true, failed: false, overview: shown && shown.overview})
     |> start_async(:repo_whitelist, fn ->
       Triage.RepoWhitelist.overview(scope, reload: reload?)
     end)}
  end

  def handle_event("close-repo-whitelist", _, socket),
    do: {:noreply, assign(socket, repo_whitelist: nil)}

  def handle_event("daily-prev", %{"before" => cursor}, socket) do
    {:noreply,
     socket
     |> assign(:daily_before, cursor)
     |> load()}
  end

  def handle_event("daily-latest", _, socket),
    do: {:noreply, socket |> assign(:daily_before, nil) |> load()}

  def handle_event(_, _, socket), do: {:noreply, socket}

  defp exact_target_page(page, %{"focus_target" => value}) when value != "" do
    target? = page.row && Enum.any?(page.row.scopes, &(to_string(&1.id) == value))
    if target?, do: page, else: %{page | row: nil, item: nil}
  end

  defp exact_target_page(page, _params), do: page

  # A result that arrives after the dialog was closed is dropped.
  @impl true
  def handle_async(:repo_whitelist, _result, %{assigns: %{repo_whitelist: nil}} = socket),
    do: {:noreply, socket}

  def handle_async(:repo_whitelist, {:ok, overview}, socket),
    do:
      {:noreply,
       assign(socket, repo_whitelist: %{loading: false, failed: false, overview: overview})}

  def handle_async(:repo_whitelist, {:exit, _reason}, socket) do
    shown = socket.assigns.repo_whitelist.overview

    {:noreply, assign(socket, repo_whitelist: %{loading: false, failed: true, overview: shown})}
  end

  # Ignore legacy/unbound result messages. Current notifications only trigger
  # a fresh read of the durable, evidence-bound classification.
  @impl true
  def handle_info({:ai_assessment, _cve, _result}, socket), do: {:noreply, socket}

  def handle_info({:classification_changed, cve}, socket) do
    socket =
      if Enum.any?(Map.get(socket.assigns, :page_rows, []), &(&1.cve == cve)),
        do: Review.load_list_classifications(socket),
        else: socket

    if socket.assigns.row && socket.assigns.row.cve == cve,
      do: {:noreply, Review.load_classification(socket)},
      else: {:noreply, socket}
  end

  def handle_info(:classification_tick, socket) do
    socket = assign(socket, classification_tick: false)

    if socket.assigns.ai_assessing,
      do: {:noreply, Review.load_classification(socket)},
      else: {:noreply, socket}
  end

  def handle_info({:workspace_changed, cve}, socket) do
    draft = Map.get(socket.assigns.drafts, cve)

    if draft && draft.dirty && not draft.saved do
      draft = Map.put(draft, :stale, true)

      socket =
        assign(socket,
          drafts: Map.put(socket.assigns.drafts, cve, draft),
          stale_cves: MapSet.put(socket.assigns.stale_cves, cve),
          ticket_evidence: nil,
          confirmation: nil
        )

      socket = if socket.assigns.item == cve, do: assign(socket, draft: draft), else: socket
      {:noreply, Review.load_classification(socket)}
    else
      drafts =
        if draft && draft.saved,
          do: socket.assigns.drafts,
          else: Map.delete(socket.assigns.drafts, cve)

      {:noreply, socket |> assign(drafts: drafts) |> load()}
    end
  end

  def handle_info({:dismiss_action_toast, id}, socket) do
    if socket.assigns.action_toast && socket.assigns.action_toast.id == id,
      do: {:noreply, assign(socket, action_toast: nil)},
      else: {:noreply, socket}
  end

  defp nav_items,
    do: [{"findings", "Triage"}, {"daily", "Timeline"}, {"statistics", "Statistics"}]

  # Drafts are stored as they change; only one the server could not store
  # would be lost by leaving, so only that one asks before the page unloads.
  defp unstored_draft?({_cve, draft}),
    do: draft.dirty and not draft.saved and not Map.get(draft, :persisted, false)

  defp ticket_state("pending"), do: "waiting for Azure DevOps"
  defp ticket_state("unknown"), do: "Azure DevOps did not confirm it"
  defp ticket_state("remote_created"), do: "created in Azure DevOps, not yet recorded here"
  defp ticket_state("blocked"), do: "needs the reviewer who started it or an administrator"
  defp ticket_state(state), do: state

  defp initials(%{user: %{email: email}}) when is_binary(email),
    do: email |> String.first() |> String.upcase()

  defp initials(_scope), do: "?"

  # Kept for existing callers (redirects, components); see `Params`.
  defdelegate workspace_path(params, changes \\ %{}), to: Params
  defdelegate nav_path(params, page), to: Params
  defdelegate drill(params, mode, extra \\ %{}), to: Params
  defdelegate review_path(params, cve), to: Params

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_scope={@current_scope}>
      <a href="#main-content" class="skip-link">Skip to content</a>
      <div
        id="shell"
        phx-hook="WorkspaceDraftGuard"
        data-dirty={Enum.any?(@drafts, &unstored_draft?/1) |> to_string()}
      >
        <header class="topbar">
          <.link patch={nav_path(@params, "findings")} class="brand" aria-label="PTV Triage">
            <svg aria-hidden="true" viewBox="0 0 32 32">
              <path d="M16 3 29 26H3Z" fill="none" stroke="#e8763a" stroke-width="3" />
              <path d="M16 11v7m0 3v2" stroke="#e8763a" stroke-width="3" />
            </svg>
            <span>PTV Triage</span>
          </.link>
          <nav class="topnav" aria-label="Primary">
            <.link
              :for={{page, label} <- nav_items()}
              id={"workspace-nav-#{page}"}
              patch={nav_path(@params, page)}
              class={[nav_active?(page, @page) && "active"]}
              aria-current={if nav_active?(page, @page), do: "page"}
            >
              {label}<span
                :if={page == "findings"}
                class="nav-count"
                title="CVEs that need a decision"
              >{@metrics["needs"].value}</span>
            </.link>
          </nav>
          <div class="topmeta">
            <button
              id="workspace-settings"
              type="button"
              class="icon-button"
              phx-click="settings"
              aria-label="Data & help"
              title="Data & help"
            >
              <span aria-hidden="true">?</span>
            </button>
            <details
              id="workspace-account"
              class="account-dropdown"
              phx-click-away={Phoenix.LiveView.JS.remove_attribute("open", to: "#workspace-account")}
              phx-window-keydown={
                Phoenix.LiveView.JS.remove_attribute("open", to: "#workspace-account")
              }
              phx-key="Escape"
            >
              <summary title="Account">
                <span class="avatar" aria-hidden="true">{initials(@current_scope)}</span>
                <span class="sr-only">Account</span>
              </summary>
              <div class="account-popover"><Layouts.account current_scope={@current_scope} /></div>
            </details>
          </div>
        </header>
        <nav :if={@page in ~w(daily timeline)} class="subnav" aria-label="Timeline views">
          <.link
            id="timeline-view-history"
            patch={nav_path(@params, "daily")}
            class={[@page == "daily" && "active"]}
            aria-current={if @page == "daily", do: "page"}
          >Detections and actions</.link>
          <.link
            id="timeline-view-chart"
            patch={nav_path(@params, "timeline")}
            class={[@page == "timeline" && "active"]}
            aria-current={if @page == "timeline", do: "page"}
          >Observation chart</.link>
          <span :if={@page == "daily"} id="workspace-history-scope" class="scope-note">
            History for <strong>{Params.history_scope_label(@page, @params)}</strong>
          </span>
        </nav>
        <.form
          :if={@page != "daily"}
          for={@scope_form}
          id="workspace-scope"
          class="scopebar"
          phx-change="scope"
        >
          <.input
            field={@scope_form[:team]}
            type="select"
            label="Team"
            aria-label="Team"
            options={[{"All teams", ""} | Enum.map(@options.teams, &{team_name(&1), &1})]}
          />
          <.input
            field={@scope_form[:environment]}
            type="select"
            label="Environment"
            aria-label="Environment"
            options={[{"All environments", ""} | Enum.map(@options.environments, &{&1, &1})]}
          />
          <.link
            :if={@params["team"] not in [nil, ""] or @params["environment"] not in [nil, ""]}
            id="reset-workspace-scope"
            class="link"
            patch={
              if @page == "timeline",
                do: TimelineFilters.path(@filters, %{owner: nil, environment: nil, cve: nil}),
                else: workspace_path(@params, %{"team" => nil, "environment" => nil, "offset" => nil})
            }
          >Reset scope</.link>
          <span class="scope-spacer"></span>
          <.link
            :if={@demo_mode}
            id="demo-mode"
            class="link demo-link"
            title="Demo defaults: active deployments in the current scope and Whitelist temporarily are preselected. Your reason and confirmation are still required."
            patch={
              workspace_path(%{}, %{
                "page" => "review",
                "team" => "demo-payments",
                "item" => "CVE-2099-9101"
              })
            }
          >Demo examples</.link>
        </.form>
        <main
          id="main-content"
          tabindex="-1"
          class={[
            "page",
            @page in ~w(findings review) && "review-page",
            @queue_shown && "show-queue"
          ]}
        >
          <h1
            :if={@page in ~w(findings review timeline)}
            id="workspace-page-title"
            class="sr-only"
          >
            {Params.page_title(@page)}
          </h1>
          <p :if={@invalid_params} class="form-error" role="alert">
            Invalid filters. No records loaded.
          </p>
          <div
            :if={@action_toast}
            id={"action-toast-#{@action_toast.id}"}
            class={["action-toast", @action_toast.action == "accepted_risk" && "whitelist-toast"]}
            role="status"
            aria-live="polite"
          >
            <span class="confirmation-icon" aria-hidden="true">✓</span>
            <strong class="confirmation-title">{if @action_toast.action == "accepted_risk",
              do: "Whitelisted",
              else: "Action completed"}</strong>
            <span>{@action_toast.text}</span>
            <button type="button" phx-click="dismiss-action-toast" aria-label="Dismiss confirmation">×</button>
          </div>
          <p
            :if={MapSet.size(@stale_cves) > 0 or (@draft && @draft.stale)}
            id="workspace-stale"
            class="workspace-notice"
            role="alert"
          >
            This CVE changed while you were working on it. Your draft is kept. Reload the CVE before saving.
          </p>
          <p :if={@message} class="workspace-notice" role="status">{@message}</p>
          <section
            :if={@pending_operation}
            id="ticket-operation"
            class="workspace-notice"
            aria-live="polite"
          >
            <h2>
              A ticket request for this CVE is still open: {ticket_state(@pending_operation.state)}
            </h2>
            <p>Don't create another ticket. Check this one instead.</p>
            <details>
              <summary>Technical details</summary>
              <p>Request ID <code>{@pending_operation.id}</code></p>
              <p :if={@pending_operation.marker}>
                Search marker in Azure DevOps: <code>{@pending_operation.marker}</code>
              </p>
            </details>
            <a
              :if={@pending_operation.ticket_url}
              href={@pending_operation.ticket_url}
              target="_blank"
              rel="noopener noreferrer"
            >Open the ticket</a>
            <p :if={@error} role="alert">{@error}</p>
            <button
              :if={@can_review && @pending_operation.state != "blocked"}
              id="reconcile-ticket"
              phx-click="reconcile-ticket"
            >Check the ticket request</button>
            <button
              :if={@can_review && @pending_operation.state == "remote_created"}
              id="review-ticket-evidence"
              phx-click="review-ticket-evidence"
            >Review the current deployments</button>
            <div :if={@ticket_evidence} id="ticket-current-evidence">
              <p>
                Confirm these current deployments for the ticket. The original request stays recorded.
              </p>
              <.scope_table targets={@ticket_evidence} />
              <button id="reconcile-ticket-current" phx-click="reconcile-ticket-current">Confirm and finish the ticket request</button>
            </div>
          </section>
          <.review
            :if={@page in ~w(review findings)}
            rows={@page_rows}
            total={@total}
            offset={@offset}
            row={@row}
            params={@params}
            draft={@draft}
            form={@decision_form}
            mode={@mode}
            error={@error}
            hidden_targets={@hidden_targets}
            queue_shown={@queue_shown}
            can_review={@can_review}
            draft_error={@draft_error}
            pending_operation={@pending_operation}
            history={@row_history}
            ai_configured={Triage.AiTriage.configured?()}
            ai_assessing={@ai_assessing}
            ai_assessment={@ai_assessment}
            ai_assessment_error={@ai_assessment_error}
            ai_rows={@ai_rows}
            classify_all={@classify_all}
            metrics={@metrics}
            search_form={@search_form}
          />
          <TimelineLive.panel :if={@page == "timeline"} workspace_scope={@params} {assigns} />
          <TriageWeb.StatisticsComponents.panel
            :if={@page == "statistics" and @statistics}
            report={@statistics}
            params={@params}
          />
          <TriageWeb.DailyComponents.panel
            :if={@page == "daily" and @daily_data}
            days={@daily_data.days}
            has_more?={@daily_data.has_more?}
            next_before={@daily_data.next_before}
            total_cves={@daily_data.total_cves}
            event_count={@daily_data.event_count}
            earlier?={@daily_data.earlier?}
            params={@params}
          />
        </main>
      </div>
      <.risk_confirmation
        :if={@can_review && @confirmation && @draft.fields["action"] == "accepted_risk"}
        row={@row}
        draft={@draft}
      />
      <.ticket_confirmation
        :if={@can_review && @confirmation && @draft.fields["action"] == "create_ticket"}
        row={@row}
        draft={@draft}
        error={@error}
      />
      <.settings_dialog :if={@settings} />
      <TriageWeb.WhitelistComponents.dialog
        :if={@repo_whitelist}
        state={@repo_whitelist}
        params={@params}
      />
    </Layouts.app>
    """
  end
end
