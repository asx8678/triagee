defmodule TriageWeb.WorkspaceLive do
  @moduledoc """
  Primary workspace over real inventory and advisory decisions.

  This LiveView owns routing, shared state (drafts, selection, confirmations)
  and the page shell. Page behaviour lives in plain modules it delegates to:
  `Params` (URLs), `Review` (drafts, decisions, tickets, classification) and
  `News` (public news and the research list). They are not LiveComponents, so
  every event still passes `TriageWeb.Auth`'s per-event authorization hook.
  """
  use TriageWeb, :live_view
  alias Triage.{Decisions, RiskDecisionHistory, Workspace}
  alias TriageWeb.{TimelineFilters, TimelineLive}
  alias TriageWeb.WorkspaceLive.{News, Params, Review}
  import TriageWeb.WorkspaceComponents
  import TriageWeb.ExceptionsComponents
  import Params, only: [nav_active?: 2]
  import News, only: [research_dialog: 1]

  # Pages that list no workspace CVEs: they need only the nav count and scope options.
  @summary_pages ~w(daily exceptions news timeline)

  @impl true
  def mount(_params, _session, socket) do
    socket = TimelineLive.initialize(socket)

    if connected?(socket) do
      Phoenix.PubSub.subscribe(Triage.PubSub, "workspace:changes")
      Phoenix.PubSub.subscribe(Triage.PubSub, "review:classification")
    end

    {:ok,
     assign(socket,
       page_title: "Overview",
       demo_mode: Application.get_env(:triage, :demo_mode, false),
       drafts: %{},
       stale_cves: MapSet.new(),
       draft_error: false,
       pending_operation: nil,
       ticket_evidence: nil,
       selected: [],
       confirmation: nil,
       error: nil,
       message: nil,
       action_toast: nil,
       expanded: false,
       queue_shown: false,
       settings: false,
       manual_open: false,
       manual_loading: false,
       manual_preview: nil,
       manual_error: nil,
       manual_form: to_form(%{"cve" => ""}, as: :manual),
       manual_cves: [],
       news_started: false,
       news_cves: nil,
       news_headlines: nil,
       news_cves_loading: false,
       news_headlines_loading: false,
       news_cves_error: nil,
       news_headlines_error: nil,
       compact: false,
       daily_before: nil,
       daily_data: nil,
       ai_assessing: false,
       ai_assessment: nil,
       ai_assessment_error: nil,
       classification_tick: false
     )}
  end

  @impl true
  def handle_params(params, uri, socket) do
    raw_params = params
    timeline? = URI.parse(uri).path == "/timeline" or params["page"] == "timeline"
    invalid_params = not Params.valid_params?(raw_params)

    timeline_params =
      if Map.has_key?(params, "team"), do: Map.put(params, "owner", params["team"]), else: params

    params =
      params
      |> Params.normalize_timeline_params(timeline?)
      |> Params.normalize_valid_params()
      |> Params.normalize_timeline_params(timeline?)
      |> Params.normalize_inspect_deep_link()
      |> Params.preserve_invalid_focus(raw_params, invalid_params)

    socket = clear_changed_selection(socket, params)
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
       confirmation: nil
     )
     |> load()
     |> News.maybe_load_news()}
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

    # Built once per load, not on every render: filtering, grouping and the
    # status tiles need the whole year's register, so paging stays in memory.
    risk_history =
      if socket.assigns.page == "exceptions" do
        now = DateTime.utc_now()
        RiskDecisionHistory.build(Decisions.risk_register(now), params, now)
      end

    socket
    |> assign(Map.drop(page, [:matching]))
    |> assign(
      row_history: history,
      risk_history: risk_history,
      daily_data: daily_data,
      scope_form: scope_form(params),
      search_form: search_form(params)
    )
    |> Review.prepare_draft(page.row, page.matching)
    |> Review.load_classification()
    |> load_timeline()
  end

  # Overview: priority preview must not miss urgent CVEs beyond the first page.
  defp page_params(%{"page" => "overview"} = params) do
    params
    |> Map.take(~w(page team environment item inspect))
    |> Map.merge(%{"mode" => "urgent", "offset" => "0"})
  end

  # T04: Findings is the primary workspace; it uses the same review projection
  # with the attention default ("Needs attention" = the existing needs mode).
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

  defp load_timeline(socket), do: socket

  defp scope_form(params),
    do:
      to_form(%{"team" => params["team"] || "", "environment" => params["environment"] || ""},
        as: :scope
      )

  defp search_form(params),
    do:
      to_form(
        %{
          "q" => params["q"] || "",
          "severity" => params["severity"] || "",
          "sort" => params["sort"] || "priority"
        },
        as: :search
      )

  @impl true
  def handle_event(event, params, socket) when event in unquote(Review.events()),
    do: Review.handle_event(event, params, socket)

  def handle_event(event, params, socket) when event in unquote(News.events()),
    do: News.handle_event(event, params, socket)

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

  def handle_event(
        "risk-filter",
        %{"risk_filters" => params},
        %{assigns: %{page: "exceptions"}} = socket
      )
      when is_map(params) do
    filters = Map.take(params, ~w(risk_q risk_team risk_environment))

    if Enum.all?(filters, fn {_key, value} -> is_binary(value) and byte_size(value) <= 2000 end) do
      {:noreply,
       push_patch(socket,
         to: workspace_path(socket.assigns.params, Map.put(filters, "risk_page", nil))
       )}
    else
      {:noreply, socket}
    end
  end

  def handle_event("risk-filter", _params, socket), do: {:noreply, socket}

  def handle_event("search", %{"search" => params}, socket) do
    {:noreply,
     push_patch(socket,
       to:
         workspace_path(
           socket.assigns.params,
           Map.merge(Map.take(params, ~w(q severity sort)), %{"offset" => nil})
         )
     )}
  end

  def handle_event("select", %{"cve" => cve}, socket) do
    selected = socket.assigns.selected

    selected =
      cond do
        cve in selected ->
          List.delete(selected, cve)

        length(selected) < 25 and Enum.any?(socket.assigns.page_rows, &(&1.cve == cve)) ->
          selected ++ [cve]

        true ->
          selected
      end

    {:noreply, assign(socket, selected: selected)}
  end

  def handle_event("clear-selection", _, socket), do: {:noreply, assign(socket, selected: [])}

  def handle_event("review-selected", _, socket) do
    if socket.assigns.selected == [] do
      {:noreply, socket}
    else
      {:noreply,
       push_patch(socket,
         to:
           workspace_path(socket.assigns.params, %{
             "page" => "review",
             "batch" => Enum.join(socket.assigns.selected, ","),
             "item" => hd(socket.assigns.selected),
             "offset" => nil
           })
       )}
    end
  end

  def handle_event("cancel-risk", _, socket), do: {:noreply, assign(socket, confirmation: nil)}

  def handle_event("queue-toggle", _, socket),
    do: {:noreply, assign(socket, queue_shown: not socket.assigns.queue_shown)}

  def handle_event("density", _, socket),
    do: {:noreply, assign(socket, compact: not socket.assigns.compact)}

  def handle_event("settings", _, socket), do: {:noreply, assign(socket, settings: true)}

  def handle_event("close-settings", _, socket), do: {:noreply, assign(socket, settings: false)}

  def handle_event("dismiss-action-toast", _, socket),
    do: {:noreply, assign(socket, action_toast: nil)}

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

  defp clear_changed_selection(socket, params) do
    previous = Map.get(socket.assigns, :params, %{}) |> Map.take(~w(team environment))

    if previous != Map.take(params, ~w(team environment)) and socket.assigns.selected != [] do
      assign(socket,
        selected: [],
        message:
          "Scope changed. Inventory selection cleared; decision draft targets are unchanged."
      )
    else
      socket
    end
  end

  # Ignore legacy/unbound result messages. Current notifications only trigger
  # a fresh read of the durable, evidence-bound classification.
  @impl true
  def handle_info({:ai_assessment, _cve, _result}, socket), do: {:noreply, socket}

  def handle_info({:classification_changed, cve}, socket) do
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

  @impl true
  def handle_async(name, result, socket), do: News.handle_async(name, result, socket)

  # Kept for existing callers (redirects, components); see `Params`.
  defdelegate workspace_path(params, changes \\ %{}), to: Params
  defdelegate nav_path(params, page), to: Params
  defdelegate drill(params, mode, extra \\ %{}), to: Params
  defdelegate review_path(params, cve), to: Params

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_scope={@current_scope} workspace>
      <a href="#main-content" class="skip-link">Skip to content</a>
      <div
        id="shell"
        class={[@compact && "compact"]}
        phx-hook="WorkspaceDraftGuard"
        data-dirty={Enum.any?(@drafts, fn {_id, d} -> not d.saved and d.dirty end) |> to_string()}
      >
        <header class="topbar">
          <.link patch={nav_path(@params, "overview")} class="brand"><svg
            aria-hidden="true"
            viewBox="0 0 32 32"
          ><path d="M16 3 29 26H3Z" fill="none" stroke="#ff702b" stroke-width="3"/><path d="M16 11v7m0 3v2" stroke="#ff702b" stroke-width="3"/></svg>PTV Triage</.link>
          <nav class="topnav" aria-label="Primary">
            <.link
              :for={
                {page, label} <- [
                  {"findings", "Review"},
                  {"exceptions", "Risk decisions"},
                  {"daily", "Timeline"}
                ]
              }
              id={"workspace-nav-#{page}"}
              patch={nav_path(@params, page)}
              class={[nav_active?(page, @page) && "active"]}
              aria-current={if nav_active?(page, @page), do: "page"}
            >
              {label}<span :if={page == "findings"} class="nav-count">{@metrics["needs"].value}</span>
            </.link>
          </nav>
          <div class="topmeta">
            <details
              id="workspace-account"
              class="account-dropdown"
              phx-click-away={Phoenix.LiveView.JS.remove_attribute("open", to: "#workspace-account")}
              phx-window-keydown={
                Phoenix.LiveView.JS.remove_attribute("open", to: "#workspace-account")
              }
              phx-key="Escape"
            >
              <summary>Account</summary>
              <div class="account-popover"><Layouts.account current_scope={@current_scope} /></div>
            </details>
            <button id="workspace-settings" phx-click="settings"><span class="settings-text">Data &amp; help</span></button>
          </div>
        </header>
        <div :if={@page == "news"} class="scopebar">
          <span class="scope-label">Public intelligence</span><span>Global CVE news · Independent of your inventory</span>
        </div>
        <div :if={@page in ~w(exceptions daily)} id="workspace-history-scope" class="scopebar">
          <span class="scope-label">History</span><span>{Params.history_scope_label(@page, @params)}</span>
          <span class="dataset"><span class="tag">{if @page == "exceptions",
            do: "Risk decision history",
            else: "Detections & actions"}</span></span>
        </div>
        <.form
          :if={@page not in ~w(news exceptions daily)}
          for={@scope_form}
          id="workspace-scope"
          class="scopebar"
          phx-change="scope"
        >
          <span class="scope-label">Scope</span>
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
          <span class="dataset"><span class="tag">{if @page == "timeline",
            do: "Recorded history",
            else: "Operational inventory"}</span></span>
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
          <.link
            :if={@demo_mode}
            id="demo-mode"
            class="tag"
            title="Demo defaults: active deployments in the current scope and Whitelist temporarily are preselected. Your reason and confirmation are still required."
            patch={
              workspace_path(%{}, %{
                "page" => "review",
                "team" => "demo-payments",
                "item" => "CVE-2099-9101"
              })
            }
          >Demo mode · examples</.link>
          <button type="button" class="freshness quiet" phx-click="settings">Coverage unverified</button>
        </.form>
        <main
          id="main-content"
          tabindex="-1"
          class={[
            "page",
            @page == "inventory" && "inventory-page",
            @page in ~w(findings review) && "review-page",
            @queue_shown && "show-queue"
          ]}
        >
          <h1
            :if={@page in ~w(findings inventory review timeline)}
            id="workspace-page-title"
            class="sr-only"
          >
            {@page_title}
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
            Workspace changed. Your draft and original evidence are preserved. Reload current evidence explicitly before committing.
          </p>
          <p :if={@message} class="workspace-notice" role="status">{@message}</p>
          <section
            :if={@pending_operation}
            id="ticket-operation"
            class="workspace-notice"
            aria-live="polite"
          >
            <h2>Existing Azure operation · {@pending_operation.state}</h2>
            <p>
              Operation <code>{@pending_operation.id}</code>
              is durable. Do not create a replacement ticket.
            </p>
            <p :if={@pending_operation.marker}>
              Recovery marker: <code>{@pending_operation.marker}</code>
            </p>
            <a
              :if={@pending_operation.ticket_url}
              href={@pending_operation.ticket_url}
              target="_blank"
              rel="noopener noreferrer"
            >Open existing ticket</a>
            <p :if={@error} role="alert">{@error}</p>
            <button
              :if={@can_review && @pending_operation.state != "blocked"}
              id="reconcile-ticket"
              phx-click="reconcile-ticket"
            >Check and reconcile existing ticket</button>
            <button
              :if={@can_review && @pending_operation.state == "remote_created"}
              id="review-ticket-evidence"
              phx-click="review-ticket-evidence"
            >Review current evidence for this ticket</button>
            <div :if={@ticket_evidence} id="ticket-current-evidence">
              <p>
                Explicitly accept this current evidence for the original ticket targets. The original request remains recorded.
              </p>
              <.scope_table targets={@ticket_evidence} />
              <button id="reconcile-ticket-current" phx-click="reconcile-ticket-current">Accept reviewed evidence and finalize existing ticket</button>
            </div>
          </section>
          <.overview
            :if={@page == "overview"}
            metrics={@metrics}
            teams={@teams}
            targets={@targets}
            params={@params}
          />
          <.inventory
            :if={@page == "inventory"}
            rows={@page_rows}
            total={@total}
            offset={@offset}
            params={@params}
            selected={@selected}
            mode={@mode}
            search_form={@search_form}
            compact={@compact}
          />
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
          />
          <TimelineLive.panel :if={@page == "timeline"} workspace_scope={@params} {assigns} />
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
          <TriageWeb.SecurityNewsComponents.panel :if={@page == "news"} {assigns} />
          <.exceptions_register
            :if={@page == "exceptions" and @risk_history}
            history={@risk_history}
            params={@params}
          />
        </main>
        <footer class="bottom-status">
          <span>Recorded evidence · coverage unverified</span><span class="right">Decisions apply to selected deployments only</span>
        </footer>
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
      <.research_dialog
        :if={@manual_open}
        form={@manual_form}
        loading={@manual_loading}
        error={@manual_error}
        preview={@manual_preview}
        cves={@manual_cves}
        can_review={@can_review}
      />
      <.settings_dialog :if={@settings} />
    </Layouts.app>
    """
  end
end
