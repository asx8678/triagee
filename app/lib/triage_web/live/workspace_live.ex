defmodule TriageWeb.WorkspaceLive do
  @moduledoc "Reversible approved-design workspace over real inventory and advisory decisions."
  use TriageWeb, :live_view
  alias Triage.Workspace
  alias Triage.Workspace.Commit
  import TriageWeb.WorkspaceComponents

  @pages ~w(overview inventory review timeline)
  @keys ~w(page team environment mode q severity sort offset item inspect tab batch)

  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "Overview",
       drafts: %{},
       selected: [],
       confirmation: nil,
       error: nil,
       message: nil,
       expanded: false,
       queue_shown: false,
       settings: false,
       compact: false
     )}
  end

  def handle_params(params, _uri, socket) do
    valid =
      Enum.all?(Map.take(params, @keys), fn {_k, v} -> is_binary(v) and byte_size(v) <= 2000 end)

    valid = valid and valid_views?(params)
    params = if valid, do: Map.take(params, @keys), else: %{}
    socket = clear_changed_selection(socket, params)
    page = if params["page"] in @pages, do: params["page"], else: "overview"
    params = Map.put(params, "page", page) |> pin_review_item(socket)

    {:noreply,
     socket
     |> assign(
       params: params,
       page: page,
       page_title: String.capitalize(page),
       invalid_params: not valid,
       confirmation: nil
     )
     |> load()}
  end

  defp pin_review_item(%{"page" => "review"} = params, %{assigns: %{page: "review", item: item}})
       when not is_nil(item), do: Map.put_new(params, "item", item)

  defp pin_review_item(params, _socket), do: params

  defp load(socket) do
    params = socket.assigns.params

    targets =
      if socket.assigns.invalid_params,
        do: [],
        else: Workspace.targets(Map.take(params, ~w(team environment)))

    mode = params["mode"] || if(socket.assigns.page == "review", do: "needs", else: "active")
    matching = targets |> Workspace.select(mode) |> filter_text(params)
    batch = String.split(params["batch"] || "", ",", trim: true)

    rows =
      Workspace.rows(matching)
      |> Enum.filter(&(batch == [] or &1.cve in batch))
      |> sort_rows(params["sort"])

    offset = offset(params["offset"])
    page_rows = Enum.slice(rows, offset, 50)
    item = params["item"] || first_item(socket.assigns.page, rows)
    # A requested advisory never falls back to another CVE or another scope.
    row = Enum.find(Workspace.rows(targets), &(&1.cve == item))

    inspector_source = inspector_source(socket.assigns.page, mode, targets, matching)

    inspect_targets = Enum.filter(inspector_source, &(&1.cve == params["inspect"]))
    inspector = List.first(Workspace.rows(inspect_targets))

    teams =
      targets
      |> Enum.group_by(&Workspace.team_key(&1.placement.owner))
      |> Enum.map(fn {name, ts} -> %{name: name, metrics: Workspace.metrics(ts)} end)
      |> Enum.sort_by(& &1.name)

    socket =
      assign(socket,
        targets: targets,
        metrics: Workspace.metrics(targets),
        teams: teams,
        options: Workspace.options(),
        mode: mode,
        rows: rows,
        page_rows: page_rows,
        offset: offset,
        item: item,
        row: row,
        inspector: inspector,
        inspector_targets: inspect_targets,
        inspector_history:
          if(inspector, do: Workspace.history(inspector.cve, inspect_targets, params), else: []),
        scope_form: scope_form(params),
        search_form: search_form(params)
      )

    prepare_draft(socket, row, matching)
  end

  defp inspector_source("inventory", mode, _targets, matching) when mode in ["unknown", "urgent"],
    do: matching

  defp inspector_source(_, _, targets, _matching), do: targets

  defp first_item("review", [row | _]), do: row.cve
  defp first_item(_, _), do: nil

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

  defp prepare_draft(socket, nil, _matching),
    do: assign(socket, draft: nil, decision_form: to_form(%{}, as: :decision), hidden_targets: [])

  defp prepare_draft(socket, row, matching) do
    initial_targets = Enum.filter(matching, &(&1.cve == row.cve and &1.active?))

    draft =
      Map.get(socket.assigns.drafts, row.cve) ||
        %{
          fields: %{
            "action" => "request_remediation",
            "owner" => "",
            "actor" => "",
            "reason" => "",
            "due_on" => ""
          },
          targets: Enum.map(initial_targets, & &1.id),
          versions: Map.new(row.scopes, &{&1.id, &1.fingerprint}),
          operation: Ecto.UUID.generate(),
          saved: false,
          dirty: false
        }

    visible_ids = Enum.map(row.scopes, & &1.id)

    socket
    |> assign(
      drafts: Map.put(socket.assigns.drafts, row.cve, draft),
      draft: draft,
      decision_form: to_form(draft.fields, as: :decision),
      hidden_targets: draft.targets -- visible_ids
    )
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
           Map.merge(Map.take(params, ~w(q severity sort)), %{"offset" => nil})
         )
     )}
  end

  def handle_event("draft", %{"decision" => params}, socket) when is_map(params) do
    {:noreply,
     update_draft(socket, %{
       fields: Map.take(params, ~w(action owner actor reason due_on)),
       saved: false
     })}
  end

  def handle_event("target", %{"id" => id}, %{assigns: %{row: row, draft: draft}} = socket)
      when not is_nil(row) do
    target = Enum.find(row.scopes, &(to_string(&1.id) == id and &1.active?))

    if target do
      ids =
        if target.id in draft.targets,
          do: List.delete(draft.targets, target.id),
          else: draft.targets ++ [target.id]

      # Newly selected targets require an explicit selection; never silently join on refresh.
      {:noreply,
       update_draft(socket, %{
         targets: ids,
         versions: Map.put_new(draft.versions, target.id, target.fingerprint),
         saved: false
       })}
    else
      {:noreply, socket}
    end
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

  def handle_event("new-draft", _, %{assigns: %{item: item}} = socket) do
    {:noreply,
     socket
     |> assign(
       drafts: Map.delete(socket.assigns.drafts, item),
       error: nil,
       message: nil,
       confirmation: nil
     )
     |> load()
     |> push_event("workspace-draft-cleared", %{})}
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

  def handle_event("save", %{"decision" => fields} = params, %{assigns: %{draft: %{}}} = socket)
      when is_map(fields) do
    socket =
      update_draft(socket, %{fields: Map.take(fields, ~w(action owner actor reason due_on))})

    next? = params["advance"] == "true"
    changeset = Commit.form(socket.assigns.draft.fields)

    cond do
      not changeset.valid? ->
        {:noreply,
         assign(socket,
           error: "Complete the required fields. Your draft is unchanged.",
           decision_form: to_form(%{changeset | action: :insert}, as: :decision)
         )}

      socket.assigns.hidden_targets != [] ->
        {:noreply,
         assign(socket,
           error:
             "Selected targets are hidden by the current scope. Restore the original scope before saving."
         )}

      socket.assigns.draft.targets == [] ->
        {:noreply, assign(socket, error: "Select at least one affected scope.")}

      fields["action"] == "accepted_risk" ->
        {:noreply, assign(socket, confirmation: %{next?: next?}, error: nil)}

      true ->
        {:noreply, commit(socket, next?)}
    end
  end

  def handle_event("confirm-risk", _, %{assigns: %{confirmation: %{next?: next?}}} = socket),
    do: {:noreply, commit(socket, next?)}

  def handle_event("cancel-risk", _, socket), do: {:noreply, assign(socket, confirmation: nil)}

  def handle_event("expand", _, socket),
    do: {:noreply, assign(socket, expanded: not socket.assigns.expanded)}

  def handle_event("queue-toggle", _, socket),
    do: {:noreply, assign(socket, queue_shown: not socket.assigns.queue_shown)}

  def handle_event("density", _, socket),
    do: {:noreply, assign(socket, compact: not socket.assigns.compact)}

  def handle_event("settings", _, socket), do: {:noreply, assign(socket, settings: true)}
  def handle_event("close-settings", _, socket), do: {:noreply, assign(socket, settings: false)}

  def handle_event("close-inspector", _, socket),
    do:
      {:noreply,
       push_patch(socket,
         to: workspace_path(socket.assigns.params, %{"inspect" => nil, "tab" => nil})
       )}

  def handle_event("reconcile", _, %{assigns: %{row: row}} = socket) when not is_nil(row) do
    current =
      Workspace.targets(
        Map.merge(Map.take(socket.assigns.params, ~w(team environment)), %{"cve" => row.cve})
      )

    selected = socket.assigns.draft.targets

    if Enum.all?(selected, fn id -> Enum.any?(current, &(&1.id == id and &1.active?)) end) do
      {:noreply,
       socket
       |> update_draft(%{
         versions: Map.new(current, &{&1.id, &1.fingerprint}),
         operation: Ecto.UUID.generate(),
         saved: false
       })
       |> load()
       |> assign(
         message:
           "Current evidence reloaded. Target selection is unchanged; inspect it before saving."
       )}
    else
      {:noreply,
       assign(socket,
         error:
           "A selected target is no longer available in this scope. Restore scope or explicitly deselect it; no replacement was selected."
       )}
    end
  end

  def handle_event(_, _, socket), do: {:noreply, socket}

  defp update_draft(%{assigns: %{draft: nil}} = socket, _changes), do: socket

  defp update_draft(socket, changes) do
    previous = socket.assigns.draft
    draft = renew_saved_draft(socket, changes) |> Map.merge(changes)

    changed = Map.take(previous, [:fields, :targets]) != Map.take(draft, [:fields, :targets])
    draft = Map.put(draft, :dirty, not draft.saved and (previous.dirty or changed))

    assign(socket,
      draft: draft,
      drafts: Map.put(socket.assigns.drafts, socket.assigns.item, draft),
      decision_form: to_form(draft.fields, as: :decision),
      confirmation: nil,
      error: nil
    )
  end

  defp renew_saved_draft(socket, changes) do
    draft = socket.assigns.draft

    changed =
      Map.take(Map.merge(draft, changes), [:fields, :targets]) !=
        Map.take(draft, [:fields, :targets])

    if draft.saved and changed do
      %{
        draft
        | saved: false,
          operation: Ecto.UUID.generate(),
          versions: Map.new(socket.assigns.row.scopes, &{&1.id, &1.fingerprint})
      }
    else
      draft
    end
  end

  defp valid_views?(params) do
    Enum.all?(
      [
        {"page", @pages},
        {"mode", ~w(active all history needs urgent unknown accepted progress)},
        {"tab", ~w(summary assets history evidence)},
        {"sort", ~w(priority age)},
        {"severity", ~w(CRITICAL HIGH MEDIUM LOW)}
      ],
      fn {key, allowed} -> params[key] in [nil, ""] or params[key] in allowed end
    )
  end

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

  defp commit(socket, next?) do
    %{draft: draft, item: cve} = socket.assigns

    case Commit.save(cve, draft.targets, draft.versions, draft.operation, draft.fields) do
      {:ok, decisions} ->
        # Only a confirmed commit can advance. Preserve the stable pre-save ordering.
        next =
          socket.assigns.rows |> Enum.drop_while(&(&1.cve != cve)) |> Enum.drop(1) |> List.first()

        socket =
          socket
          |> update_draft(%{saved: true})
          |> assign(
            confirmation: nil,
            params: Map.put(socket.assigns.params, "item", cve),
            message:
              "Decision saved for #{length(decisions)} scopes. No ticket sent; active exposure is unchanged."
          )
          |> load()
          |> push_event("workspace-draft-cleared", %{})

        if next? and next,
          do:
            push_patch(socket, to: workspace_path(socket.assigns.params, %{"item" => next.cve})),
          else: socket

      {:error, %Ecto.Changeset{} = changeset} ->
        assign(socket,
          confirmation: nil,
          error: "Save failed. Your draft is unchanged.",
          decision_form: to_form(changeset, as: :decision)
        )

      {:error, :past_date} ->
        assign(socket,
          confirmation: nil,
          error: "Choose today or a future date (UTC). Your draft is unchanged."
        )

      {:error, _} ->
        assign(socket,
          confirmation: nil,
          error:
            "Evidence or a decision changed. Nothing was saved. Reload and review current evidence; your draft is unchanged."
        )
    end
  end

  def workspace_path(params, changes \\ %{}) do
    query =
      params
      |> Map.merge(changes)
      |> Map.take(@keys)
      |> Map.reject(fn {_k, v} -> v in [nil, ""] end)
      |> URI.encode_query()

    "/workspace?" <> query
  end

  def nav_path(params, page),
    do: workspace_path(Map.take(params, ~w(team environment)), %{"page" => page})

  def drill(params, mode, extra \\ %{}),
    do:
      workspace_path(
        Map.take(params, ~w(team environment)),
        Map.merge(
          %{"page" => if(mode == "needs", do: "review", else: "inventory"), "mode" => mode},
          extra
        )
      )

  def inspector_path(params, cve),
    do: workspace_path(params, %{"inspect" => cve, "tab" => "summary"})

  def review_path(params, cve),
    do:
      workspace_path(params, %{"page" => "review", "item" => cve, "inspect" => nil, "tab" => nil})

  defp offset(text) when is_binary(text) do
    case Integer.parse(text) do
      {n, ""} when n >= 0 and n <= 1_000_000 -> n
      _ -> 0
    end
  end

  defp offset(_), do: 0

  defp filter_text(targets, params) do
    query = String.downcase(params["q"] || "")

    Enum.filter(targets, fn t ->
      text =
        Enum.join([t.cve, t.image.repository | Enum.map(t.findings, & &1.package_name)], " ")
        |> String.downcase()

      String.contains?(text, query) and
        (params["severity"] in [nil, ""] or
           Enum.any?(t.findings, &(&1.severity == params["severity"])))
    end)
  end

  defp sort_rows(rows, "age"), do: Enum.sort_by(rows, &{DateTime.to_unix(&1.first_seen), &1.cve})
  defp sort_rows(rows, _), do: rows

  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} workspace>
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
                  {"overview", "Overview"},
                  {"inventory", "Vulnerabilities"},
                  {"review", "Review"},
                  {"timeline", "Timeline"}
                ]
              }
              id={"workspace-nav-#{page}"}
              patch={nav_path(@params, page)}
              class={[@page == page && "active"]}
              aria-current={if @page == page, do: "page"}
            >
              {label}<span :if={page == "review"} class="nav-count">{@metrics["needs"].value}</span>
            </.link>
          </nav>
          <div class="topmeta">
            <span class="local-status">Local workspace · No sign-in</span><button
              id="workspace-settings"
              phx-click="settings"
            ><span class="settings-text">Data &amp; settings</span></button>
          </div>
        </header>
        <.form for={@scope_form} id="workspace-scope" class="scopebar" phx-change="scope">
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
          <span class="dataset"><span class="tag">Operational inventory</span></span>
          <.link
            class="link"
            patch={workspace_path(@params, %{"team" => nil, "environment" => nil, "offset" => nil})}
          >Reset scope</.link>
          <button type="button" class="freshness quiet" phx-click="settings">Coverage unverified</button>
        </.form>
        <main
          id="main-content"
          tabindex="-1"
          class={[
            "page",
            @page == "inventory" && "inventory-page",
            @page == "review" && "review-page",
            @queue_shown && "show-queue"
          ]}
        >
          <p :if={@invalid_params} class="form-error" role="alert">
            Invalid filters. No records loaded.
          </p>
          <p :if={@message} class="workspace-notice" role="status">{@message}</p>
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
            total={length(@rows)}
            offset={@offset}
            params={@params}
            selected={@selected}
            mode={@mode}
            search_form={@search_form}
          />
          <.review
            :if={@page == "review"}
            rows={@page_rows}
            total={length(@rows)}
            offset={@offset}
            row={@row}
            params={@params}
            draft={@draft}
            form={@decision_form}
            mode={@mode}
            error={@error}
            hidden_targets={@hidden_targets}
            queue_shown={@queue_shown}
          />
          <section :if={@page == "timeline"} class="panel">
            <div class="panel-head">
              <h1>Timeline</h1>
            </div>
            <div class="panel-body">
              <p>
                The existing observation tracks and complete event history remain available. The new timeline presentation has not passed its parity gate.
              </p><p>
                Local decisions in this workspace are available in each CVE inspector’s History. No observation gap is a verified fix.
              </p><.link href={
                ~p"/timeline?#{Map.take(@params, ["environment"]) |> Map.put("owner", @params["team"] || "")}"
              }>Open existing timeline</.link>
            </div>
          </section>
        </main>
        <footer class="bottom-status">
          <strong>Local · No sign-in</strong><span>Latest recorded evidence · not verified live coverage</span><span class="right">Workspace rollout · legacy routes preserved</span>
        </footer>
      </div>
      <.inspector
        :if={@params["inspect"]}
        row={@inspector}
        requested={@params["inspect"]}
        targets={@inspector_targets}
        history={@inspector_history}
        params={@params}
        expanded={@expanded}
      />
      <.risk_confirmation :if={@confirmation} row={@row} draft={@draft} />
      <.settings_dialog :if={@settings} />
    </Layouts.app>
    """
  end
end
