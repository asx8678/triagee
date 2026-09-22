defmodule TriageWeb.WorkspaceLive do
  @moduledoc "Primary workspace over real inventory and advisory decisions."
  use TriageWeb, :live_view
  alias Triage.Workspace
  alias Triage.Workspace.{Commit, Drafts}
  alias TriageWeb.{TimelineFilters, TimelineLive}
  import TriageWeb.WorkspaceComponents
  import TriageWeb.ExceptionsComponents

  @pages ~w(findings exceptions overview inventory review timeline news)
  @keys ~w(page team environment mode q severity sort offset item inspect tab batch weeks tview)

  def mount(_params, _session, socket) do
    socket = TimelineLive.initialize(socket)
    if connected?(socket), do: Phoenix.PubSub.subscribe(Triage.PubSub, "workspace:changes")

    {:ok,
     assign(socket,
       page_title: "Overview",
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
       compact: false
     )}
  end

  def handle_params(params, uri, socket) do
    timeline? = URI.parse(uri).path == "/timeline" or params["page"] == "timeline"

    timeline_params =
      if Map.has_key?(params, "team"), do: Map.put(params, "owner", params["team"]), else: params

    params =
      params
      |> normalize_timeline_params(timeline?)
      |> normalize_valid_params()
      |> normalize_timeline_params(timeline?)
      |> normalize_inspect_deep_link()

    socket = clear_changed_selection(socket, params)
    page = if params["page"] in @pages, do: params["page"], else: "findings"
    params = Map.put(params, "page", page) |> pin_review_item(socket)

    {:noreply,
     socket
     |> assign(
       params: params,
       timeline_params:
         if(valid_params?(params), do: timeline_params, else: %{"filters" => "invalid"}),
       page: page,
       page_title: page_title(page),
       queue_shown:
         if(params["item"] != socket.assigns[:item], do: false, else: socket.assigns.queue_shown),
       invalid_params: not valid_params?(params),
       confirmation: nil
     )
     |> load()
     |> maybe_load_news()}
  end

  defp page_title(page) do
    cond do
      page in ~w(findings review) -> "Findings"
      page == "exceptions" -> "Exceptions"
      page == "inventory" -> "Vulnerabilities"
      true -> String.capitalize(page)
    end
  end

  defp normalize_valid_params(params) do
    if valid_params?(params),
      do: Map.take(params, @keys -- ~w(weeks tview)),
      else: %{}
  end

  defp normalize_timeline_params(params, true) do
    params
    |> Map.put("page", "timeline")
    |> Map.put("team", params["team"] || params["owner"] || "")
  end

  defp normalize_timeline_params(params, false), do: params

  # T03/A002: the retired read-only inspector dialog is gone; its deep links
  # (inspect=CVE) converge on the same shared actionable detail.
  defp normalize_inspect_deep_link(%{"inspect" => cve} = params),
    do:
      params |> Map.put("page", "review") |> Map.put("item", cve) |> Map.drop(["inspect", "tab"])

  defp normalize_inspect_deep_link(params), do: params

  defp valid_params?(params) do
    Enum.all?(Map.take(params, @keys -- ~w(weeks tview)), fn {_k, v} ->
      is_binary(v) and byte_size(v) <= 2000
    end) and valid_views?(params)
  end

  defp pin_review_item(%{"page" => "review"} = params, %{assigns: %{page: "review", item: item}})
       when not is_nil(item), do: Map.put_new(params, "item", item)

  defp pin_review_item(params, _socket), do: params

  defp load(socket) do
    params = socket.assigns.params

    # SQL selects complete CVEs before evidence hydration; no full-estate side path.
    page =
      if socket.assigns.invalid_params,
        do: empty_page(params),
        else: Workspace.page(page_params(params))

    history =
      if page.row,
        do:
          Workspace.history(
            page.row.cve,
            Enum.filter(page.targets, &(&1.cve == page.row.cve)),
            params
          ),
        else: []

    exception_decisions =
      if socket.assigns.page == "exceptions" do
        now_dt = DateTime.utc_now()

        import Ecto.Query

        from(d in Triage.Decisions.Decision,
          where:
            d.decision in ["accepted_risk", "not_affected"] and
              d.decided_at >= ^DateTime.add(now_dt, -365, :day) and d.decided_at <= ^now_dt,
          order_by: [desc: d.decided_at, desc: d.id]
        )
        |> Triage.Repo.all()
        |> Enum.map(&decisions_decorate(&1, now_dt))
      else
        []
      end

    socket
    |> assign(Map.drop(page, [:matching]))
    |> assign(
      manual_cves: Triage.ManualCves.list(),
      row_history: history,
      exception_decisions: exception_decisions,
      scope_form: scope_form(params),
      search_form: search_form(params)
    )
    |> prepare_draft(page.row, page.matching)
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

  defp page_params(%{"page" => "exceptions"} = params), do: params

  defp page_params(params), do: params

  # Decisions.decorate/2 is private; this mirrors its projection for the
  # read-only exceptions register (T06).
  defp decisions_decorate(decision, now) do
    %{
      id: decision.id,
      cve: decision.cve,
      decision: decision.decision,
      label: Triage.Decisions.label(decision.decision),
      state: Triage.Decisions.state(decision, now),
      reason: decision.reason,
      actor: decision.actor,
      decided_at: decision.decided_at,
      expires_at: decision.expires_at,
      placement_id: decision.placement_id,
      supersedes_id: decision.supersedes_id,
      work_owner: decision.work_owner,
      due_on: decision.due_on,
      metadata: decision.metadata,
      operation_id: decision.operation_id
    }
  end

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

  defp prepare_draft(socket, nil, _matching) do
    cve = socket.assigns.item

    draft =
      if cve,
        do:
          Map.get(socket.assigns.drafts, cve) ||
            stored_draft(socket.assigns.current_principal, cve)

    draft = if draft, do: Map.put(draft, :stale, stale_draft?(draft, cve)), else: nil

    assign(socket,
      draft: draft,
      decision_form: to_form(if(draft, do: draft.fields, else: %{}), as: :decision),
      hidden_targets: if(draft, do: draft.targets, else: []),
      pending_operation: if(draft, do: operation_summary(draft.operation, socket), else: nil),
      ticket_evidence: nil
    )
  end

  defp prepare_draft(socket, row, _matching) do
    # A fresh draft is neutral (I05/D09): no preselected action, no prewritten
    # conclusion and no automatically selected write targets. The reviewer
    # chooses each explicitly; fingerprints are captured when a target is
    # selected, and a saved draft still restores its original selection.
    draft =
      Map.get(socket.assigns.drafts, row.cve) ||
        stored_draft(socket.assigns.current_principal, row.cve) ||
        %{
          fields: %{"action" => "", "owner" => "", "reason" => "", "due_on" => ""},
          targets: [],
          versions: %{},
          operation: Ecto.UUID.generate(),
          revision: nil,
          saved: false,
          dirty: false,
          stale: false
        }

    stale = stale_draft?(draft, row.cve)

    draft = Map.put(draft, :stale, Map.get(draft, :stale, false) or stale)
    visible_ids = Enum.map(row.scopes, & &1.id)

    socket
    |> assign(
      drafts: Map.put(socket.assigns.drafts, row.cve, draft),
      draft: draft,
      pending_operation:
        if(draft.saved, do: nil, else: operation_summary(draft.operation, socket)),
      ticket_evidence: nil,
      decision_form: to_form(draft.fields, as: :decision),
      hidden_targets: draft.targets -- visible_ids
    )
  end

  defp stale_draft?(%{dirty: false}, _cve), do: false

  defp stale_draft?(draft, cve) do
    # Exact CVE independent of display filters: hidden is not deleted.
    current = Workspace.targets(%{"cve" => cve}) |> Map.new(&{&1.id, &1})

    Enum.any?(draft.targets, fn id ->
      case current[id] do
        nil -> true
        target -> not target.active? or draft.versions[id] != target.fingerprint
      end
    end)
  end

  defp operation_summary(id, socket) do
    case Commit.operation(id, socket.assigns.current_principal) do
      {:ok, summary} -> summary
      _ -> nil
    end
  end

  defp stored_draft(principal, cve) do
    case Drafts.get(principal, cve) do
      {:ok, draft} -> draft
      _ -> nil
    end
  end

  def handle_event(event, _, %{assigns: %{pending_operation: pending}} = socket)
      when not is_nil(pending) and
             event in ["draft", "target", "save", "reconcile", "cancel-decision"] do
    {:noreply,
     assign(socket,
       error:
         "An Azure operation already exists. Reconcile it; do not start or substitute another ticket."
     )}
  end

  def handle_event("reconcile-ticket", _, %{assigns: %{pending_operation: %{id: id}}} = socket),
    do:
      {:noreply,
       finish_reconciliation(socket, Commit.reconcile(id, socket.assigns.current_principal))}

  def handle_event(
        "review-ticket-evidence",
        _,
        %{assigns: %{pending_operation: %{id: id}}} = socket
      ) do
    case Commit.operation(id, socket.assigns.current_principal) do
      {:ok, operation} ->
        targets =
          Workspace.targets(%{"cve" => operation.cve})
          |> Enum.filter(&(&1.id in operation.target_ids))

        if Enum.sort(Enum.map(targets, & &1.id)) == Enum.sort(operation.target_ids) and
             Enum.all?(targets, & &1.active?) do
          {:noreply, assign(socket, ticket_evidence: targets)}
        else
          {:noreply,
           assign(socket,
             ticket_evidence: nil,
             error:
               "An original ticket target is missing or inactive. Contact an administrator; no replacement ticket was created."
           )}
        end

      _ ->
        {:noreply,
         assign(socket,
           error: "Only the original reviewer or an administrator can reconcile this operation."
         )}
    end
  end

  def handle_event(
        "reconcile-ticket-current",
        _,
        %{assigns: %{pending_operation: %{id: id}, ticket_evidence: targets}} = socket
      )
      when is_list(targets) do
    versions = Map.new(targets, &{&1.id, &1.fingerprint})

    {:noreply,
     finish_reconciliation(
       socket,
       Commit.reconcile(id, versions, socket.assigns.current_principal)
     )}
  end

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
           Map.merge(Map.take(params, ~w(q severity sort)), %{"offset" => nil})
         )
     )}
  end

  def handle_event("draft", %{"decision" => params}, socket) when is_map(params) do
    fields =
      Map.merge(socket.assigns.draft.fields, Map.take(params, ~w(action owner reason due_on)))

    fields =
      if fields["action"] == "accepted_risk" and
           (socket.assigns.draft.fields["action"] != "accepted_risk" or
              fields["due_on"] in [nil, ""]) do
        Map.put(fields, "due_on", Date.to_iso8601(Commit.default_due_on()))
      else
        fields
      end

    {:noreply,
     update_draft(socket, %{
       fields: fields,
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

  def handle_event("save", %{"decision" => fields}, %{assigns: %{draft: %{}}} = socket)
      when is_map(fields) do
    socket =
      update_draft(
        socket,
        %{
          fields:
            Map.merge(socket.assigns.draft.fields, Map.take(fields, ~w(action reason due_on)))
        },
        persist: false
      )

    # The authenticated commit injects the real actor from the principal
    # server-side (I03); the pre-validation mirrors that so work actions are
    # judged on their required owner/date/justification merits alone.
    changeset =
      Commit.form(Map.put(socket.assigns.draft.fields, "actor", "authenticated"))

    cond do
      socket.assigns.draft_error ->
        {:noreply, socket}

      socket.assigns.draft.stale ->
        {:noreply,
         assign(socket,
           error:
             "Evidence changed. Explicitly reload and review before saving; your draft is preserved."
         )}

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

      # Decide from the draft's effective action after the merge, never the
      # raw submitted fields: a payload that omits `action` must open the
      # confirmation dialog rather than commit the retained action directly.
      socket.assigns.draft.fields["action"] in ["accepted_risk", "create_ticket"] ->
        {:noreply, assign(socket, confirmation: %{}, error: nil)}

      true ->
        {:noreply, commit(socket)}
    end
  end

  def handle_event(
        "confirm-ticket",
        _,
        %{assigns: %{confirmation: %{}, draft: %{fields: %{"action" => "create_ticket"}}}} =
          socket
      ),
      do: {:noreply, commit(socket)}

  def handle_event(
        "confirm-risk",
        _,
        %{assigns: %{confirmation: %{}, draft: %{fields: %{"action" => "accepted_risk"}}}} =
          socket
      ),
      do: {:noreply, commit(socket)}

  def handle_event("cancel-decision", _, %{assigns: %{row: row}} = socket) when not is_nil(row) do
    draft = socket.assigns.draft

    case Drafts.delete(
           socket.assigns.current_principal,
           row.cve,
           draft && draft.operation,
           draft && draft[:revision]
         ) do
      :ok ->
        {:noreply,
         socket
         |> assign(
           drafts: Map.delete(socket.assigns.drafts, row.cve),
           stale_cves: MapSet.delete(socket.assigns.stale_cves, row.cve),
           confirmation: nil,
           error: nil,
           message: nil,
           draft_error: false
         )
         |> prepare_draft(row, [])
         |> push_event("workspace-draft-cleared", %{})}

      {:error, _} ->
        {:noreply,
         assign(socket,
           error:
             "Could not discard the stored draft. Your draft is preserved; retry when storage is available."
         )}
    end
  end

  def handle_event("cancel-risk", _, socket), do: {:noreply, assign(socket, confirmation: nil)}

  def handle_event("queue-toggle", _, socket),
    do: {:noreply, assign(socket, queue_shown: not socket.assigns.queue_shown)}

  def handle_event("density", _, socket),
    do: {:noreply, assign(socket, compact: not socket.assigns.compact)}

  def handle_event("settings", _, socket), do: {:noreply, assign(socket, settings: true)}

  def handle_event("refresh-news", _, socket) do
    if socket.assigns.news_cves_loading or socket.assigns.news_headlines_loading,
      do: {:noreply, socket},
      else: {:noreply, start_news(socket)}
  end

  def handle_event("manual-close", _, socket), do: {:noreply, assign(socket, manual_open: false)}

  def handle_event("manual-open", _, socket),
    do: {:noreply, assign(socket, manual_open: not socket.assigns.manual_open)}

  def handle_event("manual-fetch", %{"manual" => %{"cve" => cve}}, socket) do
    if socket.assigns.manual_loading do
      {:noreply, socket}
    else
      {:noreply,
       socket
       |> assign(
         manual_loading: true,
         manual_preview: nil,
         manual_error: nil,
         manual_form: to_form(%{"cve" => cve}, as: :manual)
       )
       |> start_async(:manual_fetch, fn -> Triage.ManualCves.fetch(cve) end)}
    end
  end

  def handle_event("manual-save", _, %{assigns: %{manual_preview: nil}} = socket),
    do: {:noreply, socket}

  def handle_event("manual-save", _, socket) do
    case Triage.ManualCves.save(socket.assigns.manual_preview) do
      {:ok, _} ->
        {:noreply,
         assign(socket,
           manual_preview: nil,
           manual_cves: Triage.ManualCves.list(),
           message: "CVE saved to your research list."
         )}

      {:error, _} ->
        {:noreply, assign(socket, manual_error: "Could not save this CVE. Please try again.")}
    end
  end

  def handle_event("close-settings", _, socket), do: {:noreply, assign(socket, settings: false)}

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
         stale: false,
         saved: false
       })
       |> assign(stale_cves: MapSet.delete(socket.assigns.stale_cves, row.cve))
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

  def handle_event("dismiss-action-toast", _, socket),
    do: {:noreply, assign(socket, action_toast: nil)}

  def handle_event(_, _, socket), do: {:noreply, socket}

  defp update_draft(%{assigns: %{draft: nil}} = socket, _changes), do: socket

  # `persist: false` is for the commit path: the fields are about to become a
  # decision, and re-storing the draft there must not turn a concurrent tab's
  # newer saved revision into a blocking error. The post-commit cleanup still
  # removes only this tab's own operation and revision.
  defp update_draft(socket, changes, opts \\ []) do
    draft = renew_saved_draft(socket, changes) |> Map.merge(changes)
    draft = Map.put(draft, :dirty, not draft.saved)
    draft = if draft.saved, do: Map.put(draft, :stale, false), else: draft

    {result, draft} =
      if Keyword.get(opts, :persist, true) do
        persist_draft(socket, draft)
      else
        {:ok, draft}
      end

    assign(socket,
      draft: draft,
      drafts: Map.put(socket.assigns.drafts, socket.assigns.item, draft),
      decision_form: to_form(draft.fields, as: :decision),
      confirmation: nil,
      draft_error: not persisted?(result),
      error: persistence_message(result, draft)
    )
  end

  # A committed draft cleans up only its own stored operation at the revision
  # this tab last saw; an unsaved draft is stored under optimistic concurrency
  # so a stale tab cannot overwrite newer work from another tab or device.
  defp persist_draft(socket, %{saved: true} = draft) do
    {Drafts.delete(
       socket.assigns.current_principal,
       socket.assigns.item,
       draft.operation,
       draft[:revision]
     ), draft}
  end

  defp persist_draft(socket, draft) do
    case Drafts.put(socket.assigns.current_principal, socket.assigns.item, draft) do
      {:ok, revision} -> {:ok, Map.put(draft, :revision, revision)}
      {:conflict, stored} -> {{:conflict, stored}, draft}
      {:error, reason} -> {{:error, reason}, draft}
    end
  end

  defp persisted?(:ok), do: true
  defp persisted?(_other), do: false

  defp persistence_message(:ok, _draft), do: nil

  defp persistence_message({:conflict, _stored}, _draft),
    do:
      "Draft was changed in another tab or device. Your edits are kept here; reopen this item to load the saved draft."

  defp persistence_message(_error, %{saved: true}),
    do:
      "Decision committed, but draft cleanup failed. Its original operation is preserved; do not repeat the action."

  defp persistence_message(_error, _draft),
    do: "Draft could not be stored. Keep this tab open and retry; nothing was committed."

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
          stale: false,
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
        {"mode", ~w(active all history needs urgent unknown accepted progress fixed)},
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
      {:noreply, socket}
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

  defp action_message(cve, %{"action" => "fixed"}), do: "#{cve} marked as fixed"

  defp action_message(cve, %{"action" => "accepted_risk", "due_on" => date}),
    do: "#{cve} whitelisted until #{date}"

  defp action_message(cve, _), do: "#{cve}: Azure DevOps ticket created — in progress"

  defp commit(socket) do
    %{draft: draft, item: cve} = socket.assigns

    case Commit.save(
           cve,
           draft.targets,
           draft.versions,
           draft.operation,
           draft.fields,
           socket.assigns.current_principal
         ) do
      {:ok, _decisions} ->
        toast_id = System.unique_integer([:positive])
        Process.send_after(self(), {:dismiss_action_toast, toast_id}, 4000)

        socket =
          socket
          |> update_draft(%{saved: true})
          |> assign(
            confirmation: nil,
            action_toast: %{
              id: toast_id,
              action: draft.fields["action"],
              text: action_message(cve, draft.fields)
            },
            params: Map.put(socket.assigns.params, "item", cve),
            message: nil
          )
          |> load()
          |> push_event("workspace-draft-cleared", %{})

        socket

      {:error, %Ecto.Changeset{} = changeset} ->
        assign(socket,
          confirmation: nil,
          error: "Save failed. Your draft is unchanged.",
          decision_form: to_form(changeset, as: :decision)
        )

      {:error, {kind, id}}
      when kind in [:reconciliation_required, :operation_pending, :finalization_conflict] ->
        pending_ticket(socket, id, kind)

      {:error, {:ticket, message}} ->
        assign(socket, error: message)

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
      |> Map.filter(fn {_k, v} -> is_binary(v) and v != "" end)
      |> URI.encode_query()

    "/?" <> query
  end

  defp pending_ticket(socket, id, kind) do
    pending =
      operation_summary(id, socket) || %{id: id, state: "blocked", marker: nil, ticket_url: nil}

    message =
      case kind do
        :finalization_conflict ->
          "Azure ticket exists, but local evidence changed. Review current exact targets before finalizing the existing operation."

        :operation_pending ->
          "A ticket operation already claims these targets. Its original reviewer or an administrator must reconcile it."

        _ ->
          "Azure creation outcome is not yet confirmed. The durable operation is preserved. Reconcile it; never create a replacement ticket."
      end

    assign(socket,
      pending_operation: pending,
      ticket_evidence: nil,
      confirmation: nil,
      error: message
    )
  end

  defp finish_reconciliation(socket, {:ok, _decisions}) do
    socket
    |> update_draft(%{saved: true})
    |> assign(
      pending_operation: nil,
      ticket_evidence: nil,
      confirmation: nil,
      stale_cves: MapSet.delete(socket.assigns.stale_cves, socket.assigns.item),
      message: "Existing Azure operation reconciled. No additional ticket was created."
    )
    |> load()
    |> push_event("workspace-draft-cleared", %{})
  end

  defp finish_reconciliation(socket, {:error, {kind, id}})
       when kind in [:reconciliation_required, :operation_pending, :finalization_conflict],
       do: pending_ticket(socket, id, kind)

  defp finish_reconciliation(socket, _),
    do:
      assign(socket,
        error:
          "Operation remains unresolved. Only its original reviewer or an administrator can reconcile; no replacement was created."
      )

  def nav_path(params, "timeline"),
    do:
      TimelineFilters.path(TimelineFilters.defaults(), %{
        owner: params["team"],
        environment: params["environment"]
      })

  def nav_path(params, "exceptions"),
    do: workspace_path(Map.take(params, ~w(team environment)), %{"page" => "exceptions"})

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

  def review_path(params, cve),
    do:
      workspace_path(params, %{"page" => "review", "item" => cve, "inspect" => nil, "tab" => nil})

  defp maybe_load_news(socket) do
    if socket.assigns.can_review and socket.assigns.page == "news" and connected?(socket) and
         not socket.assigns.news_started,
       do: start_news(socket),
       else: socket
  end

  defp start_news(socket) do
    socket
    |> assign(
      news_started: true,
      news_cves_loading: true,
      news_headlines_loading: true,
      news_cves_error: nil,
      news_headlines_error: nil
    )
    |> start_async(:news_cves, fn -> Triage.SecurityNews.critical() end)
    |> start_async(:news_headlines, fn -> Triage.SecurityNews.headlines() end)
  end

  def handle_async(:news_cves, {:ok, {:ok, result}}, socket),
    do: {:noreply, assign(socket, news_cves: result, news_cves_loading: false)}

  def handle_async(:news_headlines, {:ok, {:ok, result}}, socket),
    do: {:noreply, assign(socket, news_headlines: result, news_headlines_loading: false)}

  def handle_async(:news_cves, result, socket),
    do: {:noreply, assign(socket, news_cves_loading: false, news_cves_error: news_error(result))}

  def handle_async(:news_headlines, result, socket),
    do:
      {:noreply,
       assign(socket, news_headlines_loading: false, news_headlines_error: news_error(result))}

  def handle_async(:manual_fetch, {:ok, {:ok, row}}, socket),
    do: {:noreply, assign(socket, manual_loading: false, manual_preview: row)}

  def handle_async(:manual_fetch, {:ok, {:error, error}}, socket),
    do: {:noreply, assign(socket, manual_loading: false, manual_error: error)}

  def handle_async(:manual_fetch, {:exit, _}, socket),
    do:
      {:noreply,
       assign(socket,
         manual_loading: false,
         manual_error: "NVD request failed. Please try again."
       )}

  defp news_error({:ok, {:error, message}}) when is_binary(message), do: message
  defp news_error(_), do: "Source could not be refreshed. Please try again."

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
                  {"findings", "Findings"},
                  {"exceptions", "Exceptions"}
                ]
              }
              id={"workspace-nav-#{page}"}
              patch={nav_path(@params, page)}
              class={[
                (page == "findings" and @page in ~w(findings review)) || (@page == page && "active")
              ]}
              aria-current={if @page == page, do: "page"}
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
        <.form
          :if={@page != "news"}
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
          <h1 :if={@page in ~w(inventory review timeline)} id="workspace-page-title" class="sr-only">
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
          />
          <TimelineLive.panel :if={@page == "timeline"} workspace_scope={@params} {assigns} />
          <TriageWeb.SecurityNewsComponents.panel :if={@page == "news"} {assigns} />
          <.exceptions_register
            :if={@page == "exceptions"}
            decisions={@exception_decisions}
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
      <dialog
        :if={@manual_open}
        id="manual-cves"
        class="confirm manual-cves"
        phx-hook="WorkspaceDialog"
        data-close-event="manual-close"
        aria-labelledby="manual-title"
      >
        <div class="confirmation-layout">
          <header class="modal-head">
            <h2 id="manual-title">Add CVE · Research list</h2>
          </header>
          <div class="modal-body">
            <div class="panel-body">
              <p class="muted">
                Paste a CVE ID to fetch its description from NVD. Saved research CVEs do not count as affected inventory.
              </p>
              <.form
                for={@manual_form}
                id="manual-cve-form"
                phx-submit="manual-fetch"
                class="manual-cve-form"
              >
                <.input
                  field={@manual_form[:cve]}
                  label="CVE number"
                  placeholder="CVE-2024-3094"
                  required
                  maxlength="40"
                  disabled={@manual_loading}
                />
                <button type="submit" disabled={@manual_loading}>{if @manual_loading,
                  do: "Fetching…",
                  else: "Fetch from NVD"}</button>
              </.form>
              <p :if={@manual_error} id="manual-cve-error" class="form-error" role="alert">
                {@manual_error}
              </p>
              <div :if={@manual_preview} id="manual-cve-preview">
                <h3>{@manual_preview.external_id}</h3>
                <p>{@manual_preview.summary}</p>
                <p>
                  <a
                    href={"https://nvd.nist.gov/vuln/detail/" <> @manual_preview.external_id}
                    target="_blank"
                    rel="noopener noreferrer"
                  >Source: NVD</a>
                </p>
                <button :if={@can_review} id="manual-cve-save" phx-click="manual-save">Save to research list</button>
              </div>
            </div>
            <div :if={@manual_cves != []} class="panel-body" id="manual-cve-list">
              <details :for={cve <- @manual_cves} id={"research-#{cve.external_id}"}>
                <summary>{cve.external_id}</summary>
                <p>{cve.summary}</p>
                <a
                  href={"https://nvd.nist.gov/vuln/detail/" <> cve.external_id}
                  target="_blank"
                  rel="noopener noreferrer"
                >Source: NVD</a>
                <span class="muted"> · Fetched {time(cve.fetched_at)}</span>
              </details>
            </div>
          </div>
          <footer class="modal-foot"><button phx-click="manual-close">Close</button></footer>
        </div>
      </dialog>
      <.settings_dialog :if={@settings} />
    </Layouts.app>
    """
  end
end
