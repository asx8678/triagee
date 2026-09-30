defmodule TriageWeb.WorkspaceLive.Review do
  @moduledoc """
  Review page state for `TriageWeb.WorkspaceLive`: per-CVE decision drafts,
  explicit commits, Azure ticket reconciliation and Kiro classification.

  Plain functions over the parent LiveView socket, not a LiveComponent, so
  every event still passes the parent's `TriageWeb.Auth` reviewer check.
  """
  import Phoenix.Component, only: [assign: 2, to_form: 2]
  import Phoenix.LiveView, only: [connected?: 1, push_event: 3]
  alias Triage.Workspace
  alias Triage.Workspace.{Commit, Drafts}
  alias TriageWeb.{WorkspaceComponents, WorkspaceLive}

  @events ~w(reconcile-ticket review-ticket-evidence reconcile-ticket-current draft target save confirm-ticket confirm-risk cancel-decision reconcile classify-now classify-all ai-analyze ai-dismiss)
  def events, do: @events

  def handle_event(event, _, %{assigns: %{pending_operation: pending}} = socket)
      when not is_nil(pending) and
             event in ["draft", "target", "save", "reconcile", "cancel-decision"] do
    {:noreply,
     assign(socket,
       error:
         "A ticket request for this CVE is still open. Check it first; don't create another ticket."
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
               "A deployment in the original ticket request is missing or no longer observed. Ask an administrator; no new ticket was created."
           )}
        end

      _ ->
        {:noreply,
         assign(socket,
           error:
             "Only the reviewer who started this ticket request, or an administrator, can check it."
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

    # The authenticated commit injects the real actor server-side. Historical
    # work requests remain supported by the domain, but Review offers only
    # the three explicit actions below. Draft storage is independent of the
    # decision transaction: an explicit commit may succeed even when autosave
    # conflicted, but it must not acknowledge or overwrite that newer draft.
    changeset =
      Commit.form(Map.put(socket.assigns.draft.fields, "actor", "authenticated"))

    cond do
      socket.assigns.draft.fields["action"] not in Commit.review_actions() ->
        {:noreply,
         assign(socket,
           error: "Choose Create ticket, Mark as fixed or Whitelist."
         )}

      socket.assigns.draft.stale ->
        {:noreply,
         assign(socket,
           error:
             "This CVE changed after you started. Reload it and check before saving; your draft is kept."
         )}

      not changeset.valid? ->
        {:noreply,
         assign(socket,
           error: "Fill in the required fields. Your draft is kept.",
           decision_form: to_form(%{changeset | action: :insert}, as: :decision)
         )}

      socket.assigns.hidden_targets != [] ->
        {:noreply,
         assign(socket,
           error:
             "Some ticked deployments are hidden by the team or environment filter. Clear the filter before saving."
         )}

      socket.assigns.draft.targets == [] ->
        {:noreply, assign(socket, error: "Tick at least one deployment.")}

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
           error: "Couldn't discard the draft. It is still saved; try again in a moment."
         )}
    end
  end

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
       |> WorkspaceLive.load()
       |> assign(
         message: "CVE reloaded. Your ticked deployments are unchanged; check them before saving."
       )}
    else
      {:noreply,
       assign(socket,
         error:
           "A ticked deployment is no longer in this team and environment. Clear the filter or untick it; nothing else was ticked."
       )}
    end
  end

  def handle_event("classify-now", _, %{assigns: %{row: row, can_review: true}} = socket)
      when not is_nil(row) do
    case Triage.AiTriage.Runs.request(
           row.cve,
           socket.assigns.params,
           socket.assigns.current_principal
         ) do
      {:ok, _run} ->
        {:noreply, socket |> load_classification() |> load_list_classifications()}

      {:error, reason} ->
        {:noreply, assign(socket, ai_assessment_error: classify_error(reason))}
    end
  end

  def handle_event("classify-now", _, socket),
    do:
      {:noreply, assign(socket, ai_assessment_error: "Reviewer access is required to classify.")}

  # Queues one guarded run per critical CVE in scope; suggestions only.
  def handle_event("classify-all", _, %{assigns: %{can_review: true}} = socket) do
    result =
      case Triage.AiTriage.Runs.request_critical(
             socket.assigns.params,
             socket.assigns.current_principal
           ) do
        {:ok, counts} -> counts
        {:error, reason} -> %{error: classify_error(reason)}
      end

    {:noreply,
     socket
     |> assign(classify_all: result)
     |> load_classification()
     |> load_list_classifications()}
  end

  def handle_event("classify-all", _, socket),
    do:
      {:noreply,
       assign(socket, classify_all: %{error: "Reviewer access is required to classify."})}

  # Existing clients use the same guarded, durable path after a code reload.
  def handle_event("ai-analyze", params, socket), do: handle_event("classify-now", params, socket)

  def handle_event("ai-dismiss", _, socket),
    do: {:noreply, assign(socket, ai_assessment: nil, ai_assessment_error: nil)}

  def handle_event(_event, _params, socket), do: {:noreply, socket}

  defp classify_error(:analysis_disabled),
    do:
      "Kiro classification is disabled. Configure TRIAGE_ANALYSIS_ENABLED and TRIAGE_KIRO_CLI, then restart."

  defp classify_error(:not_configured),
    do: "Kiro is not configured. Set TRIAGE_KIRO_CLI to your authenticated kiro-cli executable."

  defp classify_error(:prompt_too_large),
    do:
      "This CVE has too much evidence for one classification. Pick a team or environment and try again."

  defp classify_error(_reason),
    do: "Classification couldn't start. Reload the CVE and check that you have reviewer access."

  @doc """
  AI state of each listed CVE in the current scope: `:classifying` while a run
  waits or runs, otherwise the latest completed result from the last 24 hours.
  The open CVE's panel re-checks its result against current evidence.
  """
  def load_list_classifications(%{assigns: %{page: page, page_rows: rows}} = socket)
      when page in ~w(findings review) do
    cutoff = DateTime.add(DateTime.utc_now(), -86_400)

    ai_rows =
      rows
      |> Enum.map(& &1.cve)
      |> Triage.AiTriage.Runs.latest_by_cve(socket.assigns.params)
      |> Enum.flat_map(fn {cve, run} ->
        cond do
          Triage.AiTriage.Runs.in_progress?(run) ->
            [{cve, :classifying}]

          run.state == "completed" and DateTime.compare(run.inserted_at, cutoff) == :gt ->
            [{cve, run.result}]

          true ->
            []
        end
      end)
      |> Map.new()

    assign(socket, ai_rows: ai_rows)
  end

  def load_list_classifications(socket), do: assign(socket, ai_rows: %{})

  # Scores are loaded from durable jobs, never delivered as an unbound task result.
  # This only reads; opening a page never starts Kiro or modifies a reviewer draft.
  def load_classification(socket) do
    run =
      if socket.assigns.row && socket.assigns.page in ~w(findings review),
        do: Triage.AiTriage.Runs.latest(socket.assigns.row.cve, socket.assigns.params)

    display = Triage.AiTriage.Runs.display(run)

    socket
    |> assign(
      ai_assessing: display.assessing,
      ai_assessment: display.assessment,
      ai_assessment_error: display.error
    )
    |> schedule_classification_tick()
  end

  # `{:classification_changed, cve}` normally delivers results; this poll is a
  # fallback that runs only while an assessment is in progress, one at a time.
  defp schedule_classification_tick(
         %{assigns: %{ai_assessing: true, classification_tick: false}} = socket
       ) do
    if connected?(socket) do
      Process.send_after(self(), :classification_tick, 2_000)
      assign(socket, classification_tick: true)
    else
      socket
    end
  end

  defp schedule_classification_tick(socket), do: socket

  def prepare_draft(socket, nil, _matching) do
    cve = socket.assigns.item

    draft =
      if cve,
        do:
          Map.get(socket.assigns.drafts, cve) ||
            stored_draft(socket.assigns.current_principal, cve)

    draft = if draft, do: Map.put(draft, :stale, stale_draft?(draft, cve)), else: nil

    assign(socket,
      draft: draft,
      draft_error: draft_error?(draft),
      decision_form: to_form(if(draft, do: draft.fields, else: %{}), as: :decision),
      hidden_targets: if(draft, do: draft.targets, else: []),
      pending_operation: if(draft, do: operation_summary(draft.operation, socket), else: nil),
      ticket_evidence: nil
    )
  end

  def prepare_draft(socket, row, _matching) do
    # Demo defaults are only a fresh preview. User edits, deselection and saved
    # drafts are never overwritten, and opening the page never records a decision.
    demo? = socket.assigns.demo_mode and socket.assigns.can_review

    existing =
      Map.get(socket.assigns.drafts, row.cve) ||
        stored_draft(socket.assigns.current_principal, row.cve)

    draft =
      if is_nil(existing) or (demo? and not existing.dirty and not existing.saved),
        do: fresh_draft(row, demo?),
        else: existing

    stale = stale_draft?(draft, row.cve)

    draft = Map.put(draft, :stale, Map.get(draft, :stale, false) or stale)
    visible_ids = Enum.map(row.scopes, & &1.id)

    socket
    |> assign(
      drafts: Map.put(socket.assigns.drafts, row.cve, draft),
      draft: draft,
      draft_error: draft_error?(draft),
      pending_operation:
        if(draft.saved, do: nil, else: operation_summary(draft.operation, socket)),
      ticket_evidence: nil,
      decision_form: to_form(draft.fields, as: :decision),
      hidden_targets: draft.targets -- visible_ids
    )
  end

  # Demo defaults tick only deployments that still need a decision, and
  # preselect Whitelist only when there is one; a CVE that is already decided
  # opens with nothing chosen.
  defp fresh_draft(row, demo?) do
    targets = if demo?, do: Enum.filter(row.scopes, &(&1.active? and not &1.covered?)), else: []
    demo? = demo? and targets != []

    %{
      fields: %{
        "action" => if(demo?, do: "accepted_risk", else: ""),
        "owner" => "",
        "reason" => "",
        "due_on" => if(demo?, do: Date.to_iso8601(Commit.default_due_on()), else: "")
      },
      targets: Enum.map(targets, & &1.id),
      versions: Map.new(targets, &{&1.id, &1.fingerprint}),
      operation: Ecto.UUID.generate(),
      revision: nil,
      persisted: false,
      persistence_error: nil,
      saved: false,
      dirty: false,
      stale: false
    }
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
      {:ok, draft} when is_map(draft) ->
        Map.merge(draft, %{persisted: true, persistence_error: nil})

      _ ->
        nil
    end
  end

  defp update_draft(%{assigns: %{draft: nil}} = socket, _changes), do: socket

  # `persist: false` is for the commit path: the fields are about to become a
  # decision, and re-storing the draft there must not turn a concurrent tab's
  # newer saved revision into a blocking error. The post-commit cleanup still
  # removes only this tab's own operation and revision.
  defp update_draft(socket, changes, opts \\ []) do
    draft = renew_saved_draft(socket, changes) |> Map.merge(changes)
    draft = Map.put(draft, :dirty, not draft.saved)
    draft = if draft.saved, do: Map.put(draft, :stale, false), else: draft

    draft =
      if Keyword.get(opts, :persist, true) do
        {result, draft} = persist_draft(socket, draft)

        Map.merge(draft, %{
          persisted: persisted?(result) and not draft.saved,
          persistence_error: persistence_message(result, draft)
        })
      else
        # Submit/validation/confirmation are not storage acknowledgements.
        # Retain failures, and retain a prior acknowledgement only if the
        # exact content is unchanged. These flags travel with this CVE's draft.
        previous = socket.assigns.draft

        Map.put(
          draft,
          :persisted,
          previous.persisted and draft_content(previous) == draft_content(draft)
        )
      end

    assign(socket,
      draft: draft,
      drafts: Map.put(socket.assigns.drafts, socket.assigns.item, draft),
      decision_form: to_form(draft.fields, as: :decision),
      confirmation: nil,
      draft_error: draft_error?(draft),
      error: nil
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

  defp draft_content(draft), do: Map.take(draft, [:fields, :targets, :versions, :operation])
  defp draft_error?(nil), do: false
  defp draft_error?(draft), do: not is_nil(draft.persistence_error)

  defp persisted?(:ok), do: true
  defp persisted?(_other), do: false

  defp persistence_message(:ok, _draft), do: nil

  defp persistence_message({:conflict, _stored}, _draft),
    do:
      "This draft was changed in another tab or on another device. Your edits are only in this tab; copy them before reloading."

  defp persistence_message(_error, %{saved: true}),
    do: "Decision saved, but the draft couldn't be cleared. Don't repeat the action."

  defp persistence_message(_error, _draft),
    do: "Your draft couldn't be saved. Keep this tab open and try again; nothing was decided."

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

  defp action_message(cve, %{"action" => "fixed"}),
    do: "#{cve} marked as fixed. The fix still needs to be verified."

  defp action_message(cve, %{"action" => "accepted_risk", "due_on" => date}) do
    case Date.from_iso8601(date || "") do
      {:ok, date} -> "#{cve} whitelisted until #{WorkspaceComponents.format_date(date)}."
      _ -> "#{cve} whitelisted."
    end
  end

  defp action_message(cve, _), do: "Azure DevOps ticket created for #{cve}."

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
          |> WorkspaceLive.load()
          |> push_event("workspace-draft-cleared", %{})

        socket

      {:error, %Ecto.Changeset{} = changeset} ->
        assign(socket,
          confirmation: nil,
          error: "Couldn't save. Your draft is kept.",
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
          error: "Pick today or a later date (UTC). Your draft is kept."
        )

      {:error, {:dismissal_basis_invalid, _id, state}} ->
        assign(socket,
          confirmation: nil,
          error:
            "The exposure information for a ticked deployment is #{exposure_problem(state)}. Check it before whitelisting. Your draft is kept."
        )

      {:error, _} ->
        assign(socket,
          confirmation: nil,
          error:
            "This CVE or its decisions changed, so nothing was saved. Reload the CVE and check it; your draft is kept."
        )
    end
  end

  defp exposure_problem(:expired), do: "out of date"
  defp exposure_problem(:future_dated), do: "dated in the future"
  defp exposure_problem(:conflicting), do: "conflicting"
  defp exposure_problem(state), do: to_string(state)

  defp pending_ticket(socket, id, kind) do
    pending =
      operation_summary(id, socket) || %{id: id, state: "blocked", marker: nil, ticket_url: nil}

    message =
      case kind do
        :finalization_conflict ->
          "The Azure DevOps ticket exists, but this CVE changed since. Check the current deployments, then finish the existing request."

        :operation_pending ->
          "A ticket request already covers these deployments. The reviewer who started it, or an administrator, must check it."

        _ ->
          "Azure DevOps hasn't confirmed the ticket yet. The request is kept; check it instead of creating another ticket."
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
      message: "Ticket request checked and recorded. No new ticket was created."
    )
    |> WorkspaceLive.load()
    |> push_event("workspace-draft-cleared", %{})
  end

  defp finish_reconciliation(socket, {:error, {kind, id}})
       when kind in [:reconciliation_required, :operation_pending, :finalization_conflict],
       do: pending_ticket(socket, id, kind)

  defp finish_reconciliation(socket, _),
    do:
      assign(socket,
        error:
          "The ticket request is still open. Only the reviewer who started it, or an administrator, can check it; no new ticket was created."
      )
end
