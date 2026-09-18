defmodule TriageWeb.CaseLive.Show do
  @moduledoc """
  Read-and-review page for one local review case (PR 2): frozen evidence
  snapshot, manual assessment form and append-only history.

  The case scope is the scope saved on the case — never rebound from URL
  parameters. The rendered evidence is the captured snapshot payload, not a
  live Inventory preload. Case ids and event bodies are validated at the
  boundary against positive PostgreSQL bigint bounds: malformed input surfaces
  a visible notice without crashing or writing. The actor is the server-owned
  `local-operator` identity, explicitly unauthenticated; saving an assessment
  approves nothing, activates no suppression and claims no remediation.
  """

  use TriageWeb, :live_view

  alias Triage.Cases
  alias Triage.Exceptions
  alias Triage.Intel
  alias TriageWeb.{CaseFilters, FindingFilters}

  # The section components and the shared view-model formatting live in sibling
  # modules: this module owns the case's state, events and data loading, while
  # they own how a captured value is displayed.
  import TriageWeb.CaseLive.Format
  import TriageWeb.CaseLive.Sections

  @bigint_max 9_223_372_036_854_775_807

  @submit_errors [
    :conflict,
    :evidence_stale,
    :token_reuse,
    :source_out_of_scope,
    :not_found,
    :invalid_request
  ]

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Review case")
     |> assign(:case_error, nil)
     |> assign(:kev_status, nil)
     |> assign(:case, nil)
     |> assign(:snapshot, nil)
     |> assign(:latest_review, nil)
     |> assign(:evidence, empty_evidence())
     |> assign(:evidence_status, :current)
     |> assign(:back_filters, FindingFilters.defaults())
     |> assign(:invalid_back_scope, [])
     |> assign(:scope_mismatch?, false)
     |> assign(:back_path, ~p"/findings")
     |> assign(:queue_return, nil)
     |> assign(:expected_revision, nil)
     |> assign(:expected_snapshot_id, nil)
     |> assign(:idempotency_token, nil)
     |> assign(:review_form, to_form(Cases.change_review()))
     |> assign(:dirty?, false)
     |> assign(:retained_draft, nil)
     |> assign(:rebind_required?, false)
     |> assign(:rebind_confirm?, false)
     |> assign(:discard_confirm?, false)
     |> assign(:known_snapshot_ids, [])
     |> assign(:notice, nil)
     |> assign(:refresh_confirm?, false)
     |> assign(:refresh_binding, nil)
     |> assign(:applicability_options, applicability_options())
     |> assign(:priority_options, priority_options())
     |> assign(:next_action_options, next_action_options())
     |> stream_configure(:timeline, dom_id: &"timeline-#{&1.key}")
     |> stream_configure(:snapshots, dom_id: &"snapshot-#{&1.id}")}
  end

  @impl true
  def handle_params(%{"id" => id} = params, _uri, socket) do
    parsed = FindingFilters.parse(params)
    target = parse_case_id(id)

    socket =
      socket
      |> retain_departing_draft(target)
      |> assign(:back_filters, parsed)
      |> assign(:invalid_back_scope, parsed.invalid)
      |> assign(:queue_return, queue_return(params["queue"]))

    case target do
      :error ->
        {:noreply, invalidate_case(socket, :invalid_id)}

      {:ok, case_id} ->
        case Cases.get_case(case_id) do
          {:ok, data} -> {:noreply, assign_case(socket, data)}
          {:error, :not_found} -> {:noreply, invalidate_case(socket, :not_found)}
          {:error, :invalid_request} -> {:noreply, invalidate_case(socket, :invalid_id)}
        end
    end
  end

  def handle_params(_other, _uri, socket) do
    {:noreply, socket |> retain_departing_draft(:error) |> invalidate_case(:invalid_id)}
  end

  # Hidden metadata travels with a queued submission. The context checks the
  # exact retry BEFORE revision/snapshot checks, and owns all writes/locking.
  # A late retry must not erase a newer draft already being edited here.
  @impl true
  def handle_event("save", %{"review" => params, "meta" => meta}, socket)
      when is_map(params) and is_map(meta) do
    if editable?(socket) and not socket.assigns.rebind_required? do
      case parse_meta(meta) do
        {:ok, revision, snapshot_id, token} ->
          preserve? = newer_draft?(socket, params, token)

          case Cases.submit_review(socket.assigns.case.id, revision, snapshot_id, token, params) do
            {:ok, %{replayed?: replayed?}} ->
              saved = if preserve?, do: socket, else: clear_draft(socket)

              message =
                if replayed?,
                  do:
                    "Duplicate submission — the original assessment was kept; no second review was recorded.",
                  else: "Assessment saved to the local case history."

              {:noreply,
               saved
               |> reload_case(nil)
               |> put_flash(
                 :info,
                 message <>
                   if(preserve?,
                     do: " Your newer unsaved draft was kept with its original binding.",
                     else: ""
                   )
               )}

            {:error, %Ecto.Changeset{} = changeset} ->
              failed = if preserve?, do: socket, else: remember_draft(socket, params, changeset)
              {:noreply, assign(failed, :notice, :validation)}

            {:error, reason} when reason in @submit_errors ->
              failed = if preserve?, do: socket, else: remember_draft(socket, params)

              {:noreply,
               failed
               |> assign(:notice, notice_key(reason))
               |> assign(
                 :rebind_required?,
                 failed.assigns.rebind_required? or reason == :token_reuse
               )}
          end

        :error ->
          kept = if socket.assigns.dirty?, do: socket, else: remember_draft(socket, params)
          {:noreply, assign(kept, :notice, :invalid_request)}
      end
    else
      {:noreply, assign(socket, :notice, :invalid_request)}
    end
  end

  def handle_event("save", %{"review" => params}, socket) when is_map(params) do
    socket =
      if editable?(socket) and not socket.assigns.dirty?,
        do: remember_draft(socket, params),
        else: socket

    {:noreply, assign(socket, :notice, :invalid_request)}
  end

  def handle_event("save", _other, socket),
    do: {:noreply, assign(socket, :notice, :invalid_request)}

  def handle_event("validate", %{"review" => params}, socket) when is_map(params) do
    {:noreply, if(editable?(socket), do: remember_draft(socket, params), else: socket)}
  end

  def handle_event("validate", _other, socket), do: {:noreply, socket}

  # LiveView reconnect recovery must restore the browser's OLD binding, not
  # attach its recovered text to whatever revision the new mount just loaded.
  def handle_event("recover_draft", %{"review" => params, "meta" => meta}, socket)
      when is_map(params) and is_map(meta) do
    with true <- editable?(socket),
         {:ok, case_id} <- parse_case_id(meta["case_id"]),
         true <- case_id == socket.assigns.case.id,
         {:ok, revision, snapshot_id, token} <- parse_meta(meta),
         true <- revision <= socket.assigns.case.revision,
         true <- snapshot_id in socket.assigns.known_snapshot_ids do
      socket =
        socket
        |> remember_draft(params)
        |> assign(:expected_revision, revision)
        |> assign(:expected_snapshot_id, snapshot_id)
        |> assign(:idempotency_token, token)
        |> assign(
          :rebind_required?,
          revision != socket.assigns.case.revision or
            snapshot_id != socket.assigns.case.current_snapshot_id
        )
        |> assign(:notice, :draft_recovered)

      {:noreply, socket}
    else
      _ ->
        # Keep recoverable text, but block a save until the operator explicitly
        # checks the displayed evidence and confirms a new binding.
        socket = if editable?(socket), do: remember_draft(socket, params), else: socket
        {:noreply, socket |> assign(:rebind_required?, true) |> assign(:notice, :recovery_failed)}
    end
  end

  def handle_event("recover_draft", _other, socket),
    do: {:noreply, assign(socket, :notice, :invalid_request)}

  def handle_event("reload", _params, socket) do
    {:noreply, if(socket.assigns.case, do: reload_case(socket, nil), else: socket)}
  end

  def handle_event("refresh_evidence", _params, socket) do
    if editable?(socket) do
      {:noreply,
       socket
       |> assign(:refresh_confirm?, true)
       |> assign(
         :refresh_binding,
         {socket.assigns.case.revision, socket.assigns.case.current_snapshot_id}
       )}
    else
      {:noreply, assign(socket, :notice, :invalid_request)}
    end
  end

  def handle_event("refresh_evidence_cancel", _params, socket) do
    {:noreply, socket |> assign(:refresh_confirm?, false) |> assign(:refresh_binding, nil)}
  end

  def handle_event("refresh_evidence_confirmed", _params, socket) do
    if editable?(socket) and socket.assigns.refresh_confirm? do
      {revision, snapshot_id} = socket.assigns.refresh_binding
      socket = socket |> assign(:refresh_confirm?, false) |> assign(:refresh_binding, nil)

      case Cases.refresh_evidence(socket.assigns.case.id, revision, snapshot_id) do
        {:ok, %{changed?: false}} ->
          {:noreply,
           put_flash(
             socket,
             :info,
             "Evidence re-checked — captured content is unchanged; no new snapshot was recorded."
           )}

        {:ok, _changed} ->
          {:noreply, reload_case(socket, :evidence_refreshed)}

        {:error, reason} ->
          {:noreply, assign(socket, :notice, notice_key(reason))}
      end
    else
      {:noreply, assign(socket, :notice, :invalid_request)}
    end
  end

  def handle_event("rebind_draft", _params, socket) do
    {:noreply, assign(socket, :rebind_confirm?, editable?(socket) and socket.assigns.dirty?)}
  end

  def handle_event("rebind_cancel", _params, socket),
    do: {:noreply, assign(socket, :rebind_confirm?, false)}

  def handle_event("rebind_confirmed", _params, socket) do
    if editable?(socket) and socket.assigns.rebind_confirm? do
      case Cases.get_case(socket.assigns.case.id) do
        {:ok, data} ->
          if data.case.revision == socket.assigns.case.revision and
               data.case.current_snapshot_id == socket.assigns.case.current_snapshot_id do
            {:noreply,
             socket
             |> assign(:expected_revision, data.case.revision)
             |> assign(:expected_snapshot_id, data.case.current_snapshot_id)
             |> assign(:idempotency_token, Ecto.UUID.generate())
             |> assign(:rebind_required?, false)
             |> assign(:rebind_confirm?, false)
             |> assign(:notice, :draft_rebound)}
          else
            {:noreply, socket |> assign_case(data) |> assign(:notice, :conflict)}
          end

        {:error, _} ->
          {:noreply, assign(socket, :notice, :not_found)}
      end
    else
      {:noreply, assign(socket, :notice, :invalid_request)}
    end
  end

  def handle_event("discard_draft", _params, socket),
    do:
      {:noreply,
       assign(
         socket,
         :discard_confirm?,
         socket.assigns.dirty? or not is_nil(socket.assigns.retained_draft)
       )}

  def handle_event("discard_cancel", _params, socket),
    do: {:noreply, assign(socket, :discard_confirm?, false)}

  def handle_event("discard_confirmed", _params, socket) do
    if socket.assigns.discard_confirm? do
      socket = socket |> assign(:retained_draft, nil) |> clear_draft()
      {:noreply, if(socket.assigns.case, do: reload_case(socket, nil), else: socket)}
    else
      {:noreply, assign(socket, :notice, :invalid_request)}
    end
  end

  defp editable?(socket),
    do: not is_nil(socket.assigns.case) and is_nil(socket.assigns.retained_draft)

  defp remember_draft(socket, params, changeset \\ nil) do
    changeset = changeset || Cases.change_review(params)

    socket
    |> assign(:review_form, to_form(%{changeset | action: :validate}))
    |> assign(:dirty?, true)
  end

  defp newer_draft?(socket, params, token) do
    socket.assigns.dirty? and
      (token != socket.assigns.idempotency_token or
         manual_params(params) != manual_params(socket.assigns.review_form.params))
  end

  defp manual_params(params),
    do: Map.take(params || %{}, ~w(applicability priority next_action rationale))

  defp clear_draft(socket) do
    socket
    |> assign(:dirty?, false)
    |> assign(:review_form, to_form(Cases.change_review()))
    |> assign(:idempotency_token, Ecto.UUID.generate())
    |> assign(:rebind_required?, false)
    |> assign(:discard_confirm?, false)
    |> assign(:rebind_confirm?, false)
    |> push_event("draft-saved", %{})
  end

  defp retain_departing_draft(socket, target) do
    if socket.assigns.case && socket.assigns.dirty? && target != {:ok, socket.assigns.case.id} do
      draft = %{
        case_id: socket.assigns.case.id,
        form: socket.assigns.review_form,
        revision: socket.assigns.expected_revision,
        snapshot_id: socket.assigns.expected_snapshot_id,
        token: socket.assigns.idempotency_token,
        rebind_required?: socket.assigns.rebind_required?
      }

      socket |> assign(:retained_draft, draft) |> assign(:dirty?, false)
    else
      socket
    end
  end

  defp reload_case(socket, notice) do
    case Cases.get_case(socket.assigns.case.id) do
      {:ok, data} ->
        loaded = assign_case(socket, data)
        if notice, do: assign(loaded, :notice, notice), else: loaded

      {:error, _} ->
        # A failed read is not permission to destroy the draft or its binding.
        assign(socket, :notice, :not_found)
    end
  end

  defp assign_case(socket, data) do
    review_case = data.case
    retained = socket.assigns.retained_draft
    restore? = retained && retained.case_id == review_case.id

    keep? =
      socket.assigns.case && socket.assigns.case.id == review_case.id && socket.assigns.dirty?

    {form, revision, snapshot_id, token, dirty?} =
      cond do
        restore? ->
          {retained.form, retained.revision, retained.snapshot_id, retained.token, true}

        keep? ->
          {socket.assigns.review_form, socket.assigns.expected_revision,
           socket.assigns.expected_snapshot_id, socket.assigns.idempotency_token, true}

        true ->
          {to_form(Cases.change_review()), review_case.revision, review_case.current_snapshot_id,
           socket.assigns.idempotency_token || Ecto.UUID.generate(), false}
      end

    prior_rebind_required? =
      if restore?, do: retained.rebind_required?, else: socket.assigns.rebind_required?

    evidence = evidence_view(data.snapshot && data.snapshot.payload)
    decision = Exceptions.latest_index([review_case.id])[review_case.id]

    socket
    |> assign(:exception_status, Exceptions.status(decision, Exceptions.binding(data)))
    |> assign(:case_error, nil)
    |> assign(:case, review_case)
    |> assign(:snapshot, data.snapshot)
    |> assign(:latest_review, Enum.max_by(data.reviews, & &1.id, fn -> nil end))
    |> assign(:evidence, evidence)
    |> assign(:page_title, case_title(evidence.finding[:cve], review_case.id))
    |> assign(:kev, Intel.kev_row(evidence.finding[:cve]))
    |> assign(:kev_status, Intel.kev_status())
    |> assign(:evidence_status, data.evidence_status)
    |> assign(:known_snapshot_ids, Enum.map(data.snapshots, & &1.id))
    |> assign(:expected_revision, revision)
    |> assign(:expected_snapshot_id, snapshot_id)
    |> assign(:idempotency_token, token)
    |> assign(:review_form, form)
    |> assign(:dirty?, dirty?)
    |> assign(:retained_draft, if(restore?, do: nil, else: retained))
    |> assign(
      :rebind_required?,
      dirty? and
        (revision != review_case.revision or snapshot_id != review_case.current_snapshot_id or
           prior_rebind_required?)
    )
    |> assign(:notice, status_notice(data.evidence_status))
    |> assign(:refresh_confirm?, false)
    |> assign(:refresh_binding, nil)
    |> assign(:rebind_confirm?, false)
    |> assign_back_scope(review_case)
    |> stream(:timeline, timeline_entries(data), reset: true)
    |> stream(:snapshots, snapshot_views(data), reset: true)
  end

  # Invalidate active identity on an invalid route, while keeping a detached
  # draft recoverable in this LiveView session. Queued writes still fail closed.
  defp invalidate_case(socket, reason) do
    socket
    |> assign(:case_error, reason)
    |> assign(:kev_status, nil)
    |> assign(:case, nil)
    |> assign(:snapshot, nil)
    |> assign(:latest_review, nil)
    |> assign(:evidence, empty_evidence())
    |> assign(:evidence_status, :current)
    |> assign(:expected_revision, nil)
    |> assign(:expected_snapshot_id, nil)
    |> assign(:idempotency_token, nil)
    |> assign(:known_snapshot_ids, [])
    |> assign(:review_form, to_form(Cases.change_review()))
    |> assign(:dirty?, false)
    |> assign(:notice, nil)
    |> assign(:refresh_confirm?, false)
    |> assign(:refresh_binding, nil)
    |> assign(:rebind_confirm?, false)
    |> assign(:rebind_required?, false)
    |> assign(:back_path, ~p"/findings")
    |> assign(:scope_mismatch?, false)
    |> assign(:back_filters, FindingFilters.defaults())
    |> assign(:invalid_back_scope, [])
    |> stream(:timeline, [], reset: true)
    |> stream(:snapshots, [], reset: true)
  end

  # Return context is separately labelled navigation state, never case scope.
  # Only the existing queue API's validated filters/cursor can enter a link.
  defp queue_return(%{"from" => "queue"} = params) do
    parsed = CaseFilters.parse(params)

    if parsed.invalid == [] do
      query = CaseFilters.query_params(parsed)
      if map_size(query) == 0, do: ~p"/cases", else: ~p"/cases?#{query}"
    end
  end

  defp queue_return(_), do: nil

  defp queue_path(review_case) do
    ~p"/cases?#{%{owner: review_case.owner, environment: review_case.environment}}"
  end

  # The back link is ALWAYS built from the case's own saved owner/environment
  # (the case scope), never from URL query parameters. The URL's q/suppressed
  # filters are preserved on the back link ONLY when the URL owner/environment
  # exactly match the saved case scope. On any owner/environment mismatch the
  # case is never relabelled, a visible #scope-mismatch notice is rendered and
  # the back link carries the case scope alone — so a mismatched query scope
  # can never leak a different team's context through the back link.
  defp assign_back_scope(socket, %{finding_id: finding_id, owner: owner, environment: environment}) do
    filters = socket.assigns.back_filters
    invalid = socket.assigns.invalid_back_scope

    if invalid != [] do
      # Malformed filter params were already reported visibly; the back link
      # resets to the findings index so no malformed value — and no link left
      # over from a previously rendered case — is carried anywhere.
      socket
      |> assign(:scope_mismatch?, false)
      |> assign(:back_path, ~p"/findings")
    else
      if filters.owner == owner and filters.environment == environment do
        socket
        |> assign(:scope_mismatch?, false)
        |> assign(:back_path, back_path(filters, finding_id))
      else
        socket
        |> assign(:scope_mismatch?, scope_mismatch?(filters, owner, environment))
        |> assign(
          :back_path,
          ~p"/findings/#{finding_id}?#{%{owner: owner, environment: environment}}"
        )
      end
    end
  end

  # The notice fires only for an actual mismatch: a query that simply omits
  # owner/environment still gets the case-scope back link, without a warning.
  defp scope_mismatch?(%{owner: q_owner, environment: q_environment}, owner, environment) do
    (not is_nil(q_owner) and q_owner != owner) or
      (not is_nil(q_environment) and q_environment != environment)
  end

  defp parse_case_id(id) when is_binary(id) do
    case Integer.parse(id) do
      {case_id, ""} when case_id > 0 and case_id <= @bigint_max -> {:ok, case_id}
      _ -> :error
    end
  end

  defp parse_case_id(_other), do: :error

  defp parse_meta(%{
         "expected_revision" => revision,
         "expected_snapshot_id" => snapshot_id,
         "idempotency_token" => token
       }) do
    with {:ok, revision} <- parse_bound_integer(revision),
         {:ok, snapshot_id} <- parse_bound_integer(snapshot_id),
         :ok <- valid_token(token) do
      {:ok, revision, snapshot_id, token}
    else
      _ -> :error
    end
  end

  defp parse_meta(_other), do: :error

  defp parse_bound_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, ""} when n > 0 and n <= @bigint_max -> {:ok, n}
      _ -> :error
    end
  end

  defp parse_bound_integer(_other), do: :error

  # The server issues only Ecto.UUID.generate/0 tokens: anything else —
  # NUL-containing binaries, non-UUID text, wrong length, non-binary — is
  # rejected at the LiveView boundary before any context call, so a forged
  # hidden token renders the visible #invalid-request notice with the draft
  # kept and never reaches an insert (where Postgrex would raise 22021 and
  # kill the LiveView).
  defp valid_token(token) when is_binary(token) do
    case Ecto.UUID.cast(token) do
      {:ok, _uuid} -> :ok
      :error -> :error
    end
  end

  defp valid_token(_other), do: :error

  # Keep the advisory id in the tab title: a reviewer with several cases open can see which
  # advisory each tab belongs to. A case without a captured id falls back to its own id.
  defp case_title(cve, id) when is_binary(cve) and cve != "", do: "#{cve} · Case #{id}"
  defp case_title(_cve, id), do: "Review case #{id}"

  defp notice_key(:conflict), do: :conflict
  defp notice_key(:evidence_stale), do: :evidence_stale
  defp notice_key(:token_reuse), do: :token_reuse
  defp notice_key(:source_out_of_scope), do: :source_out_of_scope
  defp notice_key(:invalid_request), do: :invalid_request
  defp notice_key(:not_found), do: :not_found

  # A read-only status derived by the context surfaces as the matching notice.
  defp status_notice(:changed), do: :evidence_stale
  defp status_notice(:source_out_of_scope), do: :source_out_of_scope
  defp status_notice(:source_missing), do: :source_missing
  defp status_notice(_other), do: nil

  # The advisory detail for this case, scoped to the case's SAVED scope and never
  # to the URL scope — the case page's own rule. A mismatched query scope can
  # therefore never widen or narrow the aggregate opened from this case.
  defp cve_path(cve, review_case) do
    ~p"/cves/#{cve}?#{%{owner: review_case.owner, environment: review_case.environment}}"
  end

  defp back_path(filters, finding_id) do
    qs = FindingFilters.query_params(filters)

    if map_size(qs) == 0 do
      ~p"/findings/#{finding_id}"
    else
      ~p"/findings/#{finding_id}?#{qs}"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="triage">
      <.retained_draft_notice retained_draft={@retained_draft} />

      <.discard_confirm discard_confirm?={@discard_confirm?} retained_draft={@retained_draft} />
      <%= cond do %>
        <% @case_error == :invalid_id -> %>
          <.page_header title="Invalid case URL" />
          <.notice id="invalid-case" kind="error">
            The case id must be a positive whole number within PostgreSQL bigint range. Nothing was loaded or written.
          </.notice>
          <.link navigate={~p"/findings"} class="button button-secondary">Back to inventory</.link>
        <% @case_error == :not_found -> %>
          <.page_header title="Case not found" />
          <.notice id="case-not-found" kind="error">
            No local case exists for this id. Nothing was written.
          </.notice>
          <.link navigate={~p"/findings"} class="button button-secondary">Back to inventory</.link>
        <% true -> %>
          <.page_header
            title={text(@evidence.finding[:cve])}
            eyebrow={"Review case ##{@case.id} · Revision #{@case.revision}"}
          >
            <:actions>
              <.link
                :if={linkable?(@evidence.finding[:cve])}
                id="case-cve-action"
                navigate={cve_path(@evidence.finding[:cve], @case)}
                class="button button-secondary"
              >Advisory detail</.link>
              <.link id="back-to-finding" navigate={@back_path} class="button button-secondary">Finding detail</.link>
              <.link
                id="back-to-cases"
                navigate={@queue_return || queue_path(@case)}
                class="button button-secondary"
              >Back to Review Queue</.link>
            </:actions>
          </.page_header>
          <p id="case-scope" class="filter-summary">
            Saved scope: <strong>{@case.owner}</strong>
            · <strong>{@case.environment}</strong>
            — fixed when opened.
          </p>
          <.notice :if={@invalid_back_scope != []} id="invalid-back-scope" kind="warning">
            Invalid URL filters were not applied to the case or finding back link.
          </.notice>
          <.notice :if={@scope_mismatch?} id="scope-mismatch" kind="warning">
            URL scope does not match this case. Evidence and assessment use the saved case scope only; the finding link uses that saved scope.
          </.notice>

          <div :if={@kev} id="case-kev" class="stack">
            <p class="cluster">
              <.kev_marker id="case-kev-badge" kev={@kev} />
              <span class="supporting">
                Cached KEV feed, populated by an explicit operator refresh — current public
                intelligence about this advisory, not saved case evidence. An advisory missing
                from the cache may still be exploited.
              </span>
            </p>
            <dl class="evidence-grid key-value">
              <div :if={@kev.due_date}>
                <dt>Recorded KEV due date</dt>
                <dd><.timestamp value={@kev.due_date} /></dd>
              </div>
              <div :if={@kev.known_ransomware}>
                <dt>Known ransomware campaign use</dt>
                <dd>Recorded in the cached entry</dd>
              </div>
              <div :if={@kev.required_action}>
                <dt>Recorded required action</dt>
                <dd>{@kev.required_action}</dd>
              </div>
            </dl>
          </div>

          <.kev_source_status id="case-kev-status" status={@kev_status} />

          <section id="case-local-exception" class="assessment-panel stack">
            <h2>Local exception / action status</h2>
            <p id="case-exception-status">{Exceptions.label(@exception_status)}</p>
            <p>
              Remediation and investigation belong in the assessment below. To temporarily suppress
              this occurrence or record “not affected”, use a separate scoped decision with a reason,
              evidence and a review date. This does not change scanner severity or remote suppression.
            </p>
            <.link
              id="case-exception-action"
              navigate={~p"/cases/#{@case.id}/exception"}
              class="button"
            >
              Manage local exception / reopen
            </.link>
          </section>

          <div id="case-workspace" class="case-workspace">
            <.evidence_snapshot
              evidence={@evidence}
              evidence_status={@evidence_status}
              snapshot={@snapshot}
              latest_review={@latest_review}
              case={@case}
              retained_draft={@retained_draft}
              notice={@notice}
              refresh_confirm?={@refresh_confirm?}
            />
            <.review_section
              case={@case}
              expected_revision={@expected_revision}
              expected_snapshot_id={@expected_snapshot_id}
              dirty?={@dirty?}
              notice={@notice}
              rebind_required?={@rebind_required?}
              rebind_confirm?={@rebind_confirm?}
              review_form={@review_form}
              idempotency_token={@idempotency_token}
              applicability_options={@applicability_options}
              priority_options={@priority_options}
              next_action_options={@next_action_options}
              evidence_status={@evidence_status}
              snapshot={@snapshot}
              retained_draft={@retained_draft}
            />
            <.case_details
              evidence={@evidence}
              snapshot={@snapshot}
              case={@case}
              streams={@streams}
            />
          </div>
      <% end %>
    </Layouts.app>
    """
  end
end
