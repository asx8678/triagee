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
  alias TriageWeb.{CaseFilters, FindingFilters}

  @bigint_max 9_223_372_036_854_775_807

  @applicability_options [
    {"Affected", "affected"},
    {"Not affected with evidence", "not_affected_with_evidence"},
    {"Unknown", "unknown"}
  ]

  @priority_options [
    {"Expedited review", "expedited_review"},
    {"Normal review", "normal_review"},
    {"Insufficient context", "insufficient_context"}
  ]

  @next_action_options [
    {"Investigation", "investigation"},
    {"Dependency update", "dependency_update"},
    {"Base image update", "base_image_update"},
    {"Rebuild and redeploy", "rebuild_deploy"},
    {"Mitigation review", "mitigation_review"},
    {"Exception proposal", "exception_proposal"}
  ]

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
     |> assign(:applicability_options, @applicability_options)
     |> assign(:priority_options, @priority_options)
     |> assign(:next_action_options, @next_action_options)
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

    socket
    |> assign(:case_error, nil)
    |> assign(:case, review_case)
    |> assign(:snapshot, data.snapshot)
    |> assign(:latest_review, Enum.max_by(data.reviews, & &1.id, fn -> nil end))
    |> assign(:evidence, evidence_view(data.snapshot && data.snapshot.payload))
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

  defp back_path(filters, finding_id) do
    qs = FindingFilters.query_params(filters)

    if map_size(qs) == 0 do
      ~p"/findings/#{finding_id}"
    else
      ~p"/findings/#{finding_id}?#{qs}"
    end
  end

  # The frozen snapshot payload is normalized into a plain display map so the
  # template never touches a live Inventory preload. Missing or malformed
  # payload values degrade to visible placeholders, never a crash.
  defp empty_evidence do
    %{
      schema_version: nil,
      source: nil,
      scope_owner: nil,
      scope_environment: nil,
      finding: %{},
      image: %{},
      placements: [],
      events: [],
      coverage: nil
    }
  end

  defp evidence_view(payload) when is_map(payload) do
    %{
      schema_version: pget(payload, "schema_version"),
      source: pget(payload, "source"),
      scope_owner: pget(pget(payload, "scope"), "owner"),
      scope_environment: pget(pget(payload, "scope"), "environment"),
      finding: %{
        cve: pget2(payload, "finding", "cve"),
        package_name: pget2(payload, "finding", "package_name"),
        package_version: pget2(payload, "finding", "package_version"),
        severity: pget2(payload, "finding", "severity"),
        fix: pget2(payload, "finding", "fix"),
        url: pget2(payload, "finding", "url"),
        description: pget2(payload, "finding", "description"),
        suppressed: pget2(payload, "finding", "suppressed"),
        first_seen: pget2(payload, "finding", "first_seen"),
        last_seen: pget2(payload, "finding", "last_seen"),
        resolved_at: pget2(payload, "finding", "resolved_at"),
        reopen_count: pget2(payload, "finding", "reopen_count")
      },
      image: %{
        digest: pget2(payload, "image", "digest"),
        repository: pget2(payload, "image", "repository"),
        tag: pget2(payload, "image", "tag"),
        description: pget2(payload, "image", "description")
      },
      placements: placement_views(pget(payload, "placements")),
      events: event_views(pget(payload, "events")),
      coverage: coverage_text(pget(payload, "coverage"))
    }
  end

  defp evidence_view(_other), do: empty_evidence()

  defp placement_views(list) when is_list(list) do
    for placement <- list do
      %{
        id: pget(placement, "id"),
        owner: pget(placement, "owner"),
        namespace: pget(placement, "namespace"),
        environment: pget(placement, "environment"),
        active: pget(placement, "active"),
        first_seen: pget(placement, "first_seen"),
        last_seen: pget(placement, "last_seen")
      }
    end
  end

  defp placement_views(_other), do: []

  defp event_views(list) when is_list(list) do
    for event <- list do
      %{
        id: pget(event, "id"),
        event: pget(event, "event"),
        occurred_at: pget(event, "occurred_at"),
        note: pget(event, "note")
      }
    end
  end

  defp event_views(_other), do: []

  defp pget(map, key) when is_map(map) and is_binary(key), do: Map.get(map, key)
  defp pget(_other, _key), do: nil

  defp pget2(map, key, sub), do: map |> pget(key) |> pget(sub)

  # The coverage payload entry is structured (kind + warning); only the plain
  # warning text is displayed, never a raw dump of the map.
  defp coverage_text(%{"warning" => warning}) when is_binary(warning), do: warning
  defp coverage_text(value), do: text(value)

  defp snapshot_views(data) do
    current_id = data.case.current_snapshot_id

    for snapshot <- data.snapshots do
      %{
        id: snapshot.id,
        version: snapshot.version,
        payload_hash: snapshot.payload_hash,
        captured_at: snapshot.captured_at,
        evidence: evidence_view(snapshot.payload),
        is_current: snapshot.id == current_id
      }
    end
  end

  # Timeline = case events + reviews, deterministically ordered (newest
  # first, stable tiebreak on the stream key). Every entry carries the same
  # shape so the template never depends on key presence per type.
  defp timeline_entries(data) do
    current_id = data.case.current_snapshot_id
    versions = Map.new(data.snapshots, &{&1.id, &1.version})

    event_entries =
      for event <- data.events do
        %{
          key: "event-#{event.id}",
          type: :event,
          at: event.inserted_at,
          kind: event.kind,
          actor: event.actor,
          case_revision: event.case_revision,
          snapshot_id: event.snapshot_id,
          review_id: event.review_id,
          detail_pairs: detail_pairs(event.detail),
          applicability: nil,
          priority: nil,
          next_action: nil,
          rationale: nil,
          snapshot_version: nil,
          is_stale: false
        }
      end

    review_entries =
      for review <- data.reviews do
        %{
          key: "review-#{review.id}",
          type: :review,
          at: review.inserted_at,
          kind: "review",
          actor: review.actor,
          case_revision: nil,
          snapshot_id: review.snapshot_id,
          review_id: review.id,
          detail_pairs: [],
          applicability: review.applicability,
          priority: review.priority,
          next_action: review.next_action,
          rationale: review.rationale,
          snapshot_version: versions[review.snapshot_id] || review.snapshot_id,
          is_stale: review.snapshot_id != current_id
        }
      end

    (event_entries ++ review_entries)
    |> Enum.sort_by(fn entry -> {-time_key(entry.at), entry.key} end)
  end

  defp detail_pairs(detail) when is_map(detail) do
    detail
    |> Map.keys()
    |> Enum.sort()
    |> Enum.map(fn key -> %{key: safe_text(key), value: safe_text(Map.get(detail, key))} end)
  end

  defp detail_pairs(_other), do: []

  defp safe_text(value) when is_binary(value), do: value
  defp safe_text(value), do: inspect(value)

  defp time_key(%DateTime{} = dt), do: DateTime.to_unix(dt)

  defp time_key(%NaiveDateTime{} = ndt),
    do: :calendar.datetime_to_gregorian_seconds(NaiveDateTime.to_erl(ndt))

  defp time_key(_other), do: 0

  defp text(value) when value in [nil, ""], do: "Not reported"
  defp text(value) when is_binary(value), do: value
  defp text(value), do: inspect(value)

  defp active_label(true), do: "active"
  defp active_label(false), do: "retired"
  defp active_label(_other), do: "Not captured"

  defp label(value) do
    options = @applicability_options ++ @priority_options ++ @next_action_options

    case Enum.find(options, fn {_label, key} -> key == value end) do
      {label, _} -> label
      nil -> event_label(value)
    end
  end

  defp event_label("case_opened"), do: "Case opened"
  defp event_label("evidence_captured"), do: "Evidence captured"
  defp event_label("review_saved"), do: "Assessment saved"
  defp event_label("disappeared"), do: "No longer observed in local inventory"
  defp event_label(value), do: text(value)

  defp image_reference(image) do
    case {image[:repository], image[:tag]} do
      {repository, tag}
      when is_binary(repository) and repository != "" and is_binary(tag) and tag != "" ->
        repository <> ":" <> tag

      {repository, _} when is_binary(repository) and repository != "" ->
        repository

      _ ->
        image[:digest]
    end
  end

  defp source_label("synthetic_local_inventory"), do: "Synthetic local inventory"
  defp source_label(value), do: text(value)

  defp evidence_label(:current), do: "Local evidence match"
  defp evidence_label(:changed), do: "Local evidence changed"
  defp evidence_label(:source_out_of_scope), do: "Source out of saved scope"
  defp evidence_label(_), do: "Source unavailable"

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="cases">
      <section
        :if={@retained_draft}
        id="retained-draft"
        class="notice"
        role="status"
        phx-hook="DirtyDraft"
        data-dirty="true"
      >
        <h2>Unsaved draft retained for case #{@retained_draft.case_id}</h2>
        <p>
          The route changed, not the draft's identity. Return to that case to continue, or explicitly discard it. Other assessment forms are locked until then. This draft exists only in this connected session.
        </p>
        <div class="cluster">
          <.link
            id="return-to-draft"
            data-draft-preserving="true"
            patch={~p"/cases/#{@retained_draft.case_id}"}
            class="button button-secondary"
          >Return to draft</.link>
          <button
            id="retained-discard-btn"
            type="button"
            phx-click="discard_draft"
            class="button button-secondary"
          >Discard retained draft…</button>
        </div>
      </section>
      <div
        :if={@discard_confirm?}
        id="discard-draft-confirm"
        class="notice"
        role="alert"
        phx-hook="FocusReturn"
        data-return-focus={
          if @retained_draft, do: "retained-discard-btn", else: "review_applicability"
        }
      >
        <p>Discard this unsaved assessment? This cannot be undone. Saved history is unchanged.</p>
        <div class="cluster">
          <button
            id="discard-confirm-btn"
            type="button"
            phx-click="discard_confirmed"
            class="button button-secondary"
          >Yes, discard draft</button>
          <button
            id="discard-cancel-btn"
            type="button"
            phx-click="discard_cancel"
            class="button button-secondary"
          >Keep draft</button>
        </div>
      </div>
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

          <div id="case-workspace" class="case-workspace">
            <section
              id="evidence-snapshot"
              class="case-summary stack"
              aria-labelledby="evidence-heading"
            >
              <div class="section-header">
                <h2 id="evidence-heading">Captured evidence</h2>
                <.status_badge label={evidence_label(@evidence_status)} />
              </div>
              <p :if={@snapshot} class="supporting">
                Snapshot v{@snapshot.version} · Captured <.timestamp value={@snapshot.captured_at} />
              </p>
              <p :if={is_nil(@snapshot)} class="notice">
                No evidence snapshot is available. Do not assess missing evidence.
              </p>
              <dl class="evidence-grid">
                <div class="key-value">
                  <dt>Package · installed version</dt><dd>
                    {text(@evidence.finding[:package_name])}
                    <code>{text(@evidence.finding[:package_version])}</code>
                  </dd>
                </div>
                <div class="key-value">
                  <dt>Scanner severity</dt><dd>
                    <.status_badge label={text(@evidence.finding[:severity])} kind="severity" />
                  </dd>
                </div>
                <div class="key-value">
                  <dt>Reported fixed version</dt><dd>{text(@evidence.finding[:fix])}</dd>
                </div>
                <div class="key-value">
                  <dt>Source</dt><dd>{source_label(@evidence.source)}</dd>
                </div>
              </dl>
              <.technical_value
                id="case-image-reference"
                label="Image reference"
                value={image_reference(@evidence.image)}
              />
              <p id="case-assessment-state" class="supporting">
                <%= if @latest_review do %>
                  Assessment recorded · Saved <.timestamp value={@latest_review.inserted_at} />
                  · {if @latest_review.snapshot_id == @case.current_snapshot_id,
                    do: "Recorded for displayed snapshot",
                    else: "Needs revalidation — recorded for older snapshot"}
                <% else %>
                  No assessment recorded
                <% end %>
              </p>
              <section
                id="evidence-limitations"
                class="evidence-limitations stack"
                aria-labelledby="evidence-limitations-heading"
              >
                <h3 id="evidence-limitations-heading">Evidence limitations</h3>
                <p class="supporting">
                  Frozen local snapshot — not live inventory, production freshness, verified remediation or mitigation evidence.
                </p>
                <details id="evidence-limitations-details" class="disclosure">
                  <summary>Read full limitations</summary>
                  <p>
                    Frozen local evidence, not live inventory or proof of production freshness. A reported fix is not a verified fix.
                  </p>
                  <p :if={@evidence.finding[:suppressed]}>
                    Suppressed in captured inventory — not mitigation evidence.
                  </p>
                  <p :if={@evidence.finding[:resolved_at]}>
                    No longer observed at capture:
                    <.timestamp value={@evidence.finding[:resolved_at]} />. This is not verified remediation.
                  </p>
                  <p class="supporting">{text(@evidence.coverage)}</p>
                </details>
              </section>
              <.notice
                :if={@evidence_status == :changed or @notice == :evidence_stale}
                id="evidence-stale"
                kind="warning"
                title="Local evidence changed"
              >
                The local source differs from the captured snapshot, or the submitted snapshot is no longer current. New assessments are blocked until you explicitly refresh evidence and re-check your draft. Reloading the case does not capture evidence.
              </.notice>
              <.notice
                :if={@evidence_status == :source_out_of_scope or @notice == :source_out_of_scope}
                id="source-out-of-scope"
                kind="warning"
              >
                No active placement remains in the saved scope. New captures and assessments are blocked; frozen evidence and history remain readable.
              </.notice>
              <.notice :if={@evidence_status == :source_missing} id="source-missing" kind="warning">
                Source data is unavailable. New captures and assessments are blocked. Missing data is not evidence of safety.
              </.notice>
              <div class="cluster">
                <button
                  id="reload-case"
                  type="button"
                  phx-click="reload"
                  phx-disable-with="Reloading…"
                  class="button button-secondary"
                >Reload saved case</button>
                <button
                  id="refresh-evidence-btn"
                  type="button"
                  phx-click="refresh_evidence"
                  disabled={not is_nil(@retained_draft)}
                  class="button button-secondary"
                >Refresh evidence…</button>
              </div>
              <p class="supporting">
                Reload reads saved history only. Refresh may append a new snapshot; neither saves an assessment.
              </p>
              <div
                :if={@refresh_confirm?}
                id="refresh-evidence-confirm"
                class="notice"
                role="alert"
                phx-hook="FocusReturn"
                data-return-focus="refresh-evidence-btn"
              >
                <h3>Recapture evidence now?</h3>
                <p>
                  Changed content appends a snapshot and revision; older evidence and reviews stay unchanged. Your draft and original binding are kept, never submitted automatically.
                </p>
                <div class="cluster">
                  <button
                    id="refresh-evidence-confirm-btn"
                    type="button"
                    phx-click="refresh_evidence_confirmed"
                    phx-disable-with="Recapturing…"
                    class="button"
                  >Yes, recapture now</button>
                  <button
                    id="refresh-evidence-cancel-btn"
                    type="button"
                    phx-click="refresh_evidence_cancel"
                    class="button button-secondary"
                  >Cancel</button>
                </div>
              </div>
            </section>

            <section
              id="review-section"
              class="assessment-panel stack"
              aria-labelledby="assessment-heading"
            >
              <h2 id="assessment-heading">Local assessment</h2>
              <p id="case-banner" class="supporting">
                Saved locally by unauthenticated local-operator. This does not approve an exception, suppress a finding, or verify a fix.
              </p>
              <p id="draft-binding" class="supporting">
                Draft binding: case #{@case.id} · revision {@expected_revision} · snapshot #{@expected_snapshot_id}.
                <strong :if={@dirty?}>Unsaved changes</strong>
              </p>
              <div id="assessment-feedback" aria-live="polite">
                <.notice :if={@notice == :conflict} id="case-conflict" kind="warning">
                  This case changed. Your draft remains bound to revision {@expected_revision} and snapshot #{@expected_snapshot_id}; nothing was overwritten. Reload the saved case, inspect the newer history/evidence, then choose “Use reviewed evidence for draft”.
                </.notice>
                <.notice :if={@notice == :token_reuse} id="token-reuse" kind="warning">
                  This token already belongs to a different assessment. Your draft was kept. Reload, inspect the saved history, then choose “Use reviewed evidence for draft” to explicitly start a new submission token.
                </.notice>
                <.notice :if={@notice == :invalid_request} id="invalid-request" kind="error">
                  Malformed or unconfirmed request; nothing was written. Your draft was kept. Reload the saved case and re-check its binding before retrying.
                </.notice>
                <.notice :if={@notice == :not_found} id="case-missing" kind="error">
                  The saved case could not be loaded. Your draft was kept. Retry “Reload saved case”; do not refresh or resubmit until it is available.
                </.notice>
                <.notice :if={@notice == :validation} id="review-validation" kind="error">
                  Assessment not saved. Correct the marked fields; your draft and binding were kept.
                </.notice>
                <.notice :if={@notice == :evidence_refreshed} id="evidence-refreshed">
                  A new evidence snapshot was recorded. Your draft was not saved or rebound. Inspect the evidence before choosing “Use reviewed evidence for draft”.
                </.notice>
                <.notice :if={@notice == :draft_recovered} id="draft-recovered">
                  Draft recovered with its original case, revision, snapshot and submission token. Check the binding before saving.
                </.notice>
                <.notice :if={@notice == :recovery_failed} id="draft-recovery-failed" kind="warning">
                  Draft text recovered, but its original binding could not be verified. Saving is blocked. Check this case's evidence and explicitly rebind, or discard the draft.
                </.notice>
                <.notice :if={@notice == :draft_rebound} id="draft-rebound">
                  Draft explicitly bound to the reviewed evidence with a new submission token. Nothing has been saved; re-check all fields before saving.
                </.notice>
              </div>
              <div :if={@rebind_required?} id="draft-binding-conflict" class="notice">
                <p>
                  Draft binding needs review. Displayed case: revision {@case.revision}, snapshot #{@case.current_snapshot_id}. The draft still has its original binding above.
                </p>
              </div>
              <button
                :if={@dirty?}
                id="rebind-draft-btn"
                type="button"
                phx-click="rebind_draft"
                class="button button-secondary"
              >Use reviewed evidence for draft…</button>
              <div
                :if={@rebind_confirm?}
                id="rebind-draft-confirm"
                class="notice"
                role="alert"
                phx-hook="FocusReturn"
                data-return-focus="rebind-draft-btn"
              >
                <p>
                  Have you checked the displayed evidence and newer history? Keep all draft fields, bind them to revision {@case.revision} / snapshot #{@case.current_snapshot_id}, and issue a new submission token? This does not save anything.
                </p>
                <div class="cluster">
                  <button
                    id="rebind-confirm-btn"
                    type="button"
                    phx-click="rebind_confirmed"
                    class="button button-secondary"
                  >Yes, use reviewed evidence</button>
                  <button
                    id="rebind-cancel-btn"
                    type="button"
                    phx-click="rebind_cancel"
                    class="button button-secondary"
                  >Keep original binding</button>
                </div>
              </div>
              <.form
                id="review-form"
                for={@review_form}
                phx-change="validate"
                phx-auto-recover="recover_draft"
                phx-submit="save"
                phx-hook="DirtyDraft"
                data-dirty={to_string(@dirty?)}
              >
                <input type="hidden" name="meta[case_id]" value={@case.id} />
                <input type="hidden" name="meta[expected_revision]" value={@expected_revision} />
                <input type="hidden" name="meta[expected_snapshot_id]" value={@expected_snapshot_id} />
                <input type="hidden" name="meta[idempotency_token]" value={@idempotency_token} />
                <fieldset disabled={not is_nil(@retained_draft)}>
                  <legend class="supporting">All four fields are required</legend>
                  <.input
                    field={@review_form[:applicability]}
                    type="select"
                    label="Applicability *"
                    options={@applicability_options}
                    prompt="Select applicability"
                    required
                    aria-describedby="applicability-help"
                  />
                  <p id="applicability-help" class="supporting">
                    “Not affected” requires evidence in your rationale. Choose “Unknown” when applicability is unclear.
                  </p>
                  <.input
                    field={@review_form[:priority]}
                    type="select"
                    label="Priority *"
                    options={@priority_options}
                    prompt="Select priority"
                    required
                    aria-describedby="priority-help"
                  />
                  <p id="priority-help" class="supporting">
                    Review urgency, not scanner severity or approval.
                  </p>
                  <.input
                    field={@review_form[:next_action]}
                    type="select"
                    label="Next action *"
                    options={@next_action_options}
                    prompt="Select next action"
                    required
                    aria-describedby="next-action-help"
                  />
                  <p id="next-action-help" class="supporting">
                    Records a proposed next step; it does not execute it.
                  </p>
                  <.input
                    field={@review_form[:rationale]}
                    type="textarea"
                    label="Rationale *"
                    rows="4"
                    maxlength="2000"
                    required
                    aria-describedby="rationale-help"
                  />
                  <p id="rationale-help" class="supporting">
                    Explain applicability, evidence and next step. Maximum 2,000 characters.
                  </p>
                  <div id="assessment-actions" class="cluster assessment-actions">
                    <button
                      id="save-review-btn"
                      type="submit"
                      disabled={
                        @rebind_required? or @evidence_status != :current or is_nil(@snapshot)
                      }
                      phx-disable-with="Saving…"
                      data-confirm="Save this assessment to local append-only history? This does not approve an exception or verify a fix."
                      class="button"
                    >Save local assessment</button>
                    <button
                      :if={@dirty?}
                      id="discard-draft-btn"
                      type="button"
                      phx-click="discard_draft"
                      class="button button-secondary"
                    >Discard draft…</button>
                  </div>
                </fieldset>
              </.form>
            </section>

            <section
              id="case-details"
              class="case-details stack"
              aria-label="Detailed captured evidence and history"
            >
              <details id="evidence-details" class="disclosure">
                <summary>Detailed captured evidence · description, placements and lifecycle</summary>
                <.evidence_facts evidence={@evidence} id="current-evidence" />
              </details>
              <details id="technical-metadata" class="disclosure">
                <summary>Technical metadata · digest, content hash, schema and pointers</summary>
                <.technical_value
                  id="case-image-digest"
                  label="Image digest"
                  value={@evidence.image[:digest]}
                />
                <.technical_value
                  id="case-content-hash"
                  label="Snapshot content hash"
                  value={@snapshot && @snapshot.payload_hash}
                />
                <dl class="evidence-grid">
                  <div class="key-value">
                    <dt>Payload schema</dt><dd>{text(@evidence.schema_version)}</dd>
                  </div>
                  <div class="key-value">
                    <dt>Current snapshot id</dt><dd>{text(@case.current_snapshot_id)}</dd>
                  </div>
                </dl>
              </details>
              <details id="case-history" class="disclosure">
                <summary>Case history · append-only assessments and events</summary>
                <p class="supporting">
                  Newest save/event time first. Assessments remain attached to the snapshot they reviewed.
                </p>
                <div id="case-timeline" phx-update="stream" class="event-list">
                  <article :for={{id, entry} <- @streams.timeline} id={id} class="event-item">
                    <div class="section-header">
                      <h3>
                        {if entry.type == :review,
                          do: "Manual assessment — #{label(entry.applicability)}",
                          else: label(entry.kind)}
                      </h3>
                      <span>Saved <.timestamp value={entry.at} /></span>
                    </div>
                    <p :if={entry.type == :review}>
                      Priority: {label(entry.priority)} · Next action: {label(entry.next_action)}
                    </p>
                    <p :if={entry.type == :review and entry.rationale}>{entry.rationale}</p>
                    <p :if={entry.type == :review} class="supporting">
                      Saved against snapshot v{entry.snapshot_version} by {entry.actor}
                    </p>
                    <.status_badge
                      :if={entry.type == :review and entry.is_stale}
                      label="Needs revalidation — saved against older evidence"
                      kind="warning"
                    />
                    <p :if={entry.type == :event} class="supporting">
                      Case revision {entry.case_revision} · actor {entry.actor}<span :if={
                        entry.snapshot_id
                      }> · snapshot #{entry.snapshot_id}</span><span :if={entry.review_id}> · assessment #{entry.review_id}</span>
                    </p>
                    <details :if={entry.detail_pairs != []} class="disclosure">
                      <summary>Recorded event details</summary>
                      <dl class="evidence-grid">
                        <div :for={pair <- entry.detail_pairs} class="key-value">
                          <dt>{pair.key}</dt><dd>{pair.value}</dd>
                        </div>
                      </dl>
                    </details>
                  </article>
                </div>
              </details>
              <details id="snapshots-section" class="disclosure">
                <summary>Evidence snapshots · older evidence stays inspectable</summary>
                <div id="snapshots" phx-update="stream" class="stack">
                  <details :for={{id, snapshot} <- @streams.snapshots} id={id} class="disclosure">
                    <summary>
                      Snapshot v{snapshot.version}{if(snapshot.is_current,
                        do: " — latest captured",
                        else: " — superseded"
                      )}
                    </summary>
                    <p>Captured <.timestamp value={snapshot.captured_at} /></p>
                    <.technical_value
                      id={"snapshot-hash-#{snapshot.id}"}
                      label="Snapshot content hash"
                      value={snapshot.payload_hash}
                    />
                    <.evidence_facts
                      evidence={snapshot.evidence}
                      id={"historical-evidence-#{snapshot.id}"}
                    />
                  </details>
                </div>
              </details>
            </section>
          </div>
      <% end %>
    </Layouts.app>
    """
  end

  # All detailed facts come from immutable captured payloads, never live preloads.
  attr :evidence, :map, required: true
  attr :id, :string, required: true

  defp evidence_facts(assigns) do
    ~H"""
    <dl class="evidence-grid">
      <div class="key-value">
        <dt>Advisory</dt><dd>{text(@evidence.finding[:cve])}</dd>
      </div>
      <div class="key-value">
        <dt>Package · installed version</dt><dd>
          {text(@evidence.finding[:package_name])} {text(@evidence.finding[:package_version])}
        </dd>
      </div>
      <div class="key-value">
        <dt>Scanner severity</dt><dd>{text(@evidence.finding[:severity])}</dd>
      </div>
      <div class="key-value">
        <dt>Reported fixed version</dt><dd>{text(@evidence.finding[:fix])}</dd>
      </div>
      <div class="key-value">
        <dt>First observed</dt><dd><.timestamp value={@evidence.finding[:first_seen]} /></dd>
      </div>
      <div class="key-value">
        <dt>Last observed</dt><dd><.timestamp value={@evidence.finding[:last_seen]} /></dd>
      </div>
      <div :if={@evidence.finding[:resolved_at]} class="key-value">
        <dt>No longer observed in local inventory</dt><dd>
          <.timestamp value={@evidence.finding[:resolved_at]} /> — not verified remediation
        </dd>
      </div>
      <div :if={@evidence.finding[:suppressed]} class="key-value">
        <dt>Captured suppression</dt><dd>Suppressed — not mitigation evidence</dd>
      </div>
      <div class="key-value">
        <dt>Scanner description (captured)</dt><dd>{text(@evidence.finding[:description])}</dd>
      </div>
    </dl>
    <.technical_value
      id={"#{@id}-image"}
      label="Image reference"
      value={image_reference(@evidence.image)}
    />
    <.technical_value id={"#{@id}-digest"} label="Image digest" value={@evidence.image[:digest]} />
    <h3>Scoped placements (captured)</h3>
    <p :if={@evidence.placements == []} class="muted">No placements captured.</p>
    <div
      :if={@evidence.placements != []}
      class="table-region"
      role="region"
      tabindex="0"
      aria-label="Captured scoped placements"
    >
      <table class="data-table">
        <thead>
          <tr>
            <th scope="col">Team</th><th scope="col">Namespace</th><th scope="col">Environment</th><th scope="col">
              Placement state
            </th><th scope="col">First observed</th><th scope="col">Last observed</th>
          </tr>
        </thead>
        <tbody>
          <tr :for={placement <- @evidence.placements}>
            <td>{text(placement.owner)}</td><td>{text(placement.namespace)}</td><td>
              {text(placement.environment)}
            </td><td>{active_label(placement.active)}</td><td>
              <.timestamp value={placement.first_seen} />
            </td><td><.timestamp value={placement.last_seen} /></td>
          </tr>
        </tbody>
      </table>
    </div>
    <h3>Finding lifecycle (captured)</h3>
    <p :if={@evidence.events == []} class="muted">No lifecycle events captured.</p>
    <ul class="event-list">
      <li :for={event <- @evidence.events} class="event-item">
        {label(event.event)} ·
        <.timestamp value={event.occurred_at} /><p :if={event.note}>{text(event.note)}</p>
      </li>
    </ul>
    <p class="supporting">{text(@evidence.coverage)}</p>
    """
  end
end
