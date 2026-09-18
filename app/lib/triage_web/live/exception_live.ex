defmodule TriageWeb.ExceptionLive do
  @moduledoc """
  Explicit local exception decisions, separate from the manual assessment form.
  Browser metadata must match the displayed server binding. Recovered/conflicting
  drafts cannot silently move to new evidence; rebinding requires an explicit act.
  """
  use TriageWeb, :live_view
  alias Triage.{Cases, Exceptions}

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Local exception")
     |> assign(:data, nil)
     |> assign(:error, nil)
     |> assign(:blocked?, false)
     |> assign(:status, :action_required)
     |> assign(:token, Ecto.UUID.generate())
     |> assign(:form, to_form(Exceptions.change(%{"kind" => "accepted_risk"}), as: :exception))
     |> assign(:history_count, 0)
     |> stream(:decisions, [])}
  end

  @impl true
  def handle_params(%{"id" => id}, _uri, socket) do
    with {case_id, ""} <- Integer.parse(id),
         {:ok, data} <- Cases.get_case(case_id) do
      socket =
        if socket.assigns.data && socket.assigns.data.case.id != case_id do
          assign(
            socket,
            :form,
            to_form(Exceptions.change(%{"kind" => "accepted_risk"}), as: :exception)
          )
        else
          socket
        end

      {:noreply, load(socket, data)}
    else
      _ -> {:noreply, socket |> assign(:data, nil) |> assign(:error, "Case unavailable.")}
    end
  end

  @impl true
  def handle_event("validate", %{"exception" => attrs}, socket) do
    {:noreply, assign_form(socket, attrs)}
  end

  def handle_event("recover", %{"exception" => attrs}, socket) do
    {:noreply,
     socket
     |> assign_form(attrs)
     |> block("Draft recovered. Review the evidence and explicitly rebind before saving.")}
  end

  def handle_event("save", %{"exception" => attrs, "meta" => meta}, socket) do
    socket = assign_form(socket, attrs)

    if not socket.assigns.blocked? and matches_binding?(socket, meta) do
      cse = socket.assigns.data.case

      case Exceptions.submit(
             cse.id,
             cse.revision,
             cse.current_snapshot_id,
             socket.assigns.token,
             attrs
           ) do
        {:ok, %{replayed?: replayed?}} ->
          {:ok, data} = Cases.get_case(cse.id)

          message =
            if replayed?,
              do: "Original local decision kept.",
              else: "Local decision saved. Scanner data is unchanged."

          {:noreply,
           socket
           |> assign(
             :form,
             to_form(Exceptions.change(%{"kind" => "accepted_risk"}), as: :exception)
           )
           |> load(data)
           |> put_flash(:info, message)}

        {:error, %Ecto.Changeset{} = changeset} ->
          {:noreply,
           assign(socket, :form, to_form(%{changeset | action: :validate}, as: :exception))}

        {:error, reason} ->
          {:noreply, block(socket, error_text(reason))}
      end
    else
      {:noreply,
       block(
         socket,
         "The submission does not match the displayed case and evidence. Review and rebind the draft."
       )}
    end
  end

  def handle_event("rebind", _params, socket) do
    case socket.assigns.data do
      nil ->
        {:noreply, block(socket, "Case unavailable.")}

      data ->
        case Cases.get_case(data.case.id) do
          {:ok, fresh} ->
            {:noreply,
             socket
             |> load(fresh)
             |> put_flash(:info, "Draft rebound to displayed evidence. Check it before saving.")}

          _ ->
            {:noreply, block(socket, "Case unavailable. Your draft was kept.")}
        end
    end
  end

  def handle_event(_event, _params, socket),
    do: {:noreply, block(socket, "Malformed request. Nothing was saved.")}

  defp load(socket, data) do
    decisions = Exceptions.history(data.case.id)
    latest = List.first(decisions)

    socket
    |> assign(:data, data)
    |> assign(:status, Exceptions.status(latest, Exceptions.binding(data)))
    |> assign(:error, nil)
    |> assign(:blocked?, false)
    |> assign(:token, Ecto.UUID.generate())
    |> assign(:history_count, length(decisions))
    |> assign(:tomorrow, Date.add(Date.utc_today(), 1))
    |> assign(:latest_date, Date.add(Date.utc_today(), 90))
    |> stream(:decisions, decisions, reset: true)
  end

  defp assign_form(socket, attrs) do
    changeset = Exceptions.change(attrs)
    assign(socket, :form, to_form(%{changeset | action: :validate}, as: :exception))
  end

  defp block(socket, message), do: socket |> assign(:error, message) |> assign(:blocked?, true)

  defp matches_binding?(%{assigns: %{data: nil}}, _meta), do: false

  defp matches_binding?(socket, meta) when is_map(meta) do
    cse = socket.assigns.data.case

    meta["case_id"] == to_string(cse.id) and
      meta["revision"] == to_string(cse.revision) and
      meta["snapshot_id"] == to_string(cse.current_snapshot_id) and
      meta["token"] == socket.assigns.token
  end

  defp matches_binding?(_socket, _meta), do: false

  defp error_text(:evidence_stale),
    do:
      "Source evidence changed or left scope. Return to the assessment, refresh and inspect its evidence before making another exception. Reopening remains available."

  defp error_text(:conflict),
    do:
      "Another decision, assessment or evidence refresh changed this case. Review the new history and rebind your draft."

  defp error_text(:token_reuse),
    do:
      "Submission token already used for another decision. Review the history and explicitly rebind."

  defp error_text(_), do: "Decision not saved. Review the case and rebind your draft."

  defp decision_label("reopened"), do: "Reopened / exception revoked"
  defp decision_label("accepted_risk"), do: "Temporary local suppression / risk acceptance"
  defp decision_label("not_affected"), do: "Not affected with evidence"

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="cases">
      <.page_header
        title="Local exception"
        subtitle="A scoped, time-limited operator decision — not a global CVE whitelist."
      />
      <p :if={@error} id="exception-error" class="notice" role="alert">{@error}</p>
      <%= if @data do %>
        <p id="exception-scope" class="filter-summary">
          Case #{@data.case.id} · {@data.case.owner} / {@data.case.environment} ·
          finding #{@data.case.finding_id} · snapshot #{@data.case.current_snapshot_id} · revision {@data.case.revision}
        </p>
        <p id="exception-package">
          {@data.snapshot.payload["finding"]["cve"]} · {@data.snapshot.payload["finding"][
            "package_name"
          ]}
          <code>{@data.snapshot.payload["finding"]["package_version"]}</code>
        </p>
        <.technical_value
          id="exception-image"
          label="Scoped image digest"
          value={@data.snapshot.payload["image"]["digest"]}
        />
        <p id="exception-status" role="status"><strong>{Exceptions.label(@status)}</strong></p>
        <p id="exception-evidence-status">
          Evidence: {@data.evidence_status}. Status is checked when the page is loaded or a decision is saved.
        </p>
        <.link
          id="exception-back"
          navigate={~p"/cases/#{@data.case.id}"}
          class="button button-secondary"
        >Back to assessment and evidence</.link>

        <section id="exception-procedure" class="stack">
          <h2>Decide safely</h2>
          <ol>
            <li>
              Confirm this package, image, team and environment. Inspect the frozen evidence and current exploitation signals on the assessment page.
            </li>
            <li>
              Prefer a fix or mitigation. If risk must remain, record temporary risk acceptance. Use “Not affected” only with specific applicability evidence; missing data is not evidence of safety.
            </li>
            <li>
              Provide a reason and review date, at most 90 days away. The exception expires at 00:00 UTC on that date. Changed evidence or a later assessment requires another review.
            </li>
            <li>
              Reopen at any time with a reason. History is retained; renewals are explicit new decisions.
            </li>
          </ol>
          <p class="supporting">
            This local, unauthenticated operator decision does not change scanner severity, import/export facts,
            or remote suppression. Findings stay visible in inventory and reports. Local action badges indicate the exception separately.
          </p>
        </section>

        <section id="exception-controls" class="assessment-panel stack">
          <h2>Record decision</h2>
          <.form
            for={@form}
            id="exception-form"
            phx-change="validate"
            phx-auto-recover="recover"
            phx-submit="save"
          >
            <input type="hidden" name="meta[case_id]" value={@data.case.id} />
            <input type="hidden" name="meta[revision]" value={@data.case.revision} />
            <input type="hidden" name="meta[snapshot_id]" value={@data.case.current_snapshot_id} />
            <input type="hidden" name="meta[token]" value={@token} />
            <.input
              field={@form[:kind]}
              type="select"
              label="Decision"
              required
              options={[
                {"Temporarily suppress locally / accept risk", "accepted_risk"},
                {"Not affected — with evidence", "not_affected"},
                {"Reopen / revoke exception", "reopened"}
              ]}
            />
            <.input
              field={@form[:reason]}
              type="textarea"
              label="Reason / risk justification"
              required
              maxlength="2000"
            />
            <%= if @form[:kind].value != "reopened" do %>
              <.input
                field={@form[:evidence]}
                type="textarea"
                label="Evidence / reference (required for not affected)"
                required={@form[:kind].value == "not_affected"}
                maxlength="2000"
              />
              <.input
                field={@form[:review_by]}
                type="date"
                label="Review / expiry date (00:00 UTC)"
                min={Date.to_iso8601(@tomorrow)}
                max={Date.to_iso8601(@latest_date)}
                required
              />
            <% end %>
            <button
              id="exception-save"
              type="submit"
              class="button"
              disabled={@blocked?}
              phx-disable-with="Saving…"
              data-confirm="Save this local decision for only the displayed package, team and environment? Scanner data remains unchanged."
            >Save local decision</button>
          </.form>
          <button
            id="exception-rebind"
            type="button"
            phx-click="rebind"
            class="button button-secondary"
            data-confirm="Have you reviewed the current evidence? Reload the latest case and bind this draft to it. Nothing is saved yet."
          >Reload history and use current evidence for draft</button>
        </section>

        <section id="exception-history" class="stack">
          <h2>Decision history</h2>
          <p :if={@history_count == 0} id="exception-history-empty">No local decisions recorded.</p>
          <ol id="exception-history-rows" phx-update="stream" class="event-list">
            <li :for={{dom_id, decision} <- @streams.decisions} id={dom_id} class="event-item">
              <h3>{decision_label(decision.kind)}</h3>
              <p>{decision.reason}</p>
              <p :if={decision.evidence}>Evidence: {decision.evidence}</p>
              <p :if={decision.review_by}>
                Review by / expires: {Date.to_iso8601(decision.review_by)} at 00:00 UTC
              </p>
              <p class="supporting">
                {decision.actor} (unauthenticated) · <.timestamp value={decision.inserted_at} />
                · snapshot #{decision.snapshot_id} · original revision {decision.expected_revision}
              </p>
            </li>
          </ol>
        </section>
      <% end %>
    </Layouts.app>
    """
  end
end
