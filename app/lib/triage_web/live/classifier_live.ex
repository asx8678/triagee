defmodule TriageWeb.ClassifierLive do
  @moduledoc "Human review of durable AI suggestions. Viewing this page never starts analysis."
  use TriageWeb, :live_view
  alias Triage.{Classifier, Workspace}
  alias Triage.Classifier.Policy

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Phoenix.PubSub.subscribe(Triage.PubSub, "classifier")

    {:ok,
     assign(socket,
       approval_target: nil,
       feedback_target: nil,
       error: nil,
       control_form: to_form(%{"reason" => ""}, as: :control),
       approval_form: to_form(%{}, as: :evidence),
       feedback_form: to_form(%{}, as: :feedback)
     )}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    cve =
      case params["cve"] do
        value when is_binary(value) ->
          if Regex.match?(~r/^CVE-\d{4}-\d{4,}$/i, value), do: String.upcase(value)

        _ ->
          nil
      end

    {:noreply,
     socket
     |> assign(
       cve: cve,
       approval_target: nil,
       feedback_target: nil,
       search_form: to_form(%{"cve" => cve || ""}, as: :search)
     )
     |> reload()}
  end

  defp reload(socket) do
    targets =
      if socket.assigns.cve, do: Workspace.targets(%{"cve" => socket.assigns.cve}), else: []

    entries = Classifier.list(socket.assigns.cve)

    socket
    |> assign(
      control: Classifier.control(),
      enabled: Classifier.enabled?(),
      automatic: Classifier.automatic?(),
      metrics: Classifier.metrics(),
      targets: targets,
      entries: entries
    )
    |> stream(:evidence, entries, reset: true)
  end

  @impl true
  def handle_event("search", %{"search" => %{"cve" => cve}}, socket),
    do:
      {:noreply,
       push_patch(socket, to: ~p"/classifier?#{%{cve: String.upcase(String.trim(cve))}}")}

  def handle_event("approve-form", %{"id" => id}, socket) do
    target = Enum.find(socket.assigns.targets, &(to_string(&1.id) == id))

    if target && socket.assigns.current_user.role == "admin" do
      now = Classifier.now()

      attrs = %{
        "workload_uid" => "",
        "service" => "",
        "source_ref" => "",
        "register_ref" => "",
        "applicability" => "unknown",
        "applicability_ref" => "",
        "rationale" => "",
        "cohort" => "",
        "mode" => "assisted",
        "observed_at" => DateTime.to_iso8601(now),
        "expires_at" => DateTime.to_iso8601(DateTime.add(now, 3600)),
        "complete" => false
      }

      {:noreply,
       assign(socket,
         approval_target: target,
         approval_form: to_form(attrs, as: :evidence),
         error: nil
       )}
    else
      {:noreply,
       assign(socket, error: "A provisioned administrator must approve an exact target.")}
    end
  end

  def handle_event(
        "approve",
        %{"evidence" => attrs},
        %{assigns: %{approval_target: target}} = socket
      )
      when not is_nil(target) do
    attrs = Map.put(attrs, "packet_hash", target.packet_hash)
    result = Classifier.approve(target.cve, target.id, attrs, socket.assigns.current_principal)

    case result do
      {:ok, _} ->
        {:noreply,
         socket
         |> assign(approval_target: nil, error: nil)
         |> put_flash(
           :info,
           "Snapshot approved. Automatic classification runs only when explicitly enabled; no decision was recorded."
         )
         |> reload()}

      {:error, reason} ->
        {:noreply,
         assign(socket, error: error_text(reason), approval_form: to_form(attrs, as: :evidence))}
    end
  end

  def handle_event("classify", %{"id" => id}, socket) do
    case parse_id(id) do
      nil ->
        {:noreply, assign(socket, error: "Invalid snapshot.")}

      evidence_id ->
        respond(
          socket,
          Classifier.request(evidence_id, socket.assigns.current_principal),
          "Analysis queued. This does not whitelist anything."
        )
    end
  end

  def handle_event("feedback-form", %{"id" => id, "run" => run_id}, socket) do
    entry = Enum.find(socket.assigns.entries, &(to_string(&1.id) == id))
    run = if entry, do: Enum.find(entry.runs, &(to_string(&1.id) == run_id))

    if entry && (run || run_id == "manual") do
      form =
        to_form(
          %{
            "rating" => "unsure",
            "classification" => "needs_human",
            "reason" => "",
            "effort_seconds" => "",
            "dangerous" => false
          },
          as: :feedback
        )

      {:noreply,
       assign(socket,
         feedback_target: %{evidence: entry.evidence, run: run},
         feedback_form: form,
         error: nil
       )}
    else
      {:noreply, assign(socket, error: "Result not found. Refresh the page.")}
    end
  end

  def handle_event(
        "feedback",
        %{"feedback" => attrs},
        %{assigns: %{feedback_target: target}} = socket
      )
      when not is_nil(target) do
    result =
      Classifier.feedback(
        target.evidence.id,
        if(target.run, do: target.run.id),
        attrs,
        socket.assigns.current_principal
      )

    case result do
      {:ok, _} ->
        respond(
          assign(socket, feedback_target: nil),
          result,
          "Feedback saved. No whitelist or operational decision was made."
        )

      {:error, reason} ->
        {:noreply,
         assign(socket, error: error_text(reason), feedback_form: to_form(attrs, as: :feedback))}
    end
  end

  def handle_event("pause", %{"control" => %{"reason" => reason}}, socket),
    do:
      respond(
        socket,
        Classifier.pause(socket.assigns.current_principal, reason),
        "Classifier paused. Existing findings and manual review remain available."
      )

  def handle_event("resume", %{"control" => %{"reason" => reason}}, socket),
    do:
      respond(
        socket,
        Classifier.resume(socket.assigns.current_principal, reason),
        "Classifier resumed. Old paused results are not automatically made usable."
      )

  def handle_event("refresh", _, socket), do: {:noreply, reload(socket)}
  def handle_event(_, _, socket), do: {:noreply, socket}

  @impl true
  def handle_info(:classifier_changed, socket), do: {:noreply, reload(socket)}

  defp respond(socket, {:ok, _}, message),
    do: {:noreply, socket |> assign(error: nil) |> put_flash(:info, message) |> reload()}

  defp respond(socket, {:error, reason}, _),
    do: {:noreply, assign(socket, error: error_text(reason))}

  defp parse_id(value) when is_binary(value) do
    case Integer.parse(value) do
      {id, ""} when id > 0 -> id
      _ -> nil
    end
  end

  defp parse_id(_), do: nil

  defp error_text(%Ecto.Changeset{}),
    do:
      "Check all required fields, evidence times and effort. A snapshot/result may be reviewed only once."

  defp error_text(reason) when is_atom(reason),
    do: reason |> Atom.to_string() |> String.replace("_", " ") |> String.capitalize()

  defp error_text(_), do: "The operation could not be completed. Nothing was approved."
  defp label(value), do: (value || "pending") |> String.replace("_", " ") |> String.capitalize()

  defp usable?(entry, run, control),
    do:
      entry.current? and run.state == "completed" and control != nil and not control.paused and
        run.control_revision == control.revision and
        run.profile == Triage.Classifier.Model.profile() and
        Policy.evaluate(
          Triage.Classifier.Snapshots.current_snapshot(entry.evidence, Classifier.now()),
          run.raw
        ).state == "completed"

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_scope={@current_scope} workspace>
      <div id="classifier-shell">
        <header class="topbar">
          <.link href={~p"/"} class="brand">PTV Triage</.link>
          <nav class="topnav" aria-label="Primary">
            <.link href={~p"/"}>Review</.link>
            <.link href={~p"/classifier"} class="active" aria-current="page">AI classifier</.link>
            <.link href={~p"/?page=daily"}>Timeline</.link>
          </nav>
          <Layouts.account current_scope={@current_scope} />
        </header>
        <main id="main-content" class="classifier-main">
          <h1>AI whitelist suggestions</h1>
          <p>
            Preparation only. A suggestion or reviewer rating never whitelists, tags, fixes, or suppresses a finding.
          </p>
          <p
            :if={@current_user.email == "local-user@triage.test"}
            id="classifier-local-preview"
            class="inline-notice"
          >
            Local preview: sign in with a provisioned account to submit experiment feedback or control analysis. An administrator must approve evidence first.
          </p>
          <section id="classifier-status" class="panel">
            <strong>{if @enabled,
              do: "Model connection enabled",
              else: "AI disabled — configure an approved model connection"}</strong>
            <p>
              {if @automatic,
                do: "Automatic: approved assisted snapshots are queued every minute.",
                else: "Automatic classification is off. Viewing this page never calls AI."}
            </p>
            <p>
              Approved snapshots are manual attestations, not a live Grafana/register integration. Maximum evidence age: 24 hours.
            </p>
            <p id="classifier-pause-status">
              {if @control && not @control.paused,
                do: "Safety control: running",
                else: "Safety control: paused / unavailable"} · {if @control, do: @control.reason}
            </p>
            <.form
              :if={@can_review}
              for={@control_form}
              id="classifier-control-form"
              phx-submit={if @control && @control.paused, do: "resume", else: "pause"}
            >
              <.input
                field={@control_form[:reason]}
                label="Pause / resume reason"
                required
                minlength="3"
                maxlength="2000"
              />
              <button
                id="classifier-control-submit"
                disabled={@control && @control.paused && @current_user.role != "admin"}
              >{if @control && @control.paused,
                do: "Resume (administrator only)",
                else: "Pause classifier"}</button>
            </.form>
          </section>
          <p :if={@error} id="classifier-error" class="form-error" role="alert">{@error}</p>
          <section id="classifier-metrics" class="panel">
            <h2>Experiment counts · all cohorts</h2>
            <p>
              Approved snapshots: {@metrics.approved} · Run intents: {@metrics.attempts} · Unsafe raw suggestions: {@metrics.unsafe} · Human safety reports: {@metrics.safety_reports}
            </p>
            <p>
              Right: {@metrics.ratings["right"] || 0} · Wrong: {@metrics.ratings["wrong"] || 0} · Unsure: {@metrics.ratings[
                "unsure"
              ] || 0}
            </p>
            <p :for={{state, count} <- Enum.sort(@metrics.states)}>{label(state)}: {count}</p>
            <p :for={{mode, effort} <- Enum.sort(@metrics.effort)}>
              {label(mode)}: {effort.count} reviews · {effort.seconds} self-reported active seconds total
            </p>
            <p>
              No accuracy or time-savings claim without comparable cohorts. Unreviewed, blocked and failed runs remain in the denominator. Remediation is not evaluated.
            </p>
          </section>
          <.form for={@search_form} id="classifier-search" phx-submit="search">
            <.input field={@search_form[:cve]} label="CVE" placeholder="CVE-2026-12345" />
            <button>Find targets and suggestions</button>
          </.form>
          <section :if={@cve} id="classifier-targets" class="panel">
            <h2>Recorded targets for {@cve}</h2>
            <p :if={@targets == []}>
              No active matching inventory. Public research CVEs are not deployment evidence.
            </p>
            <div :for={target <- @targets} id={"classifier-target-#{target.id}"}>
              <p>
                Placement {target.id} · {target.placement.owner} / {target.placement.environment} · {target.image.digest}
              </p>
              <button
                :if={@current_user.role == "admin" and target.active?}
                phx-click="approve-form"
                phx-value-id={target.id}
              >Approve a source/register snapshot</button>
            </div>
            <p :if={@current_user.role != "admin"}>
              A provisioned administrator must verify and approve evidence before it can be sent to the model.
            </p>
          </section>
          <section :if={@approval_target} class="panel">
            <h2>Approve exact-workload evidence · placement {@approval_target.id}</h2>
            <p>
              Verify these references independently. Approval authorizes model data disclosure, NOT a whitelist. Do not include credentials or secrets.
            </p>
            <.form for={@approval_form} id="classifier-approval-form" phx-submit="approve">
              <.input
                field={@approval_form[:workload_uid]}
                label="Verified immutable workload UID"
                required
              />
              <.input field={@approval_form[:service]} label="Verified service" required />
              <.input
                field={@approval_form[:source_ref]}
                label="Approved source snapshot / scan reference"
                required
              />
              <.input
                field={@approval_form[:register_ref]}
                label="Approved register mapping reference"
                required
              />
              <.input
                field={@approval_form[:applicability]}
                type="select"
                label="Verified applicability (unknown if not established)"
                options={~w(unknown affected not_affected)}
              />
              <.input
                field={@approval_form[:applicability_ref]}
                label="Applicability evidence reference (or explicit unknown)"
                required
              />
              <.input
                field={@approval_form[:rationale]}
                type="textarea"
                label="Evidence explanation / limitations"
                required
              />
              <.input field={@approval_form[:cohort]} label="Predeclared experiment cohort" required />
              <.input
                field={@approval_form[:mode]}
                type="select"
                label="Experiment arm"
                options={[
                  {"AI-assisted", "assisted"},
                  {"Manual baseline (never sent to AI)", "manual"}
                ]}
              />
              <.input
                field={@approval_form[:observed_at]}
                label="Source and register verified current as of (UTC ISO timestamp)"
                required
              />
              <.input
                field={@approval_form[:expires_at]}
                label="Evidence expires at (UTC; at most 24h after observation)"
                required
              />
              <.input
                field={@approval_form[:complete]}
                type="checkbox"
                label="I verified exact CVE/package/digest/workload mapping, source completeness and permission to disclose this snapshot to the configured model."
              />
              <button id="classifier-approve">Approve snapshot</button>
            </.form>
          </section>
          <section :if={@feedback_target} class="panel">
            <h2>Record human assessment · snapshot {@feedback_target.evidence.id}</h2>
            <p>
              Evaluate the frozen evidence and raw suggestion. This feedback is NOT an operational whitelist approval.
            </p>
            <.form for={@feedback_form} id="classifier-feedback-form" phx-submit="feedback">
              <.input
                :if={@feedback_target.run}
                field={@feedback_form[:rating]}
                type="select"
                label="Was the original AI classification right?"
                options={~w(unsure right wrong)}
              />
              <.input
                field={@feedback_form[:classification]}
                type="select"
                label="Your classification"
                options={Policy.dispositions()}
              />
              <.input
                field={@feedback_form[:reason]}
                type="textarea"
                label="Reason / correction"
                required
                minlength="3"
              />
              <.input
                field={@feedback_form[:effort_seconds]}
                type="number"
                label="Active review and correction time in seconds (exclude idle time)"
                min="1"
                max="14400"
                required
              />
              <.input
                field={@feedback_form[:dangerous]}
                type="checkbox"
                label="Safety incident: pause classification immediately"
              />
              <button id="classifier-save-feedback">Save feedback only</button>
            </.form>
          </section>
          <h2>Saved evidence and suggestions</h2>
          <p>
            Latest 50 snapshots in this view, up to 20 runs each. Global counts above include all stored runs.
          </p>
          <button id="classifier-refresh" phx-click="refresh">Refresh stored results</button>
          <div id="classifier-evidence" phx-update="stream">
            <article :for={{dom_id, entry} <- @streams.evidence} id={dom_id} class="panel">
              <h3>{entry.evidence.cve} · {entry.evidence.workload_uid} · snapshot {entry.id}</h3>
              <p>
                Placement {entry.evidence.placement_id} · {entry.evidence.snapshot["cohort"]} · {entry.evidence.snapshot[
                  "experiment_mode"
                ]} · {if entry.current?,
                  do: "Evidence current",
                  else: "Stale / changed — approve fresh evidence"}
              </p>
              <p>
                Expires: {entry.evidence.expires_at} · packet:
                <code>{entry.evidence.packet_hash}</code>
              </p>
              <details>
                <summary>Frozen source and register evidence</summary><pre>{Jason.encode!(entry.evidence.snapshot, pretty: true)}</pre>
              </details>
              <button
                :if={
                  @can_review && entry.current? &&
                    entry.evidence.snapshot["experiment_mode"] == "assisted" && entry.runs == []
                }
                id={"classify-#{entry.id}"}
                phx-click="classify"
                phx-value-id={entry.id}
                disabled={not @enabled || is_nil(@control) || @control.paused}
              >Queue AI classification</button>
              <button
                :if={
                  @can_review && entry.evidence.snapshot["experiment_mode"] == "manual" &&
                    entry.feedback == []
                }
                phx-click="feedback-form"
                phx-value-id={entry.id}
                phx-value-run="manual"
              >Record manual baseline</button>
              <div :for={run <- entry.runs} id={"classifier-run-#{run.id}"}>
                <h4>
                  {if usable?(entry, run, @control),
                    do: label(run.suggestion),
                    else: "Needs human review — " <> label(run.state)}
                </h4>
                <p>
                  Model: {run.model} · run {run.id} · {run.state} · profile <code>{run.profile}</code>
                </p>
                <p :if={usable?(entry, run, @control)}>{get_in(run.raw, ["output", "rationale"])}</p>
                <p :if={run.guard_reasons != []}>Guard: {Enum.join(run.guard_reasons, ", ")}</p>
                <details :if={run.input != %{}}>
                  <summary>
                    Exact evidence sent to AI · {run.prompt_version} / {run.policy_version}
                  </summary>
                  <pre>{Jason.encode!(run.input, pretty: true)}</pre>
                </details>
                <p :if={run.unsafe} class="form-error">
                  Unsafe raw whitelist suggestion recorded. Experiment paused.
                </p>
                <details :if={run.raw != %{}}>
                  <summary>Original AI output (untrusted; may be blocked)</summary><pre>{Jason.encode!(run.raw, pretty: true)}</pre>
                </details>
                <button
                  :if={
                    @can_review && run.state not in ~w(queued running) &&
                      not Enum.any?(entry.feedback, &(&1.run_id == run.id))
                  }
                  id={"review-classification-#{run.id}"}
                  phx-click="feedback-form"
                  phx-value-id={entry.id}
                  phx-value-run={run.id}
                >Rate original suggestion</button>
              </div>
              <p :for={feedback <- entry.feedback}>
                Recorded {feedback.mode} review: {feedback.rating || "baseline"} · {label(
                  feedback.classification
                )} · {feedback.effort_seconds} active seconds · reviewer {feedback.reviewer_id}
              </p>
              <.link href={~p"/?#{%{page: "review", item: entry.evidence.cve}}"}>Open manual CVE review</.link>
            </article>
          </div>
        </main>
      </div>
    </Layouts.app>
    """
  end
end
