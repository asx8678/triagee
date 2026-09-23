defmodule Triage.Classifier do
  @moduledoc "Durable, human-reviewed whitelist suggestions. No decision or external-action write capability."
  import Ecto.Query
  import Ecto.Changeset
  alias Triage.{Accounts, Repo}

  alias Triage.Classifier.{
    Control,
    Event,
    Evidence,
    Feedback,
    Model,
    Policy,
    Run,
    Snapshots,
    Worker
  }

  def control, do: Repo.get(Control, 1)
  def enabled?, do: Model.enabled?()
  def automatic?, do: Model.automatic?()
  def now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  def approve(cve, placement_id, attrs, principal) do
    with {:ok, user} <- provisioned(principal, :admin),
         {:ok, evidence} <- Snapshots.prepare(cve, placement_id, attrs, user, now()) do
      Repo.transaction(fn -> insert_evidence!(evidence) end)
    end
  end

  defp insert_evidence!(evidence) do
    case Repo.insert(evidence, on_conflict: :nothing, conflict_target: :identity) do
      {:ok, _} -> Repo.get_by!(Evidence, identity: evidence.identity)
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  def request(evidence_id, principal) do
    with {:ok, _} <- provisioned(principal, :review), do: enqueue(evidence_id)
  end

  def enqueue(evidence_id, origin \\ :manual) do
    Repo.transaction(fn -> enqueue!(evidence_id, origin) end)
  end

  defp enqueue!(evidence_id, origin) do
    require_ready!()
    evidence = Repo.get(Evidence, evidence_id) || Repo.rollback(:not_found)
    current = Snapshots.current?(evidence)
    validate_consent!(evidence, current, origin)

    Repo.get_by(Run, evidence_id: evidence.id, profile: Model.profile()) ||
      insert_run!(evidence, current)
  end

  defp validate_consent!(evidence, current, origin) do
    if not current and origin == :manual, do: Repo.rollback(:stale_evidence)

    unless evidence.snapshot["approved_model_profile"] == Model.profile(),
      do: Repo.rollback(:model_consent_changed)

    unless evidence.snapshot["experiment_mode"] == "assisted",
      do: Repo.rollback(:manual_baseline_only)
  end

  defp insert_run!(evidence, current) do
    run =
      Repo.insert!(%Run{evidence_id: evidence.id, profile: Model.profile(), model: Model.model()})

    if current do
      {:ok, _job} = Oban.insert(Worker.new(%{run_id: run.id}))
      run
    else
      Repo.update!(
        change(run,
          state: "stale",
          suggestion: "needs_human",
          guard_reasons: ["evidence_changed_before_automatic_queue"],
          finished_at: now()
        )
      )
    end
  end

  def enqueue_approved do
    if Model.automatic?() do
      profile = Model.profile()

      ids =
        Repo.all(
          from e in Evidence,
            left_join: r in Run,
            on: r.evidence_id == e.id and r.profile == ^profile,
            where:
              is_nil(r.id) and e.expires_at > ^now() and
                fragment("?->>'experiment_mode' = 'assisted'", e.snapshot) and
                fragment("?->>'approved_model_profile' = ?", e.snapshot, ^profile),
            order_by: e.id,
            limit: 50,
            select: e.id
        )

      Enum.map(ids, &enqueue(&1, :automatic))
    else
      []
    end
  end

  def perform(id) do
    case begin_run(id) do
      {:ok, {:call, run, evidence}} ->
        result = Model.classify(run.input)
        finish_run(run, evidence, result)

      {:ok, :done} ->
        :ok

      {:error, reason} when reason in [:paused, :disabled, :safety_state_missing] ->
        {:snooze, 60}

      {:error, _} ->
        :ok
    end
  end

  defp begin_run(id) do
    Repo.transaction(fn ->
      control = require_ready!()

      run =
        Repo.one(from r in Run, where: r.id == ^id, lock: "FOR UPDATE") ||
          Repo.rollback(:not_found)

      evidence = Repo.get!(Evidence, run.evidence_id)

      cond do
        run.state != "queued" ->
          :done

        run.profile != Model.profile() or not Snapshots.current?(evidence) ->
          Repo.update!(
            change(run,
              state: "stale",
              suggestion: "needs_human",
              guard_reasons: ["evidence_or_configuration_changed"],
              finished_at: now()
            )
          )

          :done

        true ->
          run =
            Repo.update!(
              change(run,
                state: "running",
                started_at: now(),
                control_revision: control.revision,
                input:
                  Snapshots.current_snapshot(evidence, now())
                  |> Jason.encode!()
                  |> Jason.decode!(),
                prompt_version: Model.prompt_version(),
                policy_version: Policy.version()
              )
            )

          {:call, run, evidence}
      end
    end)
  end

  defp finish_run(original, evidence, result) do
    outcome = Repo.transaction(fn -> finish_locked!(original, evidence, result) end)
    broadcast()

    case outcome do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp finish_locked!(original, evidence, result) do
    control = locked_control!()
    run = Repo.one!(from r in Run, where: r.id == ^original.id, lock: "FOR UPDATE")

    if run.state == "running" do
      fields = result_fields(run, evidence, result)
      control = maybe_pause_unsafe!(control, run, fields)
      fields = publication_fields(run, evidence, fields, control)
      Repo.update!(change(run, Map.put(fields, :finished_at, now())))
    end
  end

  defp maybe_pause_unsafe!(control, run, %{unsafe: true}),
    do:
      pause_locked!(control, nil, run.id, "Unsafe raw whitelist suggestion", "unsafe_suggestion")

  defp maybe_pause_unsafe!(control, _, _), do: control

  defp publication_fields(run, evidence, fields, control) do
    cond do
      not Model.enabled?() or control.paused or control.revision != run.control_revision ->
        blocked_publication(fields, "paused", "publication_paused")

      Model.profile() != run.profile or not Snapshots.current?(evidence) ->
        blocked_publication(fields, "stale", "evidence_or_configuration_changed")

      true ->
        fields
    end
  end

  defp blocked_publication(fields, state, reason),
    do:
      Map.merge(fields, %{
        state: state,
        suggestion: "needs_human",
        guard_reasons: fields.guard_reasons ++ [reason]
      })

  defp result_fields(run, evidence, {:ok, raw}) do
    original = Policy.evaluate(run.input, raw)
    evaluated = Policy.evaluate(Snapshots.current_snapshot(evidence, now()), raw)

    %{
      raw: raw,
      state: evaluated.state,
      suggestion: evaluated.suggestion,
      guard_reasons: evaluated.reasons,
      unsafe: evaluated.unsafe or original.unsafe
    }
  end

  defp result_fields(_, _, {:error, reason}),
    do: %{
      raw: %{},
      state: "failed",
      suggestion: "needs_human",
      guard_reasons: [to_string(reason)],
      unsafe: false
    }

  # Never silently retry an uncertain provider call after a worker/process crash.
  def recover_interrupted do
    cutoff = DateTime.add(now(), -120, :second)

    Repo.update_all(from(r in Run, where: r.state == "running" and r.started_at < ^cutoff),
      set: [
        state: "interrupted",
        suggestion: "needs_human",
        guard_reasons: ["worker_interrupted_no_automatic_retry"],
        finished_at: now()
      ]
    )
  end

  def pause(principal, reason), do: change_control(principal, reason, true)
  def resume(principal, reason), do: change_control(principal, reason, false)

  defp change_control(principal, reason, paused) do
    permission = if paused, do: :review, else: :admin

    with {:ok, user} <- provisioned(principal, permission), :ok <- reason_valid(reason) do
      result = Repo.transaction(fn -> update_control!(user, reason, paused) end)
      broadcast()
      result
    end
  end

  defp update_control!(user, reason, paused) do
    control = locked_control!()
    action = if paused, do: "paused", else: "resumed"
    Repo.insert!(%Event{action: action, actor_id: user.id, reason: String.trim(reason)})

    Repo.update!(
      change(control, paused: paused, revision: control.revision + 1, reason: String.trim(reason))
    )
  end

  def feedback(evidence_id, run_id, attrs, principal) do
    with {:ok, user} <- provisioned(principal, :review) do
      result = Repo.transaction(fn -> record_feedback!(evidence_id, run_id, attrs, user) end)
      broadcast()
      result
    end
  end

  defp record_feedback!(evidence_id, run_id, attrs, user) do
    control = locked_control!()
    evidence = Repo.get(Evidence, evidence_id) || Repo.rollback(:not_found)
    run = if run_id, do: Repo.get(Run, run_id)
    validate_feedback_target!(evidence, run, run_id)
    changeset = feedback_changeset(evidence, run, attrs, user)

    case Repo.insert(changeset) do
      {:ok, feedback} ->
        if feedback.dangerous,
          do: pause_locked!(control, user.id, run_id, feedback.reason, "reviewer_safety_report")

        feedback

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  defp feedback_changeset(evidence, run, attrs, user) do
    %Feedback{
      evidence_id: evidence.id,
      run_id: if(run, do: run.id),
      reviewer_id: user.id,
      mode: if(run, do: "assisted", else: "manual")
    }
    |> cast(attrs, [:rating, :classification, :reason, :effort_seconds, :dangerous])
    |> update_change(:reason, &String.trim/1)
    |> validate_required([:classification, :reason, :effort_seconds])
    |> validate_inclusion(:classification, Policy.dispositions())
    |> validate_length(:reason, min: 3, max: 2000)
    |> validate_number(:effort_seconds, greater_than: 0, less_than_or_equal_to: 14_400)
    |> unique_constraint(:run_id)
    |> unique_constraint([:evidence_id, :reviewer_id, :mode])
    |> validate_rating(run)
  end

  defp validate_rating(changeset, nil), do: put_change(changeset, :rating, nil)

  defp validate_rating(changeset, run) do
    changeset =
      changeset
      |> validate_required(:rating)
      |> validate_inclusion(:rating, ~w(right wrong unsure))

    original = get_in(run.raw, ["output", "classification"])

    if get_field(changeset, :rating) == "right" and
         get_field(changeset, :classification) != original,
       do: add_error(changeset, :rating, "right must agree with the original classification"),
       else: changeset
  end

  defp validate_feedback_target!(evidence, nil, nil) do
    unless evidence.snapshot["experiment_mode"] == "manual",
      do: Repo.rollback(:manual_baseline_only)

    if Repo.exists?(from r in Run, where: r.evidence_id == ^evidence.id),
      do: Repo.rollback(:baseline_must_precede_analysis)
  end

  defp validate_feedback_target!(evidence, %Run{} = run, _) do
    if run.evidence_id != evidence.id or run.state in ~w(queued running),
      do: Repo.rollback(:invalid_feedback_target)
  end

  defp validate_feedback_target!(_, _, _), do: Repo.rollback(:invalid_feedback_target)

  def list(cve \\ nil) do
    query = from e in Evidence, order_by: [desc: e.id], limit: 50
    query = if cve, do: where(query, [e], e.cve == ^cve), else: query

    Enum.map(Repo.all(query), fn evidence ->
      runs =
        Repo.all(
          from r in Run, where: r.evidence_id == ^evidence.id, order_by: [desc: r.id], limit: 20
        )

      %{
        id: evidence.id,
        evidence: evidence,
        current?: Snapshots.current?(evidence),
        runs: runs,
        feedback: Repo.all(from f in Feedback, where: f.evidence_id == ^evidence.id)
      }
    end)
  end

  def metrics do
    # Aggregate complete stored denominators; never derive totals from the 50-row UI page.
    states =
      Repo.all(from r in Run, group_by: r.state, select: {r.state, count(r.id)}) |> Map.new()

    ratings =
      Repo.all(
        from f in Feedback,
          where: f.mode == "assisted",
          group_by: f.rating,
          select: {f.rating, count(f.id)}
      )
      |> Map.new()

    effort =
      Repo.all(
        from f in Feedback,
          group_by: f.mode,
          select: {f.mode, %{count: count(f.id), seconds: sum(f.effort_seconds)}}
      )
      |> Map.new()

    %{
      approved: Repo.aggregate(Evidence, :count),
      attempts: Enum.sum(Map.values(states)),
      states: states,
      ratings: ratings,
      effort: effort,
      unsafe: Repo.aggregate(from(r in Run, where: r.unsafe), :count),
      safety_reports: Repo.aggregate(from(f in Feedback, where: f.dangerous), :count)
    }
  end

  defp require_ready! do
    control = locked_control!()
    unless Model.enabled?(), do: Repo.rollback(:disabled)
    if control.paused, do: Repo.rollback(:paused)
    control
  end

  defp locked_control!,
    do:
      Repo.one(from c in Control, where: c.id == 1, lock: "FOR UPDATE") ||
        Repo.rollback(:safety_state_missing)

  defp pause_locked!(control, actor, run, reason, action) do
    Repo.insert!(%Event{action: action, actor_id: actor, run_id: run, reason: reason})
    Repo.update!(change(control, paused: true, revision: control.revision + 1, reason: reason))
  end

  defp provisioned(principal, permission) do
    with {:ok, user} <- Accounts.authorize(principal, permission) do
      if user.email == "local-user@triage.test",
        do: {:error, :provisioned_account_required},
        else: {:ok, user}
    end
  end

  defp reason_valid(reason) when is_binary(reason) do
    if String.length(String.trim(reason)) in 3..2000, do: :ok, else: {:error, :reason_required}
  end

  defp reason_valid(_), do: {:error, :reason_required}
  defp broadcast, do: Phoenix.PubSub.broadcast(Triage.PubSub, "classifier", :classifier_changed)
end
