defmodule Triage.ClassifierTest do
  use Triage.DataCase, async: false
  import Triage.ClassifierFixtures
  use Oban.Testing, repo: Triage.Repo
  alias Triage.Classifier
  alias Triage.Classifier.{Control, Event, Evidence, Feedback, Model, Run, Snapshots, Worker}

  setup do
    configure()
    %{admin: principal(:admin), reviewer: principal(:reviewer), viewer: principal(:viewer)}
  end

  test "C01 admin approval captures exact evidence and rejects forged identity, stale hashes and missing provenance",
       ctx do
    %{target: target} = target_fixture()
    attrs = approval_attrs(target)
    assert {:error, :forbidden} = Classifier.approve(target.cve, target.id, attrs, ctx.reviewer)
    assert {:error, :forbidden} = Classifier.approve(target.cve, target.id, attrs, ctx.viewer)

    assert {:error, :evidence_changed} =
             Classifier.approve(
               target.cve,
               target.id,
               Map.put(attrs, "packet_hash", "forged"),
               ctx.admin
             )

    assert {:error, %Ecto.Changeset{}} =
             Classifier.approve(
               target.cve,
               target.id,
               Map.put(attrs, "complete", false),
               ctx.admin
             )

    assert {:error, %Ecto.Changeset{}} =
             Classifier.approve(
               target.cve,
               target.id,
               Map.put(attrs, "register_ref", ""),
               ctx.admin
             )

    assert {:ok, evidence} =
             Classifier.approve(
               target.cve,
               target.id,
               Map.put(attrs, "approved_by", "forged"),
               ctx.admin
             )

    assert evidence.snapshot["inventory"]["image_digest"] == target.image.digest
    assert evidence.snapshot["register"]["workload_uid"] == attrs["workload_uid"]
    assert evidence.packet_hash == target.packet_hash
    assert evidence.snapshot["source"]["kind"] == "human_attested_snapshot"
    assert {:ok, duplicate} = Classifier.approve(target.cve, target.id, attrs, ctx.admin)
    assert duplicate.id == evidence.id
    assert Repo.aggregate(Evidence, :count) == 1
  end

  test "C01 stale/future source evidence cannot be approved", ctx do
    %{target: target} = target_fixture()
    now = Classifier.now()

    for overrides <- [
          %{"observed_at" => DateTime.to_iso8601(DateTime.add(now, 60))},
          %{"expires_at" => DateTime.to_iso8601(now)},
          %{"expires_at" => DateTime.to_iso8601(DateTime.add(now, 86_401))}
        ] do
      assert {:error, :stale_evidence} =
               Classifier.approve(
                 target.cve,
                 target.id,
                 approval_attrs(target, overrides),
                 ctx.admin
               )
    end
  end

  test "C04 explicit request is durable and idempotent; viewing results never calls the model",
       ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin)
    provider(response())
    assert {:error, :forbidden} = Classifier.request(evidence.id, ctx.viewer)
    assert {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    assert {:ok, duplicate} = Classifier.request(evidence.id, ctx.reviewer)
    assert duplicate.id == run.id
    assert Repo.aggregate(Oban.Job, :count) == 1
    assert [%{runs: [%{state: "queued"}]}] = Classifier.list(target.cve)
    refute_received {:model_request, _}
    before_count = Repo.aggregate(Triage.Decisions.Decision, :count)
    assert :ok = perform_job(Worker, %{run_id: run.id})
    assert_received {:model_request, request}
    assert request.options[:redirect] == false
    stored = Repo.get!(Run, run.id)
    assert stored.state == "completed"
    assert stored.suggestion == "whitelist_candidate"
    assert stored.input["inventory"]["packet_hash"] == evidence.packet_hash
    assert stored.prompt_version == Model.prompt_version()
    assert stored.policy_version == Triage.Classifier.Policy.version()
    assert stored.raw["output"] == response()
    assert Repo.aggregate(Triage.Decisions.Decision, :count) == before_count
    assert :ok = perform_job(Worker, %{run_id: run.id})
    refute_received {:model_request, _}
  end

  test "C03 internal-only and unknown applicability cannot yield a whitelist", ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin, %{"applicability" => "unknown"})
    provider(response())
    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    assert :ok = Classifier.perform(run.id)
    stored = Repo.get!(Run, run.id)
    assert stored.state == "blocked"
    assert stored.suggestion == "needs_human"
    assert "internal_only_is_not_non_applicability" in stored.guard_reasons
    refute Classifier.control().paused
  end

  test "C03/C06 dangerous raw suggestion is retained and atomically pauses further processing",
       ctx do
    %{target: target} =
      target_fixture(severity: "CRITICAL", exposure: "internet_exposed", kev: true)

    evidence = approve(target, ctx.admin)
    provider(response())
    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    assert :ok = Classifier.perform(run.id)
    stored = Repo.get!(Run, run.id)
    assert stored.unsafe
    assert stored.state == "paused"
    assert stored.suggestion == "needs_human"
    assert stored.raw["output"]["classification"] == "whitelist_candidate"
    assert Classifier.control().paused
    assert Repo.get_by!(Event, run_id: run.id).action == "unsafe_suggestion"
    assert {:error, :paused} = Classifier.request(evidence.id, ctx.reviewer)
    assert Classifier.metrics().unsafe == 1
  end

  test "C06 pause then resume during inference prevents publication under an old revision", ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin)

    provider(response(), fn _ ->
      assert {:ok, _} = Classifier.pause(ctx.reviewer, "Investigating safety")
      assert {:ok, _} = Classifier.resume(ctx.admin, "Investigation completed")
    end)

    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    assert :ok = Classifier.perform(run.id)
    assert Repo.get!(Run, run.id).state == "paused"
    refute Classifier.control().paused
    assert Repo.aggregate(Event, :count) == 2
  end

  test "C01 changes before inference cause zero calls; changes during inference invalidate publication",
       ctx do
    %{target: target, finding: finding} = target_fixture()
    evidence = approve(target, ctx.admin)
    provider(response())
    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    Repo.update!(change(finding, description: "Changed material evidence"))
    assert :ok = Classifier.perform(run.id)
    assert Repo.get!(Run, run.id).state == "stale"
    refute_received {:model_request, _}

    [new_target] =
      Triage.Workspace.targets(%{"cve" => target.cve, "placement_ids" => [target.id]})

    fresh = approve(new_target, ctx.admin)

    provider(response(), fn _ ->
      Repo.update!(
        change(Repo.get!(Triage.Inventory.Finding, finding.id), description: "Changed again")
      )
    end)

    {:ok, fresh_run} = Classifier.request(fresh.id, ctx.reviewer)
    assert :ok = Classifier.perform(fresh_run.id)
    assert Repo.get!(Run, fresh_run.id).state == "stale"
  end

  test "C04 invalid and failed outputs are terminal measured attempts, not hidden retries", ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin)
    provider(%{"classification" => "whitelist_candidate", "rationale" => "No citations"})
    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    assert :ok = Classifier.perform(run.id)
    assert Repo.get!(Run, run.id).state == "invalid"
    assert Classifier.metrics().states["invalid"] == 1
    assert Classifier.metrics().attempts == 1
  end

  test "C05 manual baseline is never analyzed; feedback stores identity, effort and original result",
       ctx do
    %{target: target} = target_fixture()
    baseline = approve(target, ctx.admin, %{"mode" => "manual"})
    provider(response())
    assert {:error, :manual_baseline_only} = Classifier.request(baseline.id, ctx.reviewer)
    assert {:ok, manual} = Classifier.feedback(baseline.id, nil, feedback_attrs(), ctx.reviewer)
    assert manual.mode == "manual"
    assert manual.rating == nil
    assert manual.effort_seconds == 95
    evidence = approve(target, ctx.admin)
    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)

    assert {:error, :invalid_feedback_target} =
             Classifier.feedback(evidence.id, run.id, feedback_attrs(), ctx.reviewer)

    assert :ok = Classifier.perform(run.id)

    assert {:ok, feedback} =
             Classifier.feedback(
               evidence.id,
               run.id,
               feedback_attrs(%{"reviewer_id" => -1, "mode" => "manual"}),
               ctx.reviewer
             )

    assert feedback.reviewer_id > 0
    assert feedback.mode == "assisted"

    assert {:error, %Ecto.Changeset{}} =
             Classifier.feedback(evidence.id, run.id, feedback_attrs(), ctx.reviewer)

    assert Classifier.metrics().ratings == %{"right" => 1}
    assert Classifier.metrics().effort["manual"].seconds == 95
    assert Repo.aggregate(Feedback, :count) == 2
  end

  test "C05 dangerous reviewer feedback pauses; viewers, forged targets and invalid effort are rejected",
       ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin)
    provider(response("needs_human"))
    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    Classifier.perform(run.id)

    assert {:error, :forbidden} =
             Classifier.feedback(evidence.id, run.id, feedback_attrs(), ctx.viewer)

    assert {:error, :invalid_feedback_target} =
             Classifier.feedback(evidence.id, run.id + 100, feedback_attrs(), ctx.reviewer)

    assert {:error, %Ecto.Changeset{}} =
             Classifier.feedback(
               evidence.id,
               run.id,
               feedback_attrs(%{"effort_seconds" => "0"}),
               ctx.reviewer
             )

    assert {:ok, _} =
             Classifier.feedback(
               evidence.id,
               run.id,
               feedback_attrs(%{"rating" => "wrong", "dangerous" => true}),
               ctx.reviewer
             )

    assert Classifier.control().paused
    assert Classifier.metrics().safety_reports == 1
    assert {:error, :forbidden} = Classifier.resume(ctx.reviewer, "Not permitted")
    assert {:error, :reason_required} = Classifier.resume(ctx.admin, " ")
    assert {:ok, _} = Classifier.resume(ctx.admin, "Reviewed and corrected")
    refute Classifier.control().paused
  end

  test "C04 automatic discovery processes only approved assisted snapshots and stays bounded/idempotent",
       ctx do
    %{target: target} = target_fixture()
    approve(target, ctx.admin)
    approve(target, ctx.admin, %{"mode" => "manual"})
    assert Classifier.enqueue_approved() == []
    Application.put_env(:triage, Model, Keyword.put(Model.config(), :automatic, true))
    assert [{:ok, _}] = Classifier.enqueue_approved()
    assert [] = Classifier.enqueue_approved()
    assert Repo.aggregate(Run, :count) == 1
  end

  test "C06 missing safety state and disabled model fail closed", ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin)
    Application.put_env(:triage, Model, Keyword.put(Model.config(), :enabled, false))
    assert {:error, :disabled} = Classifier.request(evidence.id, ctx.reviewer)
    Repo.delete!(Repo.get!(Control, 1))
    assert {:error, :safety_state_missing} = Classifier.request(evidence.id, ctx.reviewer)
    assert Repo.aggregate(Run, :count) == 0
  end

  test "C04 interrupted runs remain visible and cannot be silently resent", ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin)
    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    Repo.update!(change(run, state: "running", started_at: DateTime.add(Classifier.now(), -180)))
    assert {1, _} = Classifier.recover_interrupted()
    assert Repo.get!(Run, run.id).state == "interrupted"
    provider(response())
    assert :ok = Classifier.perform(run.id)
    refute_received {:model_request, _}
  end

  test "C01 model endpoint changes require fresh disclosure consent", ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin)

    Application.put_env(
      :triage,
      Model,
      Keyword.put(Model.config(), :url, "https://other.example.test/inference")
    )

    assert {:error, :model_consent_changed} = Classifier.request(evidence.id, ctx.reviewer)
    fresh = approve(target, ctx.admin)
    assert fresh.id != evidence.id
    assert {:ok, _} = Classifier.request(fresh.id, ctx.reviewer)
  end

  test "C04 automatic stale snapshots get terminal records rather than starving later work",
       ctx do
    %{target: target, finding: finding} = target_fixture()
    evidence = approve(target, ctx.admin)
    Repo.update!(change(finding, description: "Changed before discovery"))
    Application.put_env(:triage, Model, Keyword.put(Model.config(), :automatic, true))
    assert [{:ok, run}] = Classifier.enqueue_approved()
    assert run.evidence_id == evidence.id
    assert run.state == "stale"
    assert Classifier.enqueue_approved() == []
    assert Repo.aggregate(Oban.Job, :count) == 0
  end

  test "C03 highest scanner severity is retained even when risk-priority ties", ctx do
    %{target: target} = target_fixture(exposure: "internet_exposed")

    Triage.Fixtures.finding!(target.image, target.cve,
      severity: "CRITICAL",
      package_name: "second-package"
    )

    [fresh] = Triage.Workspace.targets(%{"cve" => target.cve, "placement_ids" => [target.id]})
    evidence = approve(fresh, ctx.admin)
    assert evidence.snapshot["inventory"]["severity"] == "CRITICAL"
    provider(response())
    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    Classifier.perform(run.id)
    assert Repo.get!(Run, run.id).unsafe
  end

  test "C06 queued jobs do not call the model while paused", ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin)
    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    {:ok, _} = Classifier.pause(ctx.reviewer, "Paused before inference")
    provider(response())
    assert {:snooze, 60} = Classifier.perform(run.id)
    assert Repo.get!(Run, run.id).state == "queued"
    refute_received {:model_request, _}
  end

  test "C01 a different administrator can re-attest after the original approval is revoked",
       ctx do
    %{target: target} = target_fixture()
    attrs = approval_attrs(target)
    {:ok, old} = Classifier.approve(target.cve, target.id, attrs, ctx.admin)
    Repo.update!(change(Repo.get!(Triage.Accounts.User, old.approved_by), enabled: false))
    {:ok, fresh} = Classifier.approve(target.cve, target.id, attrs, principal(:admin))
    assert fresh.id != old.id
    assert Snapshots.current?(fresh)
    refute Snapshots.current?(old)
  end

  test "C06 loss of safety control does not complete or execute queued work", ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin)
    {:ok, run} = Classifier.request(evidence.id, ctx.reviewer)
    Repo.delete!(Repo.get!(Control, 1))
    provider(response())
    assert {:snooze, 60} = Classifier.perform(run.id)
    assert Repo.get!(Run, run.id).state == "queued"
    refute_received {:model_request, _}
  end

  test "C01 revoked approver invalidates evidence without rewriting snapshots", ctx do
    %{target: target} = target_fixture()
    evidence = approve(target, ctx.admin)
    user = Repo.get!(Triage.Accounts.User, evidence.approved_by)
    Repo.update!(change(user, enabled: false))
    refute Snapshots.current?(evidence)
    assert {:error, :stale_evidence} = Classifier.request(evidence.id, ctx.reviewer)
    assert Repo.get!(Evidence, evidence.id).snapshot == evidence.snapshot
  end
end
