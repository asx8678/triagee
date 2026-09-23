defmodule Triage.AiTriageRunsTest do
  use Triage.DataCase, async: false
  import Triage.Fixtures
  import Triage.ClassifierFixtures, only: [principal: 1]
  alias Triage.{AiTriage, Repo}
  alias Triage.AiTriage.{Run, Runs}
  @fake Path.expand("../fixtures/experiment/fake_kiro_cli.sh", __DIR__)

  setup do
    previous = Application.get_env(:triage, AiTriage)
    Application.put_env(:triage, AiTriage, enabled: true, cli_path: @fake, test_env: true)
    on_exit(fn -> Application.put_env(:triage, AiTriage, previous || []) end)
    image = image!("kiro-runs")
    placement = placement!(image, "alpha", "prod")

    finding =
      finding!(image, "CVE-2099-8123", description: String.duplicate("Full description. ", 80))

    %{cve: finding.cve, finding: finding, placement: placement, principal: principal(:reviewer)}
  end

  test "K03 one pending job, persisted results and no implicit decision", c do
    assert {:ok, run} = Runs.request(c.cve, %{}, c.principal)
    assert {:ok, same} = Runs.request(c.cve, %{}, c.principal)
    assert run.id == same.id
    assert Repo.aggregate(Oban.Job, :count) == 1
    decisions = Repo.aggregate(Triage.Decisions.Decision, :count)
    assert :ok = Runs.perform(run.id)
    assert :ok = Runs.perform(run.id)

    assert %{assessment: %{"danger_score" => 42, "whitelist_score" => 18}} =
             Runs.latest(c.cve, %{}) |> Runs.display()

    assert Repo.aggregate(Triage.Decisions.Decision, :count) == decisions

    assert Repo.get!(Run, run.id).input["targets"]
           |> hd()
           |> get_in(["findings", Access.at(0), "description"]) == c.finding.description

    assert {:ok, again} = Runs.request(c.cve, %{}, c.principal)
    assert again.id != run.id
  end

  test "K02 explicit scope includes all matching deployments, no other teams", c do
    placement!(Repo.get!(Triage.Inventory.Image, c.placement.image_id), "alpha", "staging")
    placement!(Repo.get!(Triage.Inventory.Image, c.placement.image_id), "other", "prod")

    {:ok, run} =
      Runs.request(c.cve, %{"team" => "alpha", "forged_prompt" => "ignored"}, c.principal)

    assert length(run.input["targets"]) == 2
    assert Enum.all?(run.input["targets"], &(&1["placement"]["owner"] == "alpha"))
    assert run.input["intel"]["current"] in [true, false]
    assert run.input["evidence_gaps"] != []
    assert Runs.latest(c.cve, %{"team" => "other"}) == nil
  end

  test "K03 changed evidence never invokes Kiro for the old queued run", c do
    {:ok, run} = Runs.request(c.cve, %{}, c.principal)
    Repo.update!(Ecto.Changeset.change(c.finding, description: "Different evidence"))
    assert :ok = Runs.perform(run.id)
    assert Repo.get!(Run, run.id).state == "stale"
    assert %{assessment: nil, error: message} = Runs.display(Repo.get!(Run, run.id))
    assert message =~ "Evidence changed"
  end

  test "K03 URL changes and model changes invalidate completed scores", c do
    {:ok, run} = Runs.request(c.cve, %{}, c.principal)
    Runs.perform(run.id)
    completed = Repo.get!(Run, run.id)
    assert Runs.current?(completed)
    Repo.update!(Ecto.Changeset.change(c.finding, url: "https://example.test/changed"))
    refute Runs.current?(completed)
    Repo.update!(Ecto.Changeset.change(c.finding, url: c.finding.url))
    Application.put_env(:triage, AiTriage, Keyword.put(AiTriage.config(), :model, "other-model"))
    refute Runs.current?(completed)
  end

  test "K03 viewers and revoked requesters cannot execute classification", c do
    assert {:error, :forbidden} = Runs.request(c.cve, %{}, principal(:viewer))
    {:ok, run} = Runs.request(c.cve, %{}, c.principal)

    Repo.get!(Triage.Accounts.User, run.requested_by)
    |> Ecto.Changeset.change(enabled: false)
    |> Repo.update!()

    Runs.perform(run.id)
    assert Repo.get!(Run, run.id).state == "failed"
  end

  test "K03 uncertain interrupted jobs are not automatically replayed", c do
    {:ok, run} = Runs.request(c.cve, %{}, c.principal)
    old = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-181, :second)
    Repo.update!(Ecto.Changeset.change(run, state: "running", started_at: old, updated_at: old))
    assert %{assessment: nil, error: message} = Runs.display(Repo.get!(Run, run.id))
    assert message =~ "interrupted"
    {:ok, retry} = Runs.request(c.cve, %{}, c.principal)
    assert retry.id != run.id
    assert Repo.get!(Run, run.id).state == "failed"
  end

  test "K03 an expired queued intent never unexpectedly starts Kiro later", c do
    {:ok, run} = Runs.request(c.cve, %{}, c.principal)
    old = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.add(-181, :second)
    Repo.update!(Ecto.Changeset.change(run, updated_at: old))
    assert :ok = Runs.perform(run.id)
    failed = Repo.get!(Run, run.id)
    assert failed.state == "failed"
    assert failed.error == "interrupted"
    assert failed.started_at == nil
    assert failed.result == %{}
  end

  @tag :tmp_dir
  test "K01 real port invocation is headless, isolated, sanitized and cleaned up", c do
    capture = Path.join(c.tmp_dir, "prompt")
    System.put_env("TRIAGE_FAKE_RUNNER_CAPTURE", capture)
    secret = System.get_env("TRIAGE_AZURE_PAT")
    System.put_env("TRIAGE_AZURE_PAT", "synthetic-do-not-inherit")

    on_exit(fn ->
      System.delete_env("TRIAGE_FAKE_RUNNER_CAPTURE")

      if secret,
        do: System.put_env("TRIAGE_AZURE_PAT", secret),
        else: System.delete_env("TRIAGE_AZURE_PAT")
    end)

    {:ok, run} = Runs.request(c.cve, %{}, c.principal)
    Runs.perform(run.id)
    assert Repo.get!(Run, run.id).state == "completed"
    prompt = File.read!(capture)
    assert prompt =~ c.finding.description
    assert prompt =~ "image"
    assert prompt =~ "intel"
    refute prompt =~ "synthetic-do-not-inherit"
    agent = File.read!(capture <> ".agent") |> Jason.decode!()
    assert agent["tools"] == []
    assert agent["resources"] == []
    assert agent["includeMcpJson"] == false
    refute File.exists?(File.read!(capture <> ".cwd") |> String.trim())
  end

  test "K01 output limits, deadlines and invalid suitability fail without scores", c do
    on_exit(fn -> System.delete_env("TRIAGE_FAKE_RUNNER_MODE") end)

    for {mode, error} <- [
          {"oversize", :output_too_large},
          {"timeout", :timeout},
          {"bad_whitelist", :invalid_score}
        ] do
      System.put_env("TRIAGE_FAKE_RUNNER_MODE", mode)
      Application.put_env(:triage, AiTriage, Keyword.put(AiTriage.config(), :timeout_ms, 200))

      assert {:error, ^error} =
               AiTriage.assess(c.cve, Triage.Workspace.targets(%{"cve" => c.cve}))
    end
  end

  test "K04 unsupported high suitability is retained but not accepted as a whitelist score", c do
    System.put_env("TRIAGE_FAKE_RUNNER_MODE", "unsafe")
    on_exit(fn -> System.delete_env("TRIAGE_FAKE_RUNNER_MODE") end)
    {:ok, run} = Runs.request(c.cve, %{}, c.principal)
    Runs.perform(run.id)
    result = Repo.get!(Run, run.id).result
    assert result["raw_whitelist_score"] == 95
    assert result["whitelist_score"] == nil
    assert result["recommendation"] == "request_verification"
    assert result["guard_reasons"] != []
  end

  test "K02 oversized evidence is rejected before any job is created", c do
    Repo.update!(Ecto.Changeset.change(c.finding, description: String.duplicate("x", 140_000)))
    assert {:error, :prompt_too_large} = Runs.request(c.cve, %{}, c.principal)
    assert Repo.aggregate(Run, :count) == 0
    assert Repo.aggregate(Oban.Job, :count) == 0
  end
end
