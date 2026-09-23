defmodule Triage.AiTriageTest do
  @moduledoc """
  Explicit-off AI analysis containment (W01a).

  Analysis is disabled by default; executable presence alone never enables a
  model call, and there is no PATH discovery fallback. Pipeline behavior is
  proven through the fake runner fixture under test/fixtures/experiment/ —
  never a real provider (D11/I06; live validation is G04-gated).
  """
  use Triage.DataCase, async: false

  alias Triage.AiTriage

  @fake_runner Path.expand("../fixtures/experiment/fake_kiro_cli.sh", __DIR__)

  @valid_target %{
    placement: %{id: 1, owner: "alpha", environment: "prod"},
    exposure: "direct",
    findings: [
      %{
        package_name: "openssl",
        package_version: "3.2.0",
        severity: "HIGH",
        fix: "3.2.1",
        description: "buffer overflow"
      }
    ]
  }

  # App env is the single configuration source; restore the surrounding
  # application's value after every scenario.
  defp configure!(overrides) do
    previous = Application.get_env(:triage, Triage.AiTriage)
    Application.put_env(:triage, Triage.AiTriage, Keyword.put(overrides, :test_env, true))

    on_exit(fn ->
      if previous,
        do: Application.put_env(:triage, Triage.AiTriage, previous),
        else: Application.delete_env(:triage, Triage.AiTriage)
    end)

    :ok
  end

  defp runner_mode(mode) do
    System.put_env("TRIAGE_FAKE_RUNNER_MODE", mode)
    on_exit(fn -> System.delete_env("TRIAGE_FAKE_RUNNER_MODE") end)
  end

  describe "explicit-off configuration" do
    test "analysis is disabled by default; an installed runner is not enablement" do
      configure!(enabled: false, cli_path: @fake_runner)

      assert File.exists?(@fake_runner)
      refute AiTriage.enabled?()
      refute AiTriage.configured?()
      assert {:error, :analysis_disabled} = AiTriage.assess("CVE-2099-1234", [@valid_target])
    end

    test "invalid enablement values fail closed to disabled" do
      configure!(enabled: "yes", cli_path: @fake_runner)
      refute AiTriage.enabled?()
      refute AiTriage.configured?()
      assert {:error, :analysis_disabled} = AiTriage.assess("CVE-2099-1234", [@valid_target])
    end

    test "enabled without a runner path is not configured" do
      configure!(enabled: true, cli_path: nil)
      assert AiTriage.enabled?()
      refute AiTriage.configured?()
      assert {:error, :not_configured} = AiTriage.assess("CVE-2099-1234", [@valid_target])
    end

    test "enabled with a nonexistent runner path is not configured" do
      configure!(enabled: true, cli_path: "/nonexistent/fake-kiro-cli")
      assert AiTriage.enabled?()
      refute AiTriage.configured?()
    end
  end

  describe "input validation" do
    test "empty cve and empty targets are rejected before any spawn" do
      configure!(enabled: true, cli_path: @fake_runner)

      assert {:error, :invalid_request} = AiTriage.assess("", [@valid_target])
      assert {:error, :invalid_request} = AiTriage.assess("CVE-2099-1234", [])
      assert {:error, :invalid_request} = AiTriage.assess("CVE-2099-1234", [%{}])

      assert {:error, :invalid_request} =
               AiTriage.assess("CVE-2099-1234", [@valid_target, %{placement: nil}])
    end
  end

  describe "fake runner pipeline" do
    setup do
      configure!(enabled: true, cli_path: @fake_runner)
      :ok
    end

    test "assess runs the reviewed runner and validates its output" do
      assert AiTriage.configured?()

      assert {:ok, assessment} = AiTriage.assess("CVE-2099-1234", [@valid_target])
      assert assessment.cve == "CVE-2099-1234"
      assert assessment.danger_score == 42
      assert assessment.danger_level == "moderate"
      assert assessment.recommendation == "investigate"
      assert assessment.rationale == "Fake runner fixture: deterministic pipeline response."
      assert %DateTime{} = assessment.assessed_at
    end

    test "non-JSON runner output is a bounded error, never a fallback result" do
      runner_mode("invalid_json")
      assert {:error, :invalid_response} = AiTriage.assess("CVE-2099-1234", [@valid_target])
    end

    test "out-of-range scores are rejected" do
      runner_mode("bad_score")
      assert {:error, :invalid_score} = AiTriage.assess("CVE-2099-1234", [@valid_target])
    end

    test "a crashing runner is a bounded error, never a fallback result" do
      runner_mode("crash")
      assert {:error, :cli_failed} = AiTriage.assess("CVE-2099-1234", [@valid_target])
    end
  end
end
