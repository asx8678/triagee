defmodule Triage.ClassifierFixtures do
  @moduledoc false
  import Triage.Fixtures
  alias Triage.{Accounts, Classifier, Exposure, Intel, Workspace}
  alias Triage.Classifier.Model

  def configure do
    previous = Application.get_env(:triage, Model)
    exposure = Application.get_env(:triage, :exposure_policy)

    Application.put_env(:triage, Model,
      enabled: true,
      automatic: false,
      url: "https://model.example.test/v1/chat/completions",
      model: "pinned-test-model",
      api_key: "SYNTHETIC-MODEL-KEY"
    )

    Application.put_env(:triage, :exposure_policy, %{
      "classifier-fixture" => %{max_age_days: 1, require_expiry: true}
    })

    ExUnit.Callbacks.on_exit(fn ->
      Application.put_env(:triage, Model, previous || [])
      Application.put_env(:triage, :exposure_policy, exposure || %{})
    end)

    :ok
  end

  def principal(role) do
    user = TriageWeb.ConnCase.account_fixture(role)
    {:ok, token} = Accounts.create_session(user)
    Accounts.principal(token)
  end

  def target_fixture(opts \\ []) do
    name = "classifier-#{System.unique_integer([:positive])}"
    image = image!(name)
    placement = placement!(image, name, "prod")
    finding = finding!(image, "CVE-2099-9100", severity: Keyword.get(opts, :severity, "HIGH"))
    now = Classifier.now()

    {:ok, _} =
      Exposure.record(
        placement.id,
        Keyword.get(opts, :exposure, "internal"),
        "classifier-fixture",
        now,
        DateTime.add(now, 3600)
      )

    kev_fixture(Keyword.get(opts, :kev, false))
    [target] = Workspace.targets(%{"cve" => finding.cve, "placement_ids" => [placement.id]})
    %{target: target, finding: finding, placement: placement}
  end

  def kev_fixture(listed) do
    cve = if listed, do: "CVE-2099-9100", else: "CVE-2099-9101"

    {:ok, _} =
      Intel.commit_generation("kev", [%{external_id: cve, title: "Synthetic KEV fixture"}],
        complete: true,
        declared_count: 1
      )
  end

  def approval_attrs(target, overrides \\ %{}) do
    now = Classifier.now()

    Map.merge(
      %{
        "packet_hash" => target.packet_hash,
        "workload_uid" => "workload-#{target.id}",
        "service" => "fixture-service",
        "source_ref" => "fixture:scan-001",
        "register_ref" => "fixture:register-001",
        "applicability" => "not_affected",
        "applicability_ref" => "fixture:scoped-advisory-proof",
        "rationale" =>
          "Synthetic explicit non-applicability evidence; not merely internal exposure.",
        "cohort" => "fixture-cohort",
        "mode" => "assisted",
        "observed_at" => DateTime.to_iso8601(now),
        "expires_at" => DateTime.to_iso8601(DateTime.add(now, 1800)),
        "complete" => true
      },
      overrides
    )
  end

  def approve(target, admin, overrides \\ %{}) do
    {:ok, evidence} =
      Classifier.approve(target.cve, target.id, approval_attrs(target, overrides), admin)

    evidence
  end

  def response(classification \\ "whitelist_candidate") do
    %{
      "classification" => classification,
      "rationale" => "Synthetic scoped assessment.",
      "citations" => ~w(inventory source register exposure kev applicability)
    }
  end

  def provider(output, callback \\ fn _ -> :ok end) do
    test = self()
    options = Model.config()

    adapter = fn request ->
      send(test, {:model_request, request})
      callback.(request)

      body =
        Jason.encode!(%{
          "model" => "pinned-test-model",
          "choices" => [%{"message" => %{"content" => Jason.encode!(output)}}]
        })

      {request, Req.Response.new(status: 200, body: body)}
    end

    Application.put_env(
      :triage,
      Model,
      Keyword.put(options, :req_options, adapter: Triage.ClassifierTestAdapter.install(adapter))
    )
  end

  def feedback_attrs(overrides \\ %{}),
    do:
      Map.merge(
        %{
          "rating" => "right",
          "classification" => "whitelist_candidate",
          "reason" => "Independently reviewed the synthetic evidence.",
          "effort_seconds" => "95",
          "dangerous" => false
        },
        overrides
      )
end
