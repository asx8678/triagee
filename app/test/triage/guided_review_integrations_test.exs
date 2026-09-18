defmodule Triage.GuidedReviewIntegrationsTest do
  use Triage.DataCase, async: false

  import Triage.Fixtures
  alias Triage.{GuidedReview, ReviewIntegrations}
  alias Triage.GuidedReview.Request
  alias Triage.Inventory.Finding

  defmodule AzureAdapter do
    def create(plan, config) do
      send(config[:test_pid], {:azure_call, self(), plan})
      send(config[:test_pid], {:azure_organization, config[:organization]})

      case config[:test_result] do
        :raise ->
          raise "private transport details"

        :exit ->
          exit(:timeout)

        :blocked ->
          receive do
            :release -> {:ok, 42, "https://example.test/tickets/42"}
          after
            5_000 -> {:error, :timeout}
          end

        result ->
          result
      end
    end
  end

  setup do
    reset_inventory!()
    previous = Application.fetch_env(:triage, ReviewIntegrations)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:triage, ReviewIntegrations, value)
        :error -> Application.delete_env(:triage, ReviewIntegrations)
      end
    end)

    Application.put_env(:triage, ReviewIntegrations,
      organization: "test-org",
      token: "fake-token",
      azure_adapter: AzureAdapter,
      teams: %{"alpha" => %{"project" => "test-project", "area_path" => "test-area"}},
      test_pid: self(),
      test_result: {:ok, 42, "https://example.test/tickets/42"}
    )

    image = image!("configured-integrations")
    placement!(image, "alpha", "prod")
    finding = finding!(image, "CVE-2090-4321", description: "Untrusted source description")
    {:ok, plans} = GuidedReview.preview(finding.cve)
    %{finding: finding, fingerprint: GuidedReview.fingerprint(plans), image: image}
  end

  test "confirmed ticket records the receipt without changing inventory and cannot be sent twice",
       context do
    assert {:ok, [receipt]} =
             GuidedReview.create_tickets(context.finding.cve, context.fingerprint)

    assert receipt.status == "created"
    assert receipt.ticket_id == 42
    assert_receive {:azure_call, _, %{owner: "alpha", cve: "CVE-2090-4321"}}

    assert {:error, :not_actionable} =
             GuidedReview.create_tickets(context.finding.cve, context.fingerprint)

    refute_receive {:azure_call, _, _}
    assert Repo.aggregate(Request, :count) == 1
    stored = Repo.get!(Finding, context.finding.id)
    assert stored.resolved_at == nil
    refute stored.suppressed
  end

  test "a second submission cannot claim a request while the first send is in flight", context do
    configure(test_result: :blocked)

    task =
      Task.async(fn -> GuidedReview.create_tickets(context.finding.cve, context.fingerprint) end)

    assert_receive {:azure_call, sender, _}

    assert {:ok, [receipt]} =
             GuidedReview.create_tickets(context.finding.cve, context.fingerprint)

    assert receipt.status == "sending"
    refute_receive {:azure_call, _, _}
    send(sender, :release)
    assert {:ok, [%{status: "created"}]} = Task.await(task)
    assert Repo.aggregate(Request, :count) == 1
  end

  for {name, result} <- [
        {"timeout", {:error, :timeout}},
        {"ambiguous response", :invalid},
        {"exception", :raise},
        {"exit", :exit}
      ] do
    test "#{name} blocks retries and does not expose raw errors", context do
      configure(test_result: unquote(Macro.escape(result)))

      assert {:ok, [receipt]} =
               GuidedReview.create_tickets(context.finding.cve, context.fingerprint)

      assert receipt.status == "unknown"
      assert receipt.ticket_id == nil
      refute receipt.error =~ "private transport"
      assert_receive {:azure_call, _, _}

      assert {:ok, [again]} =
               GuidedReview.create_tickets(context.finding.cve, context.fingerprint)

      assert again.id == receipt.id
      assert again.status == "unknown"
      refute_receive {:azure_call, _, _}
    end
  end

  test "an explicit rejection allows a human-confirmed retry", context do
    configure(test_result: {:error, :rejected})

    assert {:ok, [%{status: "failed"}]} =
             GuidedReview.create_tickets(context.finding.cve, context.fingerprint)

    assert_receive {:azure_call, _, _}
    configure(test_result: {:ok, 42, "https://example.test/tickets/42"})

    assert {:ok, [%{status: "created"}]} =
             GuidedReview.create_tickets(context.finding.cve, context.fingerprint)

    assert_receive {:azure_call, _, _}
    assert Repo.aggregate(Request, :count) == 1
  end

  test "changed inventory invalidates the confirmation before any external call", context do
    context.finding |> Ecto.Changeset.change(description: "Updated evidence") |> Repo.update!()
    assert_stale(context)
  end

  test "a newly affected scope invalidates the confirmation", context do
    placement!(context.image, "alpha", "staging")
    assert_stale(context)
  end

  test "a changed team destination invalidates the confirmation", context do
    configure(teams: %{"alpha" => %{"project" => "other-project", "area_path" => "test-area"}})
    assert_stale(context)
  end

  test "a changed Azure organization invalidates the confirmation", context do
    configure(organization: "other-org")
    assert_stale(context)
  end

  test "unconfigured or unmapped destinations fail closed", context do
    configure(token: nil)
    assert_stale(context)
    configure(token: "fake-token", teams: %{})
    {:ok, plans} = GuidedReview.preview(context.finding.cve)
    assert_stale(%{context | fingerprint: GuidedReview.fingerprint(plans)})
  end

  test "a planned request records the exact refreshed payload and organization actually submitted",
       context do
    assert {:ok, [planned]} = GuidedReview.mark_for_fix(context.finding.cve)

    context.finding
    |> Ecto.Changeset.change(description: "New submission evidence")
    |> Repo.update!()

    configure(
      organization: "new-org",
      teams: %{"alpha" => %{"project" => "new-project", "area_path" => "new-area"}}
    )

    fingerprint = current_fingerprint(context.finding.cve)

    assert {:ok, [receipt]} = GuidedReview.create_tickets(context.finding.cve, fingerprint)
    assert_receive {:azure_call, _, plan}
    assert_receive {:azure_organization, "new-org"}
    assert receipt.id == planned.id
    assert plan.description =~ "New submission evidence"
    assert plan.mapping["project"] == "new-project"
    assert_payload(receipt, plan)
  end

  test "a rejected request records the refreshed payload on a confirmed retry", context do
    configure(test_result: {:error, :rejected})
    assert {:ok, [failed]} = GuidedReview.create_tickets(context.finding.cve, context.fingerprint)
    assert_receive {:azure_call, _, first_plan}
    assert_payload(failed, first_plan)
    context.finding |> Ecto.Changeset.change(description: "Retry evidence") |> Repo.update!()

    configure(
      organization: "retry-org",
      test_result: {:ok, 42, "https://example.test/tickets/42"}
    )

    assert {:ok, [receipt]} =
             GuidedReview.create_tickets(
               context.finding.cve,
               current_fingerprint(context.finding.cve)
             )

    assert_receive {:azure_call, _, plan}
    assert receipt.id == failed.id
    assert receipt.payload != failed.payload
    assert_payload(receipt, plan)
  end

  test "an unknown request keeps its submitted payload when evidence and destination change",
       context do
    configure(test_result: {:error, :timeout})

    assert {:ok, [unknown]} =
             GuidedReview.create_tickets(context.finding.cve, context.fingerprint)

    assert_receive {:azure_call, _, plan}
    context.finding |> Ecto.Changeset.change(description: "Later evidence") |> Repo.update!()
    configure(organization: "later-org")

    assert {:ok, [unchanged]} =
             GuidedReview.create_tickets(
               context.finding.cve,
               current_fingerprint(context.finding.cve)
             )

    refute_receive {:azure_call, _, _}
    assert unchanged.status == "unknown"
    assert_payload(unchanged, plan)
    assert unchanged.payload == unknown.payload
  end

  test "the send claim persists its payload before I/O and a losing claim cannot overwrite it",
       context do
    configure(test_result: :blocked)

    task =
      Task.async(fn -> GuidedReview.create_tickets(context.finding.cve, context.fingerprint) end)

    assert_receive {:azure_call, sender, plan}
    [sending] = GuidedReview.requests(context.finding.cve)
    assert sending.status == "sending"
    assert_payload(sending, plan)
    context.finding |> Ecto.Changeset.change(description: "Concurrent evidence") |> Repo.update!()
    configure(organization: "other-org")

    assert {:ok, [unchanged]} =
             GuidedReview.create_tickets(
               context.finding.cve,
               current_fingerprint(context.finding.cve)
             )

    refute_receive {:azure_call, _, _}
    assert_payload(unchanged, plan)
    send(sender, :release)
    assert {:ok, [created]} = Task.await(task)
    assert_payload(created, plan)
  end

  test "the adapter uses the confirmed organization rather than rereading a different destination",
       context do
    {:ok, [plan]} = GuidedReview.preview(context.finding.cve)
    configure(organization: "changed-after-preview")
    assert {:ok, 42, _} = ReviewIntegrations.create_ticket(plan)
    assert_receive {:azure_organization, "test-org"}
  end

  test "AI advice accepts only bounded recommendations and never changes local state" do
    for recommendation <- ["whitelist", "fix", "investigate"] do
      assert {:ok, %{recommendation: ^recommendation, reason: "Human review required"}} =
               ReviewIntegrations.validate_advice(
                 Jason.encode!(%{recommendation: recommendation, reason: "Human review required"})
               )
    end

    for invalid <- [
          "not json",
          "[]",
          "null",
          "{}",
          Jason.encode!(%{recommendation: "execute", reason: "Run a command"}),
          Jason.encode!(%{recommendation: "fix", reason: ""}),
          Jason.encode!(%{recommendation: "fix", reason: 1}),
          Jason.encode!(%{recommendation: "fix", reason: String.duplicate("x", 8001)})
        ] do
      assert {:error, "Internal AI returned an invalid recommendation."} =
               ReviewIntegrations.validate_advice(invalid)
    end

    assert Repo.aggregate(Request, :count) == 0
    refute_receive {:azure_call, _, _}
  end

  defp current_fingerprint(cve) do
    {:ok, plans} = GuidedReview.preview(cve)
    GuidedReview.fingerprint(plans)
  end

  defp assert_payload(receipt, plan) do
    expected =
      plan
      |> Map.take([:title, :description, :mapping, :organization])
      |> Jason.encode!()
      |> Jason.decode!()

    assert receipt.payload == expected
    assert Repo.get!(Request, receipt.id).payload == expected
  end

  defp configure(overrides) do
    Application.put_env(
      :triage,
      ReviewIntegrations,
      Keyword.merge(ReviewIntegrations.config(), overrides)
    )
  end

  defp assert_stale(context) do
    assert {:error, :preview_changed_or_configuration_missing} =
             GuidedReview.create_tickets(context.finding.cve, context.fingerprint)

    refute_receive {:azure_call, _, _}
    assert Repo.aggregate(Request, :count) == 0
  end
end
