defmodule Triage.WorkspaceTest do
  use Triage.DataCase, async: false
  import Triage.Fixtures
  alias Triage.{Decisions, Exposure, Workspace}
  alias Triage.Workspace.Commit

  setup do
    reset_inventory!()
    image = image!("workspace")
    prod = placement!(image, "alpha", "prod")
    staging = placement!(image, "alpha", "staging")
    finding = finding!(image, "CVE-2099-9001", severity: "HIGH", suppressed: true)
    %{image: image, prod: prod, staging: staging, finding: finding, cve: finding.cve}
  end

  defp fields(action \\ "request_remediation") do
    %{
      "action" => action,
      "owner" => "Team lead",
      "actor" => "Local reviewer",
      "reason" => "Test rationale and controls",
      "due_on" => Date.utc_today() |> Date.add(7) |> Date.to_iso8601()
    }
  end

  defp versions(cve), do: Workspace.targets(%{"cve" => cve}) |> Map.new(&{&1.id, &1.fingerprint})

  test "metrics reconcile exact target sets, keep suppression active and deduplicate packages and teams",
       c do
    finding!(c.image, c.cve, package_name: "second-library")
    other = placement!(c.image, "beta", "prod")
    reference = image!("reference")
    placement!(reference, Triage.ReferenceData.owner(), Triage.ReferenceData.environment())
    finding!(reference, "CVE-2099-REFERENCE")
    all = Workspace.targets()
    metrics = Workspace.metrics(all)
    assert metrics["active"].cves == [c.cve]

    assert MapSet.new(metrics["active"].targets) ==
             MapSet.new([{c.cve, c.prod.id}, {c.cve, c.staging.id}, {c.cve, other.id}])

    assert metrics["unknown"].value == 3

    for mode <- ~w(active needs urgent unknown) do
      assert metrics[mode].targets == Enum.map(Workspace.select(all, mode), &{&1.cve, &1.id})
    end

    assert Workspace.metrics(Workspace.targets(%{"team" => "beta"}))["active"].targets == [
             {c.cve, other.id}
           ]
  end

  test "priority is calculated only within the matching environment", c do
    Exposure.record(c.prod.id, "internet_exposed", "fixture", DateTime.utc_now())

    assert [%{risk: %{priority: "critical"}}] =
             Workspace.rows(Workspace.targets(%{"environment" => "prod"}))

    assert [%{risk: %{priority: "high"}}] =
             Workspace.rows(Workspace.targets(%{"environment" => "staging"}))

    assert Workspace.metrics(Workspace.targets(%{"environment" => "staging"}))["urgent"].value ==
             0
  end

  for action <- ~w(request_remediation investigate request_verification accepted_risk) do
    test "#{action} commits only production, records immutable evidence and never changes observation",
         c do
      attrs = fields(unquote(action))

      assert {:ok, [decision]} =
               Commit.save(c.cve, [c.prod.id], versions(c.cve), Ecto.UUID.generate(), attrs)

      assert decision.placement_id == c.prod.id
      assert decision.metadata["target"]["finding_ids"] == [c.finding.id]
      assert decision.metadata["target"]["environment"] == "prod"
      assert decision.metadata["identity"] == "self-declared"
      assert decision.actor == "Local reviewer"

      assert decision.expires_at ==
               DateTime.new!(
                 Date.add(Date.from_iso8601!(attrs["due_on"]), 1),
                 ~T[00:00:00],
                 "Etc/UTC"
               )

      assert Decisions.state(decision, decision.expires_at) == :expired
      assert Workspace.metrics(Workspace.targets())["active"].value == 1
      assert Workspace.metrics(Workspace.targets())["needs"].targets == [{c.cve, c.staging.id}]
      assert Repo.reload!(c.finding).resolved_at == nil
      assert Repo.reload!(c.finding).suppressed
      assert Repo.aggregate(Triage.GuidedReview.Request, :count) == 0
    end
  end

  test "fixed is durable, scoped and removed from actionable queues", c do
    attrs = fields("fixed") |> Map.drop(["owner", "due_on"])
    assert "fixed" in Commit.actions()

    assert {:ok, [decision]} =
             Commit.save(c.cve, [c.prod.id], versions(c.cve), Ecto.UUID.generate(), attrs)

    assert decision.expires_at == nil
    assert Decisions.label(decision.decision) == "Fixed"
    targets = Workspace.targets()
    assert Enum.map(Workspace.select(targets, "fixed"), & &1.id) == [c.prod.id]
    assert Enum.map(Workspace.select(targets, "needs"), & &1.id) == [c.staging.id]
    assert Workspace.select(targets, "progress") == []
    assert Repo.reload!(c.finding).resolved_at == nil
    assert Decisions.state(decision, DateTime.add(DateTime.utc_now(), 86_400 * 365)) == :active
  end

  test "operation retries return the same records, payload reuse is rejected", c do
    before = versions(c.cve)
    token = Ecto.UUID.generate()
    assert {:ok, first} = Commit.save(c.cve, [c.prod.id], before, token, fields())
    assert {:ok, ^first} = Commit.save(c.cve, [c.prod.id], before, token, fields())

    assert {:error, :operation_reused} =
             Commit.save(c.cve, [c.prod.id], before, token, fields("investigate"))

    assert Repo.aggregate(Decisions.Decision, :count) == 1
  end

  test "concurrent decisions and changed package evidence conflict without partial writes", c do
    old = versions(c.cve)
    assert {:ok, [_]} = Commit.save(c.cve, [c.prod.id], old, Ecto.UUID.generate(), fields())

    assert {:error, :conflict} =
             Commit.save(
               c.cve,
               [c.prod.id, c.staging.id],
               old,
               Ecto.UUID.generate(),
               fields("accepted_risk")
             )

    assert Repo.aggregate(Decisions.Decision, :count) == 1
    old = versions(c.cve)
    finding!(c.image, c.cve, package_name: "new-dependency")

    assert {:error, :conflict} =
             Commit.save(c.cve, [c.staging.id], old, Ecto.UUID.generate(), fields())

    assert Workspace.metrics(Workspace.targets())["needs"].value == 1
  end

  test "new placements never automatically join an explicit target set", c do
    old = versions(c.cve)
    beta = placement!(c.image, "beta", "prod")

    assert {:ok, [decision]} =
             Commit.save(c.cve, [c.prod.id], old, Ecto.UUID.generate(), fields())

    assert decision.placement_id == c.prod.id
    assert {c.cve, beta.id} in Workspace.metrics(Workspace.targets())["needs"].targets
  end

  test "empty, out of scope, stale, and invalid date submissions write nothing", c do
    for ids <- [[], [999_999], [c.prod.id, 999_999]] do
      assert {:error, _} =
               Commit.save(c.cve, ids, versions(c.cve), Ecto.UUID.generate(), fields())
    end

    for overrides <- [
          %{"owner" => "  "},
          %{"actor" => ""},
          %{"reason" => ""},
          %{"action" => "unknown_action"},
          %{"due_on" => "invalid"},
          %{"due_on" => Date.utc_today() |> Date.add(-1) |> Date.to_iso8601()}
        ] do
      assert {:error, _} =
               Commit.save(
                 c.cve,
                 [c.prod.id],
                 versions(c.cve),
                 Ecto.UUID.generate(),
                 Map.merge(fields(), overrides)
               )
    end

    old = versions(c.cve)
    c.prod |> Ecto.Changeset.change(active: false) |> Repo.update!()

    assert {:error, :conflict} =
             Commit.save(c.cve, [c.prod.id], old, Ecto.UUID.generate(), fields())

    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "unassigned scope has an exact filter key, not an empty all-teams filter", c do
    orphan = placement!(c.image, "(unknown)", "prod")
    targets = Workspace.targets(%{"team" => "__unassigned__"})
    assert Enum.map(targets, & &1.id) == [orphan.id]
    assert "__unassigned__" in Workspace.options().teams

    assert {:ok, [decision]} =
             Commit.save(c.cve, [orphan.id], versions(c.cve), Ecto.UUID.generate(), fields())

    assert [%{id: id}] = Workspace.history(c.cve, targets, %{"team" => "__unassigned__"})
    assert id == decision.id
  end

  test "changed exposure invalidates a draft; frozen evidence survives later updates", c do
    before = versions(c.cve)
    Exposure.record(c.prod.id, "internet_exposed", "fixture", DateTime.utc_now())

    assert {:error, :conflict} =
             Commit.save(c.cve, [c.prod.id], before, Ecto.UUID.generate(), fields())

    assert {:ok, [decision]} =
             Commit.save(c.cve, [c.prod.id], versions(c.cve), Ecto.UUID.generate(), fields())

    snapshot = Repo.reload!(decision).metadata["observed_evidence"]
    assert snapshot["exposure"] == "internet_exposed"
    assert hd(snapshot["findings"])["severity"] == "HIGH"
    c.finding |> Ecto.Changeset.change(description: "Changed after save") |> Repo.update!()
    assert Repo.reload!(decision).metadata["observed_evidence"] == snapshot

    assert Workspace.metrics(Workspace.targets())["needs"].targets == [
             {c.cve, c.prod.id},
             {c.cve, c.staging.id}
           ]
  end

  test "new scoped work replaces legacy global coverage without expiry resurrecting it", c do
    assert {:ok, _} =
             Decisions.record(%{
               cve: c.cve,
               decision: "accepted_risk",
               actor: "legacy",
               reason: "Old global scope",
               decided_at: DateTime.add(DateTime.utc_now(), -60),
               expires_at: DateTime.add(DateTime.utc_now(), 30 * 86_400)
             })

    assert {:ok, [work]} =
             Commit.save(
               c.cve,
               [c.prod.id],
               versions(c.cve),
               Ecto.UUID.generate(),
               fields("investigate")
             )

    prod = Enum.find(Workspace.targets(), &(&1.id == c.prod.id))
    assert prod.decision.decision == "investigate"
    expired = Workspace.targets(%{}, work.expires_at)
    assert Workspace.metrics(expired)["needs"].targets == [{c.cve, c.prod.id}]
  end

  test "disappearance is observation history, not an active or verified target", c do
    c.finding |> Ecto.Changeset.change(resolved_at: at(0)) |> Repo.update!()
    targets = Workspace.targets()
    assert Workspace.select(targets, "active") == []
    assert length(Workspace.select(targets, "history")) == 2
  end

  test "history excludes sibling-placement decisions and labels legacy global scope", c do
    assert {:ok, [_]} =
             Commit.save(c.cve, [c.prod.id], versions(c.cve), Ecto.UUID.generate(), fields())

    assert Workspace.history(c.cve, Workspace.targets(%{"environment" => "staging"})) == []

    assert {:ok, global} =
             Decisions.record(%{
               cve: c.cve,
               decision: "mitigated",
               actor: "legacy",
               reason: "Old global claim"
             })

    assert [%{id: id, placement_id: nil}] =
             Workspace.history(c.cve, Workspace.targets(%{"environment" => "staging"}))

    assert id == global.id
  end
end
