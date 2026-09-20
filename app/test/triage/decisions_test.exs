defmodule Triage.DecisionsTest do
  use Triage.DataCase, async: true

  import Triage.Fixtures

  alias Triage.{Decisions, Inventory}
  alias Triage.Inventory.Finding

  setup do
    reset_inventory!()
    image = image!("decisions")
    placement = placement!(image, "alpha", "prod-cluster-1")

    finding =
      finding!(image, "CVE-2098-6101",
        severity: "CRITICAL",
        first_seen: at(5),
        last_seen: at(0)
      )

    %{placement: placement, finding: finding}
  end

  defp attrs(overrides \\ %{}) do
    Map.merge(
      %{
        cve: "CVE-2098-6101",
        decision: "accepted_risk",
        reason: "Synthetic test acceptance that expires.",
        actor: "test-operator",
        decided_at: at(1),
        expires_at: DateTime.add(at(0), 30, :day)
      },
      overrides
    )
  end

  test "records an accepted risk with its actor, reason and expiry", %{placement: placement} do
    assert {:ok, decision} = Decisions.record(attrs(%{placement_id: placement.id}))
    assert decision.decision == "accepted_risk"
    assert decision.actor == "test-operator"
    assert decision.placement_id == placement.id

    assert Decisions.latest_by_cve(["CVE-2098-6101"]) == %{}
    current = Decisions.latest_by_scope(["CVE-2098-6101"])[{"CVE-2098-6101", placement.id}]
    assert current.label == "Whitelisted"
    assert current.state == :active
    assert Decisions.active?(current)
    assert current.expires_at == decision.expires_at
  end

  test "placement decisions never cover siblings and triage requires every scope", context do
    image = Repo.get!(Triage.Inventory.Image, context.finding.image_id)
    sibling = placement!(image, "beta", "prod-cluster-1")
    cve = context.finding.cve
    assert {:ok, _} = Decisions.record(attrs(%{placement_id: context.placement.id}))
    decisions = Decisions.latest_by_scope([cve])
    assert Decisions.covering_decision(decisions, cve, context.placement.id)
    assert Decisions.covering_decision(decisions, cve, sibling.id) == nil
    assert Decisions.latest_by_cve([cve]) == %{}
    assert {:ok, %{rows: [row]}} = Triage.Triage.list_critical(filter: "all")
    assert row.state == :awaiting_assessment
    assert row.scopes_decided == 1
    assert Enum.map(Triage.GuidedReview.get(cve).pending, & &1.owner) == ["beta"]

    assert {:ok, _} = Decisions.record(attrs(%{placement_id: sibling.id}))
    assert {:ok, %{rows: [covered]}} = Triage.Triage.list_critical(filter: "whitelisted")
    assert covered.state == :decision_recorded
    assert covered.scopes_decided == 2
    assert Triage.GuidedReview.get(cve) == nil
  end

  test "scoped work replaces a global claim consistently in workspace and legacy readers",
       context do
    cve = context.finding.cve
    assert {:ok, global} = Decisions.record(attrs(%{decided_at: at(3)}))

    assert {:ok, work} =
             Decisions.record(
               attrs(%{
                 placement_id: context.placement.id,
                 decision: "investigate",
                 work_owner: "Scope owner",
                 due_on: Date.utc_today(),
                 decided_at: at(1)
               })
             )

    decisions = Decisions.latest_by_scope([cve])
    assert Decisions.covering_decision(decisions, cve, context.placement.id).id == work.id
    assert {:ok, %{rows: [row]}} = Triage.Triage.list_critical(filter: "all")
    assert hd(row.work_items).decision.id == work.id
    assert hd(Triage.Workspace.targets(%{"cve" => cve})).decision.id == work.id
    assert Decisions.latest_by_cve([cve])[cve].id == global.id
  end

  test "expired scoped work never resurrects an older global acceptance on legacy routes",
       context do
    cve = context.finding.cve
    image = Repo.get!(Triage.Inventory.Image, context.finding.image_id)
    sibling = placement!(image, "beta", "staging")
    assert {:ok, global} = Decisions.record(attrs(%{decided_at: at(3)}))

    assert {:ok, _work} =
             Decisions.record(
               attrs(%{
                 placement_id: context.placement.id,
                 decision: "request_remediation",
                 work_owner: "Scope owner",
                 due_on: Date.utc_today() |> Date.add(-1),
                 decided_at: at(2),
                 expires_at: at(1)
               })
             )

    decisions = Decisions.latest_by_scope([cve])
    assert Decisions.covering_decision(decisions, cve, context.placement.id) == nil
    assert Decisions.covering_decision(decisions, cve, sibling.id).id == global.id
    assert Enum.map(Triage.GuidedReview.get(cve).pending, & &1.owner) == ["alpha"]
    assert {:ok, %{rows: [row]}} = Triage.Triage.list_critical(filter: "active")
    assert row.scopes_decided == 1
    assert row.state == :awaiting_assessment
  end

  test "same-second replacements use record identity and a newer global claim still governs",
       context do
    cve = context.finding.cve
    assert {:ok, _global} = Decisions.record(attrs())
    assert {:ok, scoped} = Decisions.record(attrs(%{placement_id: context.placement.id}))

    assert Decisions.covering_decision(
             Decisions.latest_by_scope([cve]),
             cve,
             context.placement.id
           ).id == scoped.id

    assert {:ok, newest} = Decisions.record(attrs())

    assert Decisions.covering_decision(
             Decisions.latest_by_scope([cve]),
             cve,
             context.placement.id
           ).id == newest.id
  end

  test "future decisions are pending and cannot replace current coverage", context do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    cve = context.finding.cve
    assert {:ok, future} = Decisions.record(attrs(%{decided_at: DateTime.add(now, 3600)}))
    assert Decisions.state(future, now) == :pending
    assert Decisions.latest_by_scope([cve], now) == %{}
    assert Triage.GuidedReview.get(cve)
    assert {:ok, %{rows: [row]}} = Triage.Triage.list_critical(filter: "active")
    assert row.scopes_decided == 0

    assert {:ok, effective} = Decisions.record(attrs(%{decided_at: DateTime.add(now, -60)}))
    assert Decisions.latest_by_cve([cve], now)[cve].id == effective.id
    assert Decisions.latest_by_cve([cve], DateTime.add(now, 3600))[cve].id == future.id
  end

  test "expiry covers its exact boundary but not the next second", context do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    assert {:ok, decision} = Decisions.record(attrs(%{expires_at: now}))
    assert Decisions.state(decision, now) == :active
    assert Decisions.state(decision, DateTime.add(now, 1)) == :expired

    assert Decisions.latest_by_cve([context.finding.cve], DateTime.add(now, 1))[
             context.finding.cve
           ].state == :expired
  end

  test "an accepted risk without an expiry is refused" do
    assert {:error, changeset} = Decisions.record(attrs(%{expires_at: nil}))
    assert "is required for accepted risk" <> _ = errors_on(changeset).expires_at |> hd()
    assert Decisions.history_for_cve("CVE-2098-6101") == []
  end

  test "whitelist comments are optional but internal actor is required" do
    assert {:ok, decision} = Decisions.record(attrs(%{reason: ""}))
    assert decision.reason == ""

    assert {:error, actor_changeset} = Decisions.record(Map.delete(attrs(), :actor))
    assert "can't be blank" in errors_on(actor_changeset).actor
  end

  test "a decision for a CVE this estate never recorded is refused" do
    assert {:error, :unknown_cve} = Decisions.record(attrs(%{cve: "CVE-1999-9999"}))
    assert Decisions.history_for_cve("CVE-1999-9999") == []
  end

  test "an unknown decision word is refused" do
    assert {:error, changeset} = Decisions.record(attrs(%{decision: "looks_fine"}))
    assert "is invalid" in errors_on(changeset).decision
  end

  test "expiry ends coverage: the advisory comes back to the work list" do
    assert {:ok, decision} = Decisions.record(attrs())
    assert Decisions.active?(Decisions.latest_by_cve(["CVE-2098-6101"])["CVE-2098-6101"])

    later = DateTime.add(decision.expires_at, 1, :day)
    assert %{"CVE-2098-6101" => expired} = Decisions.latest_by_cve(["CVE-2098-6101"], later)
    assert expired.state == :expired
    refute Decisions.active?(expired)
    assert expired.expires_at == decision.expires_at
  end

  test "the latest effective replacement expires without reviving an older acceptance" do
    active_expiry = DateTime.add(at(0), 10, :day)

    assert {:ok, _older} =
             Decisions.record(attrs(%{decided_at: at(9), expires_at: active_expiry}))

    assert {:ok, newer} = Decisions.record(attrs(%{decided_at: at(1), expires_at: at(1)}))

    assert %{"CVE-2098-6101" => governing} = Decisions.latest_by_cve(["CVE-2098-6101"])
    assert governing.expires_at == newer.expires_at
    assert governing.id == newer.id
    assert governing.state == :expired
  end

  test "history is append-only and links the decision it supersedes" do
    assert {:ok, first} = Decisions.record(attrs())

    assert {:ok, second} =
             Decisions.record(attrs(%{reason: "Replaced by a longer acceptance."}))

    assert second.supersedes_id == first.id

    history = Decisions.history_for_cve("CVE-2098-6101")
    assert Enum.map(history, & &1.id) == [second.id, first.id]
    assert Enum.map(history, & &1.reason) == [second.reason, first.reason]
  end

  test "a decision never rewrites the inventory and is not a handling decision", %{
    finding: finding
  } do
    assert {:ok, _} = Decisions.record(attrs())

    stored = Repo.get!(Finding, finding.id)
    assert stored.severity == "CRITICAL"
    assert stored.suppressed == false
    assert stored.resolved_at == nil

    # Still an occurrence in the inventory, still counted in posture, and still
    # uncovered by any saved review: the decision changed no finding column.
    assert Inventory.count_groups([]) == 1
    assert Inventory.cve_summary_counts().critical == 1
  end

  test "the inventory reset also clears decisions and impact evidence" do
    # Both new tables hang off `image_placements`, and a decision may be
    # CVE-wide with no placement at all. `reset_inventory!` is relied on by
    # count-sensitive tests, so this pins that CASCADE really does empty them:
    # an estate-wide decision is not protected by its placement foreign key.
    assert {:ok, _} = Decisions.record(attrs())

    assert {:ok, placement} =
             Repo.insert(%Triage.Inventory.ImagePlacement{
               image_id: image!("reset-cascade").id,
               namespace: "ns",
               owner: "alpha",
               environment: "prod-cluster-1",
               active: true,
               first_seen: at(30),
               last_seen: at(0)
             })

    assert {:ok, _} = Triage.Impact.record(placement.id, "high", "test", at(0))
    assert Decisions.history_for_cve("CVE-2098-6101") != []
    assert Triage.Impact.current_by_placement([placement.id]) != %{}

    reset_inventory!()

    assert Decisions.history_for_cve("CVE-2098-6101") == []
    assert Triage.Impact.current_by_placement([placement.id]) == %{}
  end

  test "decisions inside the window are listed newest first" do
    assert {:ok, out_of_window} = Decisions.record(attrs(%{decided_at: at(40)}))
    assert {:ok, middle} = Decisions.record(attrs(%{decided_at: at(9)}))
    assert {:ok, older} = Decisions.record(attrs(%{decided_at: at(20)}))
    assert {:ok, newer} = Decisions.record(attrs(%{decided_at: at(1)}))

    listed = Decisions.list_between(at(30), at(0))

    assert Enum.map(listed, & &1.id) == [newer.id, middle.id, older.id]
    refute out_of_window.id in Enum.map(listed, & &1.id)
  end
end
