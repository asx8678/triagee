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
        decided_at: at(0),
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

    assert %{"CVE-2098-6101" => current} = Decisions.latest_by_cve(["CVE-2098-6101"])
    assert current.label == "Accepted risk"
    assert current.state == :active
    assert Decisions.active?(current)
    assert current.expires_at == decision.expires_at
  end

  test "an accepted risk without an expiry is refused" do
    assert {:error, changeset} = Decisions.record(attrs(%{expires_at: nil}))
    assert "is required for accepted risk" <> _ = errors_on(changeset).expires_at |> hd()
    assert Decisions.history_for_cve("CVE-2098-6101") == []
  end

  test "a decision without a reason or an actor is refused" do
    assert {:error, reason_changeset} = Decisions.record(attrs(%{reason: ""}))
    assert "can't be blank" in errors_on(reason_changeset).reason

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

  test "an active decision outranks a newer expired one" do
    active_expiry = DateTime.add(at(0), 10, :day)

    assert {:ok, _older} =
             Decisions.record(attrs(%{decided_at: at(9), expires_at: active_expiry}))

    assert {:ok, newer} = Decisions.record(attrs(%{decided_at: at(1), expires_at: at(1)}))

    assert %{"CVE-2098-6101" => governing} = Decisions.latest_by_cve(["CVE-2098-6101"])
    assert governing.expires_at == active_expiry
    assert governing.id != newer.id
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
