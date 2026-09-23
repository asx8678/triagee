defmodule Triage.WorkspaceEvidenceCurrencyTest do
  @moduledoc """
  Saved-acceptance currency (W01c, A04–A06, A08 consumption, A09, A10).

  A saved acceptance is only current while the material evidence it was made
  from is unchanged; the application projection and the SQL page must agree,
  legacy dismissals must not be promoted, and invalid exposure evidence must
  not support a dismissal.
  """
  use Triage.DataCase, async: false

  import Triage.Fixtures

  alias Triage.{Attention, Decisions, Exposure, Intel, Repo, Workspace}
  alias Triage.Workspace.Commit

  setup do
    reset_inventory!()
    image = image!("currency")
    prod = placement!(image, "alpha", "prod")
    sibling = placement!(image, "alpha", "staging")
    finding = finding!(image, "CVE-2099-5150", severity: "HIGH")
    %{prod: prod, sibling: sibling, cve: finding.cve, finding: finding, image: image}
  end

  defp accept!(c, placement_ids) do
    versions = Workspace.targets(%{"cve" => c.cve}) |> Map.new(&{&1.id, &1.fingerprint})

    {:ok, decisions} =
      Commit.save(c.cve, placement_ids, versions, Ecto.UUID.generate(), %{
        "action" => "accepted_risk",
        "actor" => "reviewer",
        "reason" => "Accepted during the vendor patch window",
        "due_on" => Date.utc_today() |> Date.add(30) |> Date.to_iso8601()
      })

    decisions
  end

  defp target(c, placement, now \\ DateTime.utc_now()) do
    Workspace.targets(%{"cve" => c.cve, "placement_ids" => [placement.id]}, now) |> hd()
  end

  defp sql_needs do
    Workspace.page(%{"mode" => "needs"}).page_rows |> Enum.map(& &1.cve)
  end

  test "A04: an exposure change invalidates a saved acceptance in Elixir and SQL", c do
    decisions = accept!(c, [c.prod.id, c.sibling.id])
    assert Enum.all?(decisions, & &1.metadata["packet_hash"])

    covered = target(c, c.prod)
    assert covered.covered?
    assert covered.coverage_state == :covered
    assert Workspace.select(Workspace.targets(%{"cve" => c.cve}), "needs") == []
    assert sql_needs() == []

    # The operator declares a material exposure change: the acceptance's basis
    # is gone even though no review form was open.
    assert {:ok, _} =
             Exposure.record(c.prod.id, "internet_exposed", "operator", DateTime.utc_now())

    changed = target(c, c.prod)
    refute changed.covered?
    assert changed.coverage_state == :evidence_changed
    assert changed.needs_decision?
    assert Attention.band(changed) == 0
    assert Attention.reason(changed) =~ "Material evidence changed"

    # Scope-exact: only the changed placement returns to needs; the sibling
    # acceptance is untouched.
    assert target(c, c.sibling).coverage_state == :covered

    elixir_needs =
      Workspace.targets(%{"cve" => c.cve}) |> Workspace.select("needs") |> Enum.map(& &1.id)

    assert elixir_needs == [c.prod.id]
    assert sql_needs() == [c.cve]
  end

  test "A05: a new KEV fact invalidates the binding; an unrelated one does not", c do
    accept!(c, [c.prod.id])
    assert target(c, c.prod).covered?

    # An unrelated advisory in the same generation changes nothing here.
    assert {:ok, %{current?: true}} =
             Intel.commit_generation(
               "kev",
               [%{external_id: "CVE-2099-9999", summary: "unrelated", required_action: "apply"}],
               complete: true,
               receipt: true
             )

    assert target(c, c.prod).covered?

    # A KEV fact for this exact CVE does.
    assert {:ok, %{current?: true}} =
             Intel.commit_generation(
               "kev",
               [
                 %{external_id: "CVE-2099-9999", summary: "unrelated", required_action: "apply"},
                 %{
                   external_id: c.cve,
                   summary: "exploited",
                   required_action: "Apply updates",
                   known_ransomware: true
                 }
               ],
               complete: true,
               receipt: true
             )

    changed = target(c, c.prod)
    refute changed.covered?
    assert changed.coverage_state == :evidence_changed
    assert Attention.band(changed) == 0
    assert sql_needs() == [c.cve]
  end

  test "A06: expiry alone fails usability at its boundary and never revives an older acceptance",
       c do
    accept!(c, [c.prod.id])
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    packet_hash = target(c, c.prod).packet_hash

    # A newer acceptance that is already expired at exactly this instant.
    boundary =
      Repo.insert!(%Decisions.Decision{
        cve: c.cve,
        placement_id: c.prod.id,
        decision: "accepted_risk",
        reason: "boundary fixture",
        actor: "fixture",
        decided_at: now,
        expires_at: now,
        metadata: %{"packet_hash" => packet_hash, "expiry_boundary" => "exclusive"}
      })

    assert Decisions.state(Repo.get!(Decisions.Decision, boundary.id), now) == :expired

    at_boundary = target(c, c.prod, now)
    refute at_boundary.covered?
    assert at_boundary.coverage_state == :uncovered

    # The older acceptance is not resurrected by the newer one expiring.
    assert Decisions.covering_decision(
             Decisions.latest_by_scope([c.cve], now),
             c.cve,
             c.prod.id
           ) == nil

    assert sql_needs() == [c.cve]
  end

  test "A08 consumption: invalid exposure evidence cannot support a risk acceptance", c do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    assert {:ok, _} =
             Exposure.record(
               c.prod.id,
               "internal",
               "scanner",
               DateTime.add(now, -3600, :second),
               DateTime.add(now, -60, :second)
             )

    assert target(c, c.prod).exposure_state == :expired

    versions = Workspace.targets(%{"cve" => c.cve}) |> Map.new(&{&1.id, &1.fingerprint})

    assert {:error, {:dismissal_basis_invalid, _id, :expired}} =
             Commit.save(c.cve, [c.prod.id], versions, Ecto.UUID.generate(), %{
               "action" => "accepted_risk",
               "actor" => "reviewer",
               "reason" => "Accepting on expired evidence",
               "due_on" => Date.utc_today() |> Date.add(30) |> Date.to_iso8601()
             })

    # A request for human work is still allowed on the same evidence.
    assert {:ok, [_]} =
             Commit.save(c.cve, [c.prod.id], versions, Ecto.UUID.generate(), %{
               "action" => "investigate",
               "owner" => "Team lead",
               "actor" => "reviewer",
               "reason" => "Investigate the expired exposure",
               "due_on" => Date.utc_today() |> Date.add(7) |> Date.to_iso8601()
             })

    assert Decisions.history_for_cve(c.cve) |> Enum.map(& &1.decision) == ["investigate"]
  end

  test "A09: legacy v1 and nil-hash dismissals are readable but never current approvals", c do
    hash = target(c, c.prod).evidence_hash
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    legacy =
      Repo.insert!(%Decisions.Decision{
        cve: c.cve,
        placement_id: c.prod.id,
        decision: "fixed",
        reason: "Recorded before packets existed",
        actor: "legacy-operator",
        decided_at: now,
        metadata: %{"evidence_hash" => hash}
      })

    legacy_target = target(c, c.prod)

    # Flagged, not demoted (default policy): it keeps covering, with the flag
    # visible in the reason rather than silently treated as verified.
    assert legacy_target.coverage_state == :legacy_flagged
    assert legacy_target.covered?
    refute legacy_target.needs_decision?
    assert Attention.reason(legacy_target) =~ "Pre-packet approval"

    # History is unchanged and readable; the stored hash is not rewritten.
    assert Enum.any?(Decisions.history_for_cve(c.cve), &(&1.id == legacy.id))
    assert Repo.get!(Decisions.Decision, legacy.id).metadata == %{"evidence_hash" => hash}

    # Only the undecided sibling scope is in needs, in both projections.
    assert sql_needs() == [c.cve]

    assert Workspace.targets(%{"cve" => c.cve})
           |> Workspace.select("needs")
           |> Enum.map(& &1.id) == [c.sibling.id]

    # A work request bound to the same v1 hash keeps covering: it is a request,
    # not an approval.
    Repo.insert!(%Decisions.Decision{
      cve: c.cve,
      placement_id: c.prod.id,
      decision: "investigate",
      reason: "continuing work",
      actor: "operator",
      decided_at: now,
      work_owner: "Team lead",
      due_on: Date.utc_today() |> Date.add(5),
      expires_at: DateTime.add(now, 30, :day),
      metadata: %{"evidence_hash" => hash}
    })

    assert target(c, c.prod).coverage_state == :covered
  end

  test "A10: a material change in one scope does not uncover a sibling scope", c do
    accept!(c, [c.prod.id, c.sibling.id])
    assert target(c, c.prod).covered?
    assert target(c, c.sibling).covered?

    assert {:ok, _} =
             Exposure.record(c.sibling.id, "internet_exposed", "operator", DateTime.utc_now())

    assert target(c, c.sibling).coverage_state == :evidence_changed
    assert target(c, c.prod).coverage_state == :covered

    # Queue membership stays scope-exact in both projections.
    elixir_needs =
      Workspace.targets(%{"cve" => c.cve}) |> Workspace.select("needs") |> Enum.map(& &1.id)

    assert elixir_needs == [c.sibling.id]
    assert Workspace.page(%{"mode" => "needs"}).page_rows |> Enum.map(& &1.cve) == [c.cve]
  end
end
