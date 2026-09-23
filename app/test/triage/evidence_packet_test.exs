defmodule Triage.EvidencePacketTest do
  @moduledoc """
  Packet v2 material facts and coverage states (W01c).

  The hash covers what an approval is allowed to claim, and nothing else: a
  repeated identical observation or an unrelated advisory elsewhere must not
  invalidate an approval, while a material change must.
  """
  # Serialized: one scenario toggles the legacy-policy application env,
  # which is process-wide.
  use ExUnit.Case, async: false

  alias Triage.Evidence
  alias Triage.Evidence.Packet

  defp placement do
    %{id: 1, image_id: 2, owner: "alpha", environment: "prod", namespace: "web", active: true}
  end

  defp finding(id) do
    %{
      id: id,
      package_name: "libssl",
      package_version: "1.0.0",
      severity: "HIGH",
      fix: nil,
      description: "buffer overflow",
      resolved_at: nil,
      reopen_count: 0,
      first_seen: ~U[2026-09-01 00:00:00Z],
      suppressed: false
    }
  end

  defp build(overrides) do
    Packet.build(
      Map.merge(
        %{
          cve: "CVE-2099-1000",
          placement: placement(),
          image_digest: "sha256:aaa",
          findings: [finding(1)],
          exposure: %{"state" => "current", "value" => "internal"},
          intel: %{
            "kev" => false,
            "ransomware" => nil,
            "due_date" => nil,
            "required_action" => false
          },
          captured_at: ~U[2026-09-22 00:00:00Z],
          provenance: %{"exposure" => %{"source" => "fixture"}}
        },
        overrides
      )
    )
  end

  test "identical material with different capture provenance hashes identically" do
    a =
      build(%{
        captured_at: ~U[2026-09-22 00:00:00Z],
        provenance: %{"exposure" => %{"source" => "a"}}
      })

    b =
      build(%{
        captured_at: ~U[2026-09-23 11:22:33Z],
        provenance: %{"exposure" => %{"source" => "b"}}
      })

    assert a.hash == b.hash
  end

  test "material exposure, intelligence, findings and identity all change the hash" do
    base = build(%{})

    assert build(%{exposure: %{"state" => "current", "value" => "internet_exposed"}}).hash !=
             base.hash

    assert build(%{exposure: %{"state" => "expired", "value" => "unknown"}}).hash != base.hash
    assert build(%{exposure: %{"state" => "conflicting", "value" => "unknown"}}).hash != base.hash

    kev = %{"kev" => true, "ransomware" => true, "due_date" => nil, "required_action" => true}
    assert build(%{intel: kev}).hash != base.hash

    assert build(%{findings: [finding(1), finding(2)]}).hash != base.hash
    assert build(%{image_digest: "sha256:bbb"}).hash != base.hash
    assert build(%{placement: %{placement() | active: false}}).hash != base.hash
  end

  test "unavailable live edges are explicit blockers, never fabricated facts" do
    packet = build(%{})

    assert packet.blockers == Packet.live_blockers()
    assert Enum.all?(packet.blockers, &is_binary/1)
    refute Map.has_key?(Packet.material(packet), "register")
    refute Map.has_key?(Packet.material(packet), "scan_run")
  end

  test "coverage states distinguish current, changed, legacy and historical" do
    current = build(%{})
    other = build(%{image_digest: "sha256:other"})

    v2 = %{decision: "accepted_risk", metadata: %{"packet_hash" => current.hash}}
    assert Evidence.coverage_state(v2, packet_hash: current.hash) == :covered
    assert Evidence.coverage_state(v2, packet_hash: other.hash) == :evidence_changed

    legacy_v1 = %{decision: "accepted_risk", metadata: %{"evidence_hash" => "v1"}}

    # Default policy: flag, not demote — it keeps covering, visibly flagged.
    assert Evidence.legacy_policy() == :flag

    assert Evidence.coverage_state(legacy_v1, packet_hash: current.hash, legacy_hash: "v1") ==
             :legacy_flagged

    assert Evidence.covered?(:legacy_flagged)
    assert Evidence.legacy?(:legacy_flagged)

    legacy_nil = %{decision: "fixed", metadata: %{}}
    assert Evidence.coverage_state(legacy_nil, packet_hash: current.hash) == :legacy_flagged

    # A changed inventory still demotes it.
    legacy_other = %{decision: "accepted_risk", metadata: %{"evidence_hash" => "other"}}

    assert Evidence.coverage_state(legacy_other, packet_hash: current.hash, legacy_hash: "v1") ==
             :evidence_changed

    # The strict variant stays available.
    original = Application.get_env(:triage, :legacy_dismissal_policy)
    Application.put_env(:triage, :legacy_dismissal_policy, :demote)

    assert Evidence.coverage_state(legacy_v1, packet_hash: current.hash, legacy_hash: "v1") ==
             :legacy_unverified

    refute Evidence.covered?(:legacy_unverified)
    assert Evidence.legacy?(:legacy_unverified)

    if original,
      do: Application.put_env(:triage, :legacy_dismissal_policy, original),
      else: Application.delete_env(:triage, :legacy_dismissal_policy)

    work = %{decision: "investigate", metadata: %{"evidence_hash" => "v1"}}
    assert Evidence.coverage_state(work, packet_hash: current.hash, legacy_hash: "v1") == :covered

    assert Evidence.coverage_state(work, packet_hash: current.hash, legacy_hash: "other") ==
             :evidence_changed

    assert Evidence.coverage_state(nil, packet_hash: current.hash) == :uncovered
    assert Evidence.coverage_state(v2, packet_hash: current.hash, active?: false) == :historical
  end

  test "packet version and hash domain are pinned" do
    assert Evidence.packet_version() == 2
    assert Packet.hash_domain() == "triage.workspace.evidence.packet.v2"
    assert Packet.version() == 2
  end
end
