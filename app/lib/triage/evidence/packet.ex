defmodule Triage.Evidence.Packet do
  @moduledoc """
  Material evidence for one exact target scope (W01c, packet v2).

  A packet is the immutable set of facts a decision is made from: the placement
  and image identity, the findings, the *material* exposure state and the
  *material* intelligence facts. Provenance (when each part was read, from which
  source or generation) travels with the packet but is deliberately excluded
  from the hash, so a refresh that changes nothing material does not invalidate
  an approval, while a material change does.

  Material means "could change what an approval is allowed to claim":

    * exposure carries the displayed value and its validity class (`current`,
      `exp-ired`, `future_dated`, `conflicting`, `none`) — not observation
      timestamps, so a repeated identical observation changes nothing;
    * intelligence carries per-CVE KEV facts (presence, ransomware flag, due
      date presence and value, required-action presence) — not the generation
      content hash, so an unrelated advisory added elsewhere changes nothing;
    * findings, placement identity and image digest carry the inventory facts.

  Live-only edges (registry, scan-run and register provenance) are not
  fabricated: the packet records them as `live_blockers/0`, which is why a
  packet is never reported as live-eligible before W02/W03 supply verified
  provenance.
  """

  alias Triage.Canonical

  @version 2
  @hash_domain "triage.workspace.evidence.packet.v2"
  @live_blockers ["register_provenance_unavailable", "scan_run_provenance_unavailable"]

  defstruct version: @version,
            cve: nil,
            placement: %{},
            image_digest: nil,
            findings: [],
            exposure: %{},
            intel: %{},
            captured_at: nil,
            provenance: %{},
            blockers: [],
            hash: nil

  @type t :: %__MODULE__{}

  def version, do: @version
  def hash_domain, do: @hash_domain

  @doc "Edges that only a live source or register can supply; never invented."
  def live_blockers, do: @live_blockers

  @doc "Builds a packet and its hash from already-hydrated facts."
  @spec build(map()) :: t()
  def build(attrs) when is_map(attrs) do
    packet = %__MODULE__{
      cve: Map.get(attrs, :cve),
      placement: placement_material(Map.get(attrs, :placement)),
      image_digest: Map.get(attrs, :image_digest),
      findings: findings_material(Map.get(attrs, :findings) || []),
      exposure: exposure_material(Map.get(attrs, :exposure)),
      intel: intel_material(Map.get(attrs, :intel)),
      captured_at: Map.get(attrs, :captured_at),
      provenance: Map.get(attrs, :provenance) || %{},
      blockers: Map.get(attrs, :blockers) || live_blockers()
    }

    %{packet | hash: hash(packet)}
  end

  @doc "The packet hash: the versioned, canonical encoding of the material facts."
  @spec hash(t()) :: String.t()
  def hash(%__MODULE__{} = packet), do: Canonical.hash({@hash_domain, material(packet)})

  @doc """
  The hashable material subset, with string keys so the SQL twin can reproduce
  it byte for byte (see `Triage.Workspace.EvidenceSQL.packet_hash_sql/0`).
  """
  @spec material(t()) :: map()
  def material(%__MODULE__{} = packet) do
    %{
      "version" => @version,
      "cve" => packet.cve,
      "placement" => packet.placement,
      "image_digest" => packet.image_digest,
      "findings" => packet.findings,
      "exposure" => packet.exposure,
      "intel" => packet.intel
    }
  end

  @doc "Material exposure: the displayed value plus the validity class."
  @spec exposure_material(term()) :: map()
  def exposure_material(nil), do: %{"state" => "none", "value" => "unknown"}

  # Accepts both the structured evidence map from `Triage.Exposure` (atom keys)
  # and an already-material map (string keys), so the builder is idempotent.
  def exposure_material(%{} = evidence) do
    %{
      "state" => state_name(Map.get(evidence, :state) || Map.get(evidence, "state")),
      "value" => Map.get(evidence, :exposure) || Map.get(evidence, "value") || "unknown"
    }
  end

  def exposure_material(_other), do: %{"state" => "none", "value" => "unknown"}

  @doc "Material intelligence: per-CVE KEV facts, never generation-wide hashes."
  @spec intel_material(term()) :: map()
  def intel_material(nil),
    do: %{"kev" => false, "ransomware" => nil, "due_date" => nil, "required_action" => false}

  # Accepts a cached advisory row (atom keys, presence means KEV-listed) and an
  # already-material map (string keys), so the builder is idempotent.
  def intel_material(%{} = advisory) do
    kev = Map.get(advisory, :kev) || Map.get(advisory, "kev")

    %{
      "kev" => if(is_boolean(kev), do: kev, else: true),
      "ransomware" => Map.get(advisory, :known_ransomware) || Map.get(advisory, "ransomware"),
      "due_date" => Map.get(advisory, :due_date) || Map.get(advisory, "due_date"),
      "required_action" => required_action?(advisory)
    }
  end

  def intel_material(_other),
    do: %{"kev" => false, "ransomware" => nil, "due_date" => nil, "required_action" => false}

  @doc "Exposure provenance: source and observation time, never hashed."
  @spec exposure_provenance(term()) :: map() | nil
  def exposure_provenance(nil), do: nil

  def exposure_provenance(%{} = evidence) do
    %{
      "source" => Map.get(evidence, :source),
      "observed_at" => Map.get(evidence, :observed_at),
      "expires_at" => Map.get(evidence, :expires_at),
      "usable_for_dismissal?" => Map.get(evidence, :usable?)
    }
  end

  def exposure_provenance(_other), do: nil

  @doc "Intelligence provenance: which source and generation supplied the facts."
  @spec intel_provenance(term()) :: map() | nil
  def intel_provenance(nil), do: nil

  def intel_provenance(%{} = advisory) do
    %{
      "source" => Map.get(advisory, :source),
      "generation_id" => Map.get(advisory, :generation_id),
      "fetched_at" => Map.get(advisory, :fetched_at)
    }
  end

  def intel_provenance(_other), do: nil

  defp placement_material(nil), do: %{}

  defp placement_material(%{} = placement) do
    placement
    |> Map.take([:id, :image_id, :owner, :environment, :namespace, :active])
    |> Map.new()
  end

  defp placement_material(_other), do: %{}

  defp findings_material(findings) do
    fields = [
      :id,
      :package_name,
      :package_version,
      :severity,
      :fix,
      :description,
      :resolved_at,
      :reopen_count,
      :first_seen,
      :suppressed
    ]

    findings
    |> Enum.map(fn finding -> finding |> Map.take(fields) |> Map.new() end)
    |> Enum.sort_by(&Map.get(&1, :id, 0))
  end

  defp required_action?(advisory) do
    case Map.get(advisory, :required_action) || Map.get(advisory, "required_action") do
      nil -> false
      false -> false
      _other -> true
    end
  end

  defp state_name(nil), do: "none"
  defp state_name(state) when is_atom(state), do: Atom.to_string(state)
  defp state_name(state), do: to_string(state)
end
