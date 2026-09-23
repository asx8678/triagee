defmodule Triage.Evidence do
  @moduledoc """
  Evidence currency and coverage (W01c).

  A decision is only a current claim while the material evidence it was made
  from is still the material evidence on the target. Two hash domains exist:

    * **v2 (`Triage.Evidence.Packet`)** — placement, image digest, findings,
      material exposure state and material KEV facts. Decisions recorded from
      here store `metadata["packet_hash"]`.
    * **v1 (`Triage.Workspace.EvidenceSQL`)** — the earlier hash over placement,
      digest and findings only. It cannot express exposure or intelligence
      changes, so it is never treated as a current approval: v1 and nil-hash
      *dismissal* decisions report `:legacy_unverified` and return to review
      instead of being promoted. Work requests keep their v1 binding, because a
      request for human work is not an approval.

  Expiry is decided by `Triage.Decisions.state/2` (with its exclusive boundary)
  before coverage is asked about; this module answers only the evidence
  dimension.
  """

  alias Triage.Evidence.Packet

  # Decisions that assert the target needs no further work. These must be backed
  # by current material evidence to keep covering.
  @dismissal_decisions ~w(accepted_risk fixed not_affected)
  @work_actions ~w(request_remediation investigate request_verification create_ticket)

  @doc "The packet version these rules reason about."
  def packet_version, do: Packet.version()

  @doc "Whether this decision value claims the work is settled."
  def dismissal?(decision), do: decision in @dismissal_decisions

  @doc "Whether this decision value is a request for human work."
  def work_action?(decision), do: decision in @work_actions

  @doc """
  Coverage state of one decision against the current evidence.

  Returns:
    * `:uncovered` — no recorded decision;
    * `:historical` — a retired scope: the recorded decision stays visible;
    * `:covered` — the decision's own hash still matches current evidence;
    * `:evidence_changed` — the decision was bound to different material facts;
    * `:legacy_unverified` — a dismissal recorded before packets existed (v1 or
      no hash): readable history, never a current approval.
  """
  @spec coverage_state(map() | nil, keyword()) :: atom()
  def coverage_state(nil, _opts), do: :uncovered

  def coverage_state(decision, opts) when is_map(decision) do
    if Keyword.get(opts, :active?, true) == false do
      :historical
    else
      evidence_state(decision, Map.get(decision, :metadata) || %{}, opts)
    end
  end

  def coverage_state(_other, _opts), do: :uncovered

  @doc """
  Whether a coverage state keeps the target out of the needs queue.

  `:legacy_flagged` covers: pre-packet approvals stay in force while visibly
  flagged unverified instead of flooding the queue (owner decision, 22 Sep 2026).
  """
  def covered?(:covered), do: true
  def covered?(:historical), do: true
  def covered?(:legacy_flagged), do: true
  def covered?(_other), do: false

  @doc "Whether the state is a pre-packet approval (flagged or demoted)."
  def legacy?(:legacy_flagged), do: true
  def legacy?(:legacy_unverified), do: true
  def legacy?(_other), do: false

  @doc """
  Policy for pre-packet dismissals, set by the owner.

    * `:flag` (default) — keep covering as `:legacy_flagged` while the decision's
      own v1 evidence hash is absent or unchanged; an inventory change demotes it.
      Material exposure/intelligence changes cannot be detected for these rows,
      which is exactly what the visible flag reports.
    * `:demote` — report `:legacy_unverified` and return every pre-packet
      dismissal to review.
  """
  def legacy_policy do
    case Application.get_env(:triage, :legacy_dismissal_policy, :flag) do
      :demote -> :demote
      _other -> :flag
    end
  end

  # Under `:demote` every pre-packet dismissal returns to review. Under the
  # default `:flag` it keeps covering while its own v1 evidence hash is absent or
  # still matches, so a changed inventory still demotes it.
  defp legacy_dismissal_state(metadata, legacy_hash) do
    cond do
      legacy_policy() == :demote -> :legacy_unverified
      Map.get(metadata, "evidence_hash") in [nil, legacy_hash] -> :legacy_flagged
      true -> :evidence_changed
    end
  end

  defp evidence_state(decision, metadata, opts) do
    packet_hash = Map.get(metadata, "packet_hash")
    current_hash = Keyword.get(opts, :packet_hash)
    legacy_hash = Keyword.get(opts, :legacy_hash)

    cond do
      present?(packet_hash) and packet_hash == current_hash ->
        :covered

      present?(packet_hash) ->
        :evidence_changed

      dismissal?(Map.get(decision, :decision)) ->
        legacy_dismissal_state(metadata, legacy_hash)

      present?(legacy_hash) and Map.get(metadata, "evidence_hash") in [nil, legacy_hash] ->
        :covered

      true ->
        :evidence_changed
    end
  end

  @doc "Human-readable reason for a non-covering state; nil when covered."
  def coverage_reason(:legacy_flagged),
    do: "Pre-packet approval kept in force; flagged unverified"

  def coverage_reason(:legacy_unverified),
    do: "Recorded before evidence packets; needs review again"

  def coverage_reason(:evidence_changed),
    do: "Material evidence changed since this decision"

  def coverage_reason(_other), do: nil

  defp present?(value), do: is_binary(value) and value != ""
end
