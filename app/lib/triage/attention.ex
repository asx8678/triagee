defmodule Triage.Attention do
  @moduledoc """
  Versioned, deterministic scope-local attention policy (T05).

  Attention determines *review order* — which recorded target most needs a
  human step next. It is not a safety verdict, not a CVSS score, and never a
  claim about exploitability. Smaller band = more urgent.

  The bands are computed from recorded facts only: active scope, effective
  decision coverage, the Risk policy's severity/exploitation classification,
  and the decision's work due date. Unknown facts never become positive
  safety conclusions (I10, D14). Changing this policy changes queue order;
  it never changes authorization, exception validity, or evidence.

  SQL and Elixir must agree per target; `Triage.Workspace.Query` embeds the
  same band expression and both projections are parity-tested.
  """

  @version 2
  @review_lead_days 7

  @doc "The policy version; bump only with queue-order parity tests."
  def version, do: @version

  @doc "Days before expiry that an exception enters review-due attention."
  def review_lead_days, do: @review_lead_days

  @doc """
  Attention band for one exact target. Smaller is more urgent.

  * 0 — needs attention now: active and uncovered, no effective decision.
  * 1 — review due: covered by an exception whose expiry is within the
    review lead window (or already past it but the target is still active),
    or covered by a reported fix that still needs deployment verification
    (a fix claim is not a verified remediation — A24).
  * 2 — work in progress: covered by a valid investigation, remediation
    request, ticket, or verification request. A verification request is the
    recognized current work for a reported fix and is not re-nagged.
  * 3 — covered, no action needed: a valid risk acceptance. (A verified
    deployed fix would also land here, but no verified state exists yet; a
    merely reported fix never does.)
  * 4 — historical: not an active scope (retired or no longer observed).

  The Risk policy's priority (critical → low) breaks ties *within* a band
  via the existing severity-first ordering in SQL; this module never
  overrides scanner severity or claims exploitation.
  """
  @spec band(map()) :: 0..4
  def band(target, now \\ DateTime.utc_now()) do
    cond do
      not target.active? -> 4
      not target.covered? -> 0
      review_due?(target, now) -> 1
      verification_due?(target) -> 1
      work_in_progress?(target) -> 2
      true -> 3
    end
  end

  @doc """
  Deterministic, read-only human reason for a target's band. Displayed with
  the queue row so the needed human step stays visible independently of the
  recorded workflow status. This is a derivation only: no work rows, jobs or
  decisions are created here (W01a/A24).
  """
  @spec reason(map()) :: String.t()
  def reason(target, now \\ DateTime.utc_now()) do
    case band(target, now) do
      4 -> "Historical: no longer observed in this scope"
      0 -> band_zero_reason(target)
      1 -> band_one_reason(target)
      2 -> "Work in progress: #{Triage.Decisions.label(target.decision.decision)}"
      3 -> "Covered: #{Triage.Decisions.label(target.decision.decision)}"
    end
  end

  @doc "True when the target needs a new human step (bands 0 or 1)."
  @spec needs_attention?(map()) :: boolean()
  def needs_attention?(target, now \\ DateTime.utc_now()), do: band(target, now) in [0, 1]

  @doc "True when the target has active recorded work (band 2)."
  @spec in_progress?(map()) :: boolean()
  def in_progress?(target), do: band(target) == 2

  @doc "True when the target has no current action need (bands 3 or 4)."
  @spec tracked?(map()) :: boolean()
  def tracked?(target), do: band(target) in [3, 4]

  @doc """
  SQL expression for the attention band, embedded in `Workspace.Query`.
  Mirrors `band/1` exactly; the parity test asserts the two agree on every
  target shape the fixtures produce. Parameters: $3 is the shared `now`
  timestamp, `covered` and `active` come from the target_facts CTE, and
  `d.expires_at` / `d.decision` from the effective decision lateral join.
  """
  def sql do
    """
    CASE
      WHEN NOT t.active THEN 4
      WHEN NOT covered THEN 0
      WHEN d.expires_at IS NOT NULL AND d.expires_at <= ($3::timestamp + interval '#{review_lead_days()} days') THEN 1
      WHEN covered AND d.decision = 'fixed' THEN 1
      WHEN covered AND d.decision IN ('investigate', 'request_remediation', 'request_verification', 'create_ticket') THEN 2
      ELSE 3
    END
    """
  end

  defp review_due?(target, now) do
    case target.decision do
      %{expires_at: nil} ->
        false

      %{expires_at: expires_at} ->
        DateTime.compare(expires_at, review_deadline(now)) != :gt

      nil ->
        false
    end
  end

  defp review_deadline(now) do
    DateTime.add(now, @review_lead_days, :day)
  end

  # A reported fix is a claim, not a verified remediation (A24): the target
  # still needs a human verification step, so it stays in attention instead
  # of sinking to band 3. A reviewer who records request_verification moves
  # the target to band 2 — recognized current work, not a duplicate nag.
  defp verification_due?(%{decision: %{decision: "fixed"}}), do: true
  defp verification_due?(_target), do: false

  # An uncovered target that already carries a decision is uncovered because
  # that decision's material evidence no longer matches (or predates packets),
  # which is a different human step from "no decision yet".
  defp band_zero_reason(%{coverage_state: state})
       when state in [:legacy_unverified, :evidence_changed],
       do: Triage.Evidence.coverage_reason(state)

  defp band_zero_reason(_target), do: "Needs a decision: active and uncovered"

  defp band_one_reason(%{coverage_state: :legacy_flagged}),
    do: "Pre-packet approval kept in force; flagged unverified"

  defp band_one_reason(%{decision: %{decision: "fixed"}}),
    do: "Reported fix awaiting verification"

  defp band_one_reason(_target), do: "Exception expiring: review due"

  defp work_in_progress?(target) do
    case target.decision do
      %{decision: decision}
      when decision in [
             "investigate",
             "request_remediation",
             "request_verification",
             "create_ticket"
           ] ->
        true

      _ ->
        false
    end
  end
end
