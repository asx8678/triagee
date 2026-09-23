defmodule Triage.Exposure.Policy do
  @moduledoc """
  Versioned exposure-evidence policy (W01b/A08).

  Displaying exposure and *trusting* exposure are different questions. Evidence
  from a source with an explicitly approved, bounded maximum age can support a
  dismissal; anything else — an unknown source, an unbounded age, evidence
  older than the approved age, or a missing expiry where the source requires
  one — never can. Such evidence can still prompt human investigation, and its
  display value is unchanged, but it must not close work.

  Approved sources are administrator configuration (non-secret):

      config :triage, :exposure_policy, %{
        "scanner:trivy" => %{max_age_days: 30, require_expiry: true}
      }

  The default is an empty map: every source is unknown, so no exposure evidence
  can support a dismissal until an operator approves a bounded policy. The
  clock tolerance is part of this versioned policy and is shared with the SQL
  projection, so the two can never disagree about what counts as future-dated.
  """

  @version 1
  @clock_tolerance_seconds 300

  @doc "The policy version; bump only with parity tests."
  def version, do: @version

  @doc "Approved tolerance for clock skew when judging an observation time."
  def clock_tolerance_seconds, do: @clock_tolerance_seconds

  @doc "Approved policy for one evidence source; unknown sources are unbounded."
  @spec for_source(term()) :: %{max_age_days: pos_integer() | nil, require_expiry: boolean()}
  def for_source(source) when is_binary(source) do
    case Application.get_env(:triage, :exposure_policy, %{}) do
      %{} = configured -> normalize(Map.get(configured, source))
      _other -> unbounded()
    end
  end

  def for_source(_other), do: unbounded()

  @doc """
  Whether one evidence row's observation can support a dismissal at `now`.

  Requires an approved bounded maximum age; an unbounded or unapproved source
  always returns false (fail closed).
  """
  @spec usable?(map() | term(), DateTime.t()) :: boolean()
  def usable?(%{source: source, observed_at: observed_at, expires_at: expires_at}, now) do
    policy = for_source(source)

    cond do
      is_nil(policy.max_age_days) -> false
      is_nil(observed_at) -> false
      DateTime.compare(observed_at, DateTime.add(now, -policy.max_age_days, :day)) == :lt -> false
      policy.require_expiry and is_nil(expires_at) -> false
      true -> true
    end
  end

  def usable?(_other, _now), do: false

  defp normalize(%{} = policy) do
    days = Map.get(policy, :max_age_days) || Map.get(policy, "max_age_days")
    require = Map.get(policy, :require_expiry) || Map.get(policy, "require_expiry")

    if is_integer(days) and days > 0,
      do: %{max_age_days: days, require_expiry: require == true},
      else: unbounded()
  end

  defp normalize(_other), do: unbounded()

  defp unbounded, do: %{max_age_days: nil, require_expiry: false}
end
