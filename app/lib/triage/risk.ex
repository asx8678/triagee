defmodule Triage.Risk do
  @moduledoc """
  Deterministic, explainable review priority for findings.

  Policy: severity is never downgraded. Exposure and exploitation data only
  affect *review priority*, never the scanner-reported severity. Unknown or
  stale exposure is treated as `unknown`, never as "safe". An available fix
  changes remediation, not danger. Internal placement alone never lowers
  priority below the severity baseline.

  Pure functions only: no database, no network, fully unit-testable.
  """

  @policy_version 1

  @priorities ~w(critical high medium low)
  @ranks Map.new(Enum.zip(@priorities, 4..1//-1))

  defstruct [:priority, :severity, :exposure, reasons: [], policy_version: @policy_version]

  @typedoc "One classified occurrence: its priority, the inputs behind it and the policy version."
  @type t :: %__MODULE__{
          priority: String.t(),
          severity: String.t(),
          exposure: String.t(),
          reasons: [String.t()],
          policy_version: pos_integer()
        }

  @spec policy_version() :: pos_integer()
  def policy_version, do: @policy_version
  @spec priorities() :: [String.t()]
  def priorities, do: @priorities

  @doc """
  Classifies one placement-level occurrence.

  Inputs (all optional, missing means unknown — never zero risk):
    * `:severity` — scanner severity string
    * `:exposure` — `"internet_exposed" | "internal" | "unknown"` or nil
    * `:known_exploited` — boolean or nil (nil/absent is NOT "not exploited")
    * `:fix_available` — boolean or nil (remediation information only)
  """
  @spec classify(map()) :: t()
  def classify(attrs) when is_map(attrs) do
    severity = attrs |> get(:severity) |> normalize_severity()

    exposure =
      case get(attrs, :exposure) do
        "internet_exposed" -> "internet_exposed"
        "internal" -> "internal"
        _ -> "unknown"
      end

    known_exploited = get(attrs, :known_exploited) == true
    fix_available = get(attrs, :fix_available) == true

    base = Triage.Severity.rank(severity)

    {level, reasons} =
      cond do
        known_exploited and base >= 3 ->
          {4, ["Actively exploited (KEV) with #{severity} severity"]}

        known_exploited ->
          {3, ["Actively exploited (KEV)"]}

        exposure == "internet_exposed" and base >= 3 ->
          {4, ["Internet-exposed placement with #{severity} severity"]}

        exposure == "internet_exposed" ->
          {3, ["Internet-exposed placement"]}

        base >= 4 ->
          {4, ["#{severity} severity; exposure not verified"]}

        base == 3 ->
          {3, ["#{severity} severity; exposure not verified"]}

        base == 2 ->
          {2, ["#{severity} severity"]}

        base == 1 ->
          {1, ["LOW severity"]}

        true ->
          {2, ["Severity not reported; treating as needing review"]}
      end

    additional_reasons = [
      {exposure == "internal",
       "Placement declared internal — likelihood input only, severity unchanged"},
      {fix_available, "Fix available — remediation information, does not reduce danger"},
      {not is_nil(get(attrs, :known_exploited)) and not known_exploited,
       "Not listed as known exploited — absence is not evidence"}
    ]

    reasons = reasons ++ for({true, reason} <- additional_reasons, do: reason)

    %__MODULE__{
      priority: priority_for(level),
      severity: severity || "NOT_REPORTED",
      exposure: exposure,
      reasons: reasons
    }
  end

  @doc "Aggregates placement-level priorities to a CVE-level maximum."
  @spec aggregate([t()]) :: t() | nil
  def aggregate(results) when is_list(results) and results != [] do
    Enum.max_by(results, &rank/1)
  end

  def aggregate([]), do: nil

  defp rank(%__MODULE__{priority: priority}), do: Map.fetch!(@ranks, priority)

  # Level 4 is the most urgent and `@priorities` is ordered most urgent first,
  # so the label for a level is that list indexed from the top. Reading the
  # label out of the same list `priorities/0` publishes keeps the public label
  # order and this mapping from drifting apart.
  defp priority_for(level), do: Enum.at(@priorities, 4 - level)

  defp normalize_severity(value), do: Triage.Severity.normalize(value)

  defp get(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Atom.to_string(key))
    end
  end
end
