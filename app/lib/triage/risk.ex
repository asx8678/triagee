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

  @severity_weight %{"CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1}
  @priorities ~w(critical high medium low)

  defstruct [:priority, :severity, :exposure, reasons: [], policy_version: @policy_version]

  def policy_version, do: @policy_version
  def priorities, do: @priorities

  @doc """
  Classifies one placement-level occurrence.

  Inputs (all optional, missing means unknown — never zero risk):
    * `:severity` — scanner severity string
    * `:exposure` — `"internet_exposed" | "internal" | "unknown"` or nil
    * `:known_exploited` — boolean or nil (nil/absent is NOT "not exploited")
    * `:fix_available` — boolean or nil (remediation information only)
  """
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

    base = Map.get(@severity_weight, severity, 0)

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

    reasons =
      reasons
      |> Kernel.++(
        if exposure == "internal",
          do: ["Placement declared internal — likelihood input only, severity unchanged"],
          else: []
      )
      |> Kernel.++(
        if fix_available,
          do: ["Fix available — remediation information, does not reduce danger"],
          else: []
      )
      |> Kernel.++(
        if is_nil(get(attrs, :known_exploited)),
          do: [],
          else:
            if(known_exploited,
              do: [],
              else: ["Not listed as known exploited — absence is not evidence"]
            )
      )

    %__MODULE__{
      priority: priority_for(level),
      severity: severity || "NOT_REPORTED",
      exposure: exposure,
      reasons: reasons
    }
  end

  @doc "Aggregates placement-level priorities to a CVE-level maximum."
  def aggregate(results) when is_list(results) and results != [] do
    Enum.max_by(results, &rank/1)
  end

  def aggregate([]), do: nil

  defp rank(%__MODULE__{priority: p}),
    do: Enum.find_index(@priorities |> Enum.reverse(), &(&1 == p)) || 0

  # Level 4 is the most urgent and `@priorities` is ordered most urgent first,
  # so the label for a level is that list indexed from the top. Reading the
  # label out of the same list `priorities/0` publishes keeps the public label
  # order and this mapping from drifting apart.
  defp priority_for(level), do: Enum.at(@priorities, 4 - level)

  defp normalize_severity(nil), do: nil

  defp normalize_severity(s) when is_binary(s) do
    case String.upcase(String.trim(s)) do
      "CRITICAL" -> "CRITICAL"
      "HIGH" -> "HIGH"
      "MEDIUM" -> "MEDIUM"
      "LOW" -> "LOW"
      _ -> nil
    end
  end

  defp get(map, key) do
    Map.get(map, key) || Map.get(map, Atom.to_string(key))
  end
end
