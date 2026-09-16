defmodule Triage.RiskTest do
  use ExUnit.Case, async: true

  alias Triage.Risk

  describe "classify/1" do
    test "internet-exposed critical is highest priority" do
      result = Risk.classify(%{"severity" => "CRITICAL", "exposure" => "internet_exposed"})
      assert result.priority == "critical"
      assert "Internet-exposed placement with CRITICAL severity" in result.reasons
    end

    test "known exploited critical stays highest even when internal" do
      result =
        Risk.classify(%{
          "severity" => "CRITICAL",
          "exposure" => "internal",
          "known_exploited" => true
        })

      assert result.priority == "critical"
    end

    test "internal placement never downgrades severity-based priority" do
      exposed = Risk.classify(%{"severity" => "HIGH", "exposure" => "internet_exposed"})
      internal = Risk.classify(%{"severity" => "HIGH", "exposure" => "internal"})

      assert exposed.priority == "critical"
      assert internal.priority == "high"
      assert Enum.any?(internal.reasons, &String.contains?(&1, "severity unchanged"))
    end

    test "fix available is remediation information, not danger reduction" do
      no_fix = Risk.classify(%{"severity" => "HIGH", "fix_available" => false})
      fixed = Risk.classify(%{"severity" => "HIGH", "fix_available" => true})

      assert no_fix.priority == fixed.priority

      assert Enum.any?(fixed.reasons, fn r ->
               String.contains?(r, "Fix available") and
                 String.contains?(r, "remediation information")
             end)
    end

    test "unknown exposure is never lower than severity baseline" do
      medium = Risk.classify(%{"severity" => "MEDIUM", "exposure" => "unknown"})
      assert medium.priority == "medium"
    end

    test "unknown KEV flag is not asserted as safe" do
      result = Risk.classify(%{"severity" => "HIGH", "known_exploited" => false})
      assert Enum.any?(result.reasons, &String.contains?(&1, "absence is not evidence"))
    end

    test "missing severity still needs review" do
      result = Risk.classify(%{})
      assert result.priority == "medium"
      assert "Severity not reported; treating as needing review" in result.reasons
    end

    test "atom and string keys agree for true, false and unknown boolean inputs" do
      for flag <- [true, false, nil] do
        atom = %{
          severity: "HIGH",
          exposure: "internal",
          known_exploited: flag,
          fix_available: flag
        }

        string = Map.new(atom, fn {key, value} -> {Atom.to_string(key), value} end)
        assert Risk.classify(atom) == Risk.classify(string)
      end

      assert Enum.any?(
               Risk.classify(%{severity: "HIGH", known_exploited: false}).reasons,
               &String.contains?(&1, "absence is not evidence")
             )
    end

    test "an explicitly present atom key wins even when false or nil" do
      for value <- [false, nil] do
        mixed = %{"known_exploited" => true, severity: "HIGH", known_exploited: value}
        assert Risk.classify(mixed).priority == "high"
      end
    end

    test "policy_version is stable" do
      assert Risk.policy_version() == 1
    end
  end

  describe "aggregate/1" do
    test "aggregate picks the maximum placement priority" do
      high = Risk.classify(%{"severity" => "CRITICAL", "exposure" => "internet_exposed"})
      low = Risk.classify(%{"severity" => "LOW"})

      assert Risk.aggregate([low, high]) == high
      assert Risk.aggregate([high, low]) == high
    end

    test "all published priorities have a strict rank and ties keep the first result" do
      for {priority, index} <- Enum.with_index(Risk.priorities()) do
        winner = %Risk{priority: priority, reasons: ["first"]}
        tie = %Risk{priority: priority, reasons: ["second"]}
        lower = Enum.map(Enum.drop(Risk.priorities(), index + 1), &%Risk{priority: &1})
        assert Risk.aggregate(lower ++ [winner, tie]) == winner
      end
    end

    test "an invalid priority never silently becomes low urgency" do
      assert_raise KeyError, fn ->
        Risk.aggregate([%Risk{priority: "unexpected"}, %Risk{priority: "low"}])
      end
    end

    test "aggregate of empty is nil" do
      assert Risk.aggregate([]) == nil
    end
  end
end
