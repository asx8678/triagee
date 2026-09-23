defmodule Triage.ClassifierPolicyTest do
  use ExUnit.Case, async: true
  alias Triage.Classifier.Policy

  defp safe do
    %{
      "inventory" => %{"severity" => "HIGH"},
      "exposure" => %{"value" => "internal", "state" => "current", "usable" => true},
      "kev" => %{"listed" => false, "current" => true},
      "applicability" => %{"status" => "not_affected"}
    }
  end

  defp raw do
    %{
      "output" => %{
        "classification" => "whitelist_candidate",
        "rationale" => "Scoped non-applicability evidence",
        "citations" => ~w(source register exposure kev applicability)
      }
    }
  end

  test "candidate requires explicit non-applicability, current trusted evidence and citations" do
    assert %{state: "completed", suggestion: "whitelist_candidate", unsafe: false} =
             Policy.evaluate(safe(), raw())

    for evidence <- [
          put_in(safe(), ["applicability", "status"], "unknown"),
          put_in(safe(), ["exposure", "usable"], false),
          put_in(safe(), ["exposure", "state"], "expired"),
          put_in(safe(), ["exposure", "value"], "unknown"),
          put_in(safe(), ["kev", "current"], false)
        ] do
      assert %{state: "blocked", suggestion: "needs_human"} = Policy.evaluate(evidence, raw())
    end
  end

  test "KEV, exposed Critical and known affected suggestions are unsafe even if schema is invalid" do
    critical =
      safe()
      |> put_in(["inventory", "severity"], "CRITICAL")
      |> put_in(["exposure", "value"], "internet_exposed")

    for evidence <- [
          critical,
          put_in(safe(), ["kev", "listed"], true),
          put_in(safe(), ["applicability", "status"], "affected")
        ] do
      assert %{suggestion: "needs_human", unsafe: true} = Policy.evaluate(evidence, raw())

      assert %{unsafe: true} =
               Policy.evaluate(evidence, put_in(raw(), ["output", "citations"], []))
    end
  end

  test "rejected tool envelopes still count dangerous textual whitelist suggestions" do
    evidence = put_in(safe(), ["kev", "listed"], true)

    assert %{state: "invalid", unsafe: true, suggestion: "needs_human"} =
             Policy.evaluate(evidence, Map.put(raw(), "invalid_envelope", true))
  end

  test "unknown citations, arbitrary actions, extra fields and malformed JSON cannot become suggestions" do
    for output <- [
          nil,
          %{},
          %{"classification" => "whitelist"},
          Map.put(raw()["output"], "command", "merge"),
          put_in(raw()["output"], ["citations"], ["https://untrusted.test"]),
          put_in(raw()["output"], ["rationale"], " ")
        ] do
      assert %{state: "invalid", suggestion: "needs_human"} =
               Policy.evaluate(safe(), %{"output" => output})
    end
  end
end
