defmodule Triage.Classifier.Policy do
  @moduledoc "Pure semantic guard. The model can suggest, but cannot authorize a whitelist."
  @version "whitelist-v1"
  @dispositions ~w(whitelist_candidate do_not_whitelist needs_human)
  @citations ~w(inventory source register exposure kev applicability)

  def version, do: @version
  def dispositions, do: @dispositions

  def evaluate(evidence, raw) when is_map(raw) do
    output = Map.get(raw, "output", %{})
    output = if is_map(output), do: output, else: %{}
    unsafe = output["classification"] == "whitelist_candidate" and threat?(evidence)

    validation =
      validate(output) ++
        if(raw["invalid_envelope"] == true, do: ["invalid_model_envelope"], else: [])

    reasons = validation ++ whitelist_blocks(evidence, output)

    %{
      suggestion: if(reasons == [], do: output["classification"], else: "needs_human"),
      reasons: Enum.uniq(reasons),
      unsafe: unsafe,
      state:
        if(validation == [],
          do: if(reasons == [], do: "completed", else: "blocked"),
          else: "invalid"
        )
    }
  end

  def threat?(s) do
    s["kev"]["listed"] == true or
      (s["inventory"]["severity"] == "CRITICAL" and s["exposure"]["value"] == "internet_exposed") or
      s["applicability"]["status"] == "affected"
  end

  defp validate(output) do
    citations = output["citations"]

    cond do
      Enum.sort(Map.keys(output)) != ~w(citations classification rationale) ->
        ["invalid_output_schema"]

      output["classification"] not in @dispositions ->
        ["invalid_classification"]

      not is_binary(output["rationale"]) ->
        ["missing_rationale"]

      not rationale?(output["rationale"]) ->
        ["invalid_rationale"]

      not citation_list?(citations) ->
        ["missing_citations"]

      not Enum.all?(citations, &(&1 in @citations)) ->
        ["unknown_citation"]

      true ->
        []
    end
  end

  defp citation_list?(value), do: is_list(value) and length(value) in 1..6
  defp rationale?(value), do: byte_size(value) <= 4000 and String.trim(value) != ""

  defp whitelist_blocks(s, %{"classification" => "whitelist_candidate"} = output) do
    citations = output["citations"]

    required_citations =
      is_list(citations) and
        Enum.all?(~w(source register exposure kev applicability), &(&1 in citations))

    [
      {threat?(s), "threat_requires_human_investigation"},
      {s["exposure"]["state"] != "current" or s["exposure"]["usable"] != true,
       "untrusted_exposure"},
      {s["exposure"]["value"] not in ~w(internal internet_exposed), "unknown_exposure"},
      {s["kev"]["current"] != true, "kev_freshness_unknown"},
      {s["applicability"]["status"] != "not_affected", "internal_only_is_not_non_applicability"},
      {not required_citations, "whitelist_requires_evidence_citations"}
    ]
    |> Enum.filter(&elem(&1, 0))
    |> Enum.map(&elem(&1, 1))
  end

  defp whitelist_blocks(_, _), do: []
end
