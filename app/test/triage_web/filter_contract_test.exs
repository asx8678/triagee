defmodule TriageWeb.FilterContractTest do
  use ExUnit.Case, async: true

  alias TriageWeb.{CaseFilters, FindingFilters, TimelineFilters}

  test "all scalar fields reject raw controls, invalid UTF-8 and wrong types" do
    controls = for byte <- Enum.to_list(0..31) ++ [127], do: <<byte>>
    invalid = controls ++ [<<0xFF>>, <<0xC0, 0x80>>, false, true, 1, [], %{}, %URI{}]

    for field <- ~w(owner environment q severity sort suppressed), value <- invalid do
      parsed = FindingFilters.parse(%{field => value})
      assert parsed.invalid == [String.to_existing_atom(field)]
      refute parsed.include_suppressed
    end

    for {field, token} <- [{"severity", "high"}, {"sort", "cve"}, {"suppressed", "on"}],
        control <- controls do
      assert FindingFilters.parse(%{field => control <> token}).invalid != []
      assert FindingFilters.parse(%{field => token <> control}).invalid != []
    end
  end

  test "finite vocabularies preserve normalization, blank defaults and long padding" do
    examples =
      Enum.map(~w(CRITICAL HIGH MEDIUM LOW), &{"severity", String.downcase(&1), :severity, &1}) ++
        Enum.map(FindingFilters.sorts(), &{"sort", String.upcase(&1), :sort, &1}) ++
        [
          {"severity", "hıgh", :severity, "HIGH"},
          {"suppressed", "on", :include_suppressed, true},
          {"suppressed", "false", :include_suppressed, false}
        ]

    for {field, token, key, expected} <- examples,
        padding <- ["", " ", String.duplicate(" ", 200)] do
      parsed = FindingFilters.parse(%{field => padding <> token <> padding})
      assert parsed.invalid == []
      assert Map.fetch!(parsed, key) == expected
    end

    for field <- ~w(severity sort suppressed), blank <- [nil, "", "  ", "\u00A0"] do
      assert FindingFilters.parse(%{field => blank}) == FindingFilters.defaults()
    end

    for token <- ["TRUE", "ON", "FALSE", String.duplicate("x", 121)] do
      assert FindingFilters.parse(%{"suppressed" => token}).invalid == [:suppressed]
    end
  end

  test "case and timeline wrappers accept only scope-valid blank sibling fields" do
    contracts = [
      {CaseFilters, ~w(owner environment before)},
      {TimelineFilters, ~w(owner environment weeks cve events_after cases_after)}
    ]

    for {module, fields} <- contracts, field <- fields do
      for blank <- [nil, "", "  ", "\u00A0", String.duplicate(" ", 200)] do
        parsed = module.parse_event(%{"filters" => %{"owner" => "alpha"}, field => blank})
        assert parsed.owner == "alpha"
        assert parsed.invalid == []
      end

      for invalid <- ["\t", "\n", "\u0000", "\u007F", <<0xFF>>, "value", false, [], %{}] do
        parsed = module.parse_event(%{"filters" => %{"owner" => "alpha"}, field => invalid})
        assert parsed.invalid == [:filters]
        assert parsed.owner == nil
      end
    end
  end
end
