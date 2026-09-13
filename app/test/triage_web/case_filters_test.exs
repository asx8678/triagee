defmodule TriageWeb.CaseFiltersTest do
  @moduledoc """
  Unit regressions for the review queue's parameter contract: owner and
  environment scope values, the `before` keyset cursor, the reserved `filters`
  wrapper, ambiguous event shapes and canonical query-param emission.
  """

  use ExUnit.Case, async: true

  alias TriageWeb.CaseFilters
  alias TriageWeb.FindingFilters

  describe "parse/1 URL params" do
    test "absent or blank fields are the intentional All/newest state" do
      assert CaseFilters.parse(%{}) == %{
               owner: nil,
               environment: nil,
               before_id: nil,
               invalid: []
             }

      assert CaseFilters.parse(%{"owner" => "  ", "environment" => "", "before" => ""}) ==
               %{owner: nil, environment: nil, before_id: nil, invalid: []}
    end

    test "valid trimmed scopes and a valid cursor are kept" do
      parsed =
        CaseFilters.parse(%{"owner" => " alpha ", "environment" => "beta", "before" => "42"})

      assert parsed.owner == "alpha"
      assert parsed.environment == "beta"
      assert parsed.before_id == 42
      assert parsed.invalid == []
    end

    test "genuinely unrelated URL metadata is ignored, never invalidating" do
      parsed =
        CaseFilters.parse(%{
          "q" => String.duplicate("a", 300),
          "suppressed" => "maybe",
          "return_to" => "/somewhere",
          "page" => "2",
          "sort" => "cve",
          "_target" => ["owner"]
        })

      assert parsed.invalid == []
      assert parsed.owner == nil
    end

    test "a malformed unrelated value never masks an invalid scope value" do
      parsed = CaseFilters.parse(%{"q" => <<0xFF>>, "owner" => "\tal"})

      assert :owner in parsed.invalid
      assert parsed.invalid == [:owner]
      assert parsed.owner == nil
    end

    test "a top-level filters wrapper key is rejected in URL params" do
      parsed = CaseFilters.parse(%{"filters" => %{"owner" => "beta"}, "owner" => "alpha"})

      assert :filters in parsed.invalid
      assert parsed.owner == nil
      assert parsed.before_id == nil
    end

    test "non-map terms are total: invalid state, no crash" do
      for term <- [123, nil, [], true, "not-a-map", :atom] do
        parsed = CaseFilters.parse(term)

        assert :filters in parsed.invalid
        assert parsed.owner == nil
      end
    end

    test "structs are rejected as non-plain maps" do
      for term <- [%Triage.Cases.ReviewCase{}, %URI{}] do
        parsed = CaseFilters.parse(term)

        assert :filters in parsed.invalid
        assert parsed.owner == nil
        assert parsed.environment == nil
        assert parsed.before_id == nil
      end
    end

    test "nonbinary scope and cursor values are rejected, never coerced" do
      for value <- [%{"0" => "alpha"}, ["alpha"], 123, :alpha] do
        parsed = CaseFilters.parse(%{"owner" => value})
        assert :owner in parsed.invalid
        assert parsed.owner == nil
      end

      for value <- [42, ["42"], %{"a" => "1"}, true] do
        parsed = CaseFilters.parse(%{"before" => value})
        assert :before in parsed.invalid
        assert parsed.before_id == nil
      end
    end

    test "raw control characters are rejected before trimming, even edge-only values" do
      for value <- ["\talpha", "alpha\n", "\ralpha", " \t ", "\u0000", "\u007F"] do
        parsed = CaseFilters.parse(%{"owner" => value, "environment" => value})

        assert :owner in parsed.invalid
        assert :environment in parsed.invalid
      end
    end

    test "invalid UTF-8 binaries are rejected before trimming, never coerced" do
      parsed = CaseFilters.parse(%{"owner" => "alpha" <> <<0xFF>>, "environment" => <<0x80>>})

      assert :owner in parsed.invalid
      assert :environment in parsed.invalid
      assert parsed.owner == nil
    end

    test "scope values longer than 120 characters are rejected, not truncated" do
      assert :owner in CaseFilters.parse(%{"owner" => String.duplicate("a", 121)}).invalid

      assert :environment in CaseFilters.parse(%{"environment" => String.duplicate("e", 121)}).invalid

      assert CaseFilters.parse(%{"owner" => String.duplicate("a", 120)}).owner ==
               String.duplicate("a", 120)
    end
  end

  describe "parse/1 cursor" do
    test "zero, negatives and signs are rejected" do
      for value <- ["0", "-1", "+1", "-0", "00"] do
        parsed = CaseFilters.parse(%{"before" => value})
        assert :before in parsed.invalid
        assert parsed.before_id == nil
      end
    end

    test "19 digits parse within bigint bounds; overflow and 20 digits are rejected" do
      assert CaseFilters.parse(%{"before" => "9223372036854775807"}).before_id ==
               9_223_372_036_854_775_807

      for value <- ["9223372036854775808", "9999999999999999999", String.duplicate("9", 20)] do
        parsed = CaseFilters.parse(%{"before" => value})
        assert :before in parsed.invalid
        assert parsed.before_id == nil
      end
    end

    test "whitespace, floats, non-decimal and non-ASCII digit forms are rejected" do
      for value <- [" 42", "42 ", "\t42", "42\n", "42.5", "1e3", "0x10", "٤٢", "4 2", "abc", ""] do
        # "" is the documented empty/newest case, not a rejection
        if value == "" do
          assert CaseFilters.parse(%{"before" => value}).before_id == nil
        else
          parsed = CaseFilters.parse(%{"before" => value})
          assert :before in parsed.invalid
          assert parsed.before_id == nil
        end
      end
    end

    test "cursor controls and invalid UTF-8 are rejected" do
      for value <- ["42\u0000", "42\u007F", "42" <> <<0xFF>>] do
        parsed = CaseFilters.parse(%{"before" => value})
        assert :before in parsed.invalid
        assert parsed.before_id == nil
      end
    end

    test "an invalid cursor is reported beside a valid scope without losing it" do
      parsed = CaseFilters.parse(%{"owner" => "alpha", "before" => "oops"})

      assert parsed.owner == "alpha"
      assert :before in parsed.invalid
      assert parsed.invalid == [:before]
    end
  end

  describe "parse_event/1" do
    test "flat form params parse like URL params and ignore _target" do
      parsed =
        CaseFilters.parse_event(%{
          "owner" => "beta",
          "environment" => "",
          "before" => "7",
          "_target" => ["owner"]
        })

      assert parsed.owner == "beta"
      assert parsed.environment == nil
      assert parsed.before_id == 7
      assert parsed.invalid == []
    end

    test "a plain filters wrapper is unwrapped once and validated" do
      parsed = CaseFilters.parse_event(%{"filters" => %{"owner" => "beta", "before" => "9"}})

      assert parsed.owner == "beta"
      assert parsed.before_id == 9
      assert parsed.invalid == []
    end

    test "a wrapper alongside the form's serialized blank fields still parses" do
      parsed =
        CaseFilters.parse_event(%{
          "owner" => "",
          "environment" => "  ",
          "before" => "",
          "filters" => %{"owner" => "beta"},
          "_target" => ["filters"]
        })

      assert parsed.owner == "beta"
      assert parsed.before_id == nil
      assert parsed.invalid == []
    end

    test "a wrapper beside a nonblank flat scope value is rejected as ambiguous" do
      parsed = CaseFilters.parse_event(%{"filters" => %{"owner" => "beta"}, "owner" => "alpha"})

      assert :filters in parsed.invalid
      assert parsed.owner == nil
    end

    test "a wrapper beside a nonblank flat before cursor is rejected as ambiguous" do
      parsed = CaseFilters.parse_event(%{"filters" => %{"owner" => "beta"}, "before" => "9"})

      assert :filters in parsed.invalid
      assert parsed.before_id == nil
    end

    test "a wrapper beside an invalid flat value is rejected, not unwrapped" do
      parsed = CaseFilters.parse_event(%{"filters" => %{"owner" => "beta"}, "owner" => "\tal"})

      assert :filters in parsed.invalid
      assert parsed.owner == nil
    end

    test "a doubly nested filters wrapper is rejected, never unwrapped to All" do
      parsed = CaseFilters.parse_event(%{"filters" => %{"filters" => %{"owner" => ["alpha"]}}})

      assert :filters in parsed.invalid
      assert parsed.owner == nil
      assert parsed.before_id == nil
    end

    test "a non-map wrapper and non-map event bodies are total" do
      assert :filters in CaseFilters.parse_event(%{"filters" => "not-a-map"}).invalid

      for body <- [123, nil, [], true, "not-a-map", :atom] do
        parsed = CaseFilters.parse_event(body)
        assert :filters in parsed.invalid
        assert parsed.owner == nil
      end
    end

    test "an outer struct event body carrying a filters key is rejected, never unwrapped" do
      # Frozen contract: ALL non-plain-map event bodies are rejected. A struct
      # with a string-key "filters" entry must not slip through the wrapper
      # clause just because the wrapper value itself is a plain map.
      for body <- [
            Map.put(%URI{}, "filters", %{"owner" => "alpha"}),
            Map.put(%Triage.Cases.ReviewCase{}, "filters", %{"owner" => "alpha", "before" => "9"})
          ] do
        parsed = CaseFilters.parse_event(body)

        assert :filters in parsed.invalid
        assert parsed.owner == nil
        assert parsed.environment == nil
        assert parsed.before_id == nil
      end
    end

    test "struct event bodies and struct wrapper values are rejected as non-plain maps" do
      for body <- [%Triage.Cases.ReviewCase{}, %URI{}] do
        parsed = CaseFilters.parse_event(body)

        assert :filters in parsed.invalid
        assert parsed.owner == nil
        assert parsed.before_id == nil
      end

      for wrapper <- [%Triage.Cases.ReviewCase{}, %URI{}] do
        parsed = CaseFilters.parse_event(%{"filters" => wrapper})

        assert :filters in parsed.invalid
        assert parsed.owner == nil
        assert parsed.before_id == nil
      end
    end

    test "unrelated event metadata is ignored in flat events" do
      parsed =
        CaseFilters.parse_event(%{"owner" => "beta", "q" => <<0xFF>>, "suppressed" => "maybe"})

      assert parsed.owner == "beta"
      assert parsed.invalid == []
    end
  end

  describe "query_params/1" do
    test "drops nil All choices and emits only validated values" do
      assert CaseFilters.query_params(CaseFilters.parse(%{})) == %{}
      assert CaseFilters.query_params(CaseFilters.parse(%{"environment" => "  "})) == %{}
    end

    test "emits owner, environment and a stringified cursor" do
      qs = CaseFilters.query_params(CaseFilters.parse(%{"owner" => "alpha", "before" => "5"}))

      assert qs == %{owner: "alpha", before: "5"}
      assert is_binary(qs[:before])
    end

    test "invalid values resolve to nil and are never emitted" do
      parsed = CaseFilters.parse(%{"owner" => String.duplicate("a", 121), "before" => "x"})

      assert CaseFilters.query_params(parsed) == %{}
    end

    test "unvalidated scope values are never emitted" do
      assert CaseFilters.query_params(%{owner: <<255>>, environment: nil, before_id: 0}) == %{}

      assert CaseFilters.query_params(%{owner: 123, environment: :beta, before_id: "5"}) == %{}

      assert CaseFilters.query_params(%{
               owner: "  ",
               environment: String.duplicate("e", 121),
               before_id: nil
             }) == %{}

      assert CaseFilters.query_params(%{
               owner: "alpha" <> <<0xFF>>,
               environment: "\tbeta",
               before_id: nil
             }) == %{}
    end

    test "only a positive bigint cursor is emitted as a plain string" do
      for value <- [0, -1, 1.5, "5", true, nil, 9_223_372_036_854_775_808] do
        assert CaseFilters.query_params(%{owner: "alpha", environment: nil, before_id: value}) ==
                 %{owner: "alpha"}
      end

      assert CaseFilters.query_params(%{
               owner: "alpha",
               environment: "beta",
               before_id: 9_223_372_036_854_775_807
             }) == %{owner: "alpha", environment: "beta", before: "9223372036854775807"}

      assert CaseFilters.query_params(%{owner: "alpha", environment: nil, before_id: 1}) ==
               %{owner: "alpha", before: "1"}
    end

    test "valid scope values pass the value contract and are emitted trimmed" do
      assert CaseFilters.query_params(%{owner: " alpha ", environment: "beta", before_id: nil}) ==
               %{owner: "alpha", environment: "beta"}
    end

    test "the emit direction and FindingFilters' parse direction agree on one contract" do
      # Both directions call `FindingFilters.scope_value/1`, so a value the
      # emitter drops must be one the parser rejects, and a value it emits must
      # survive a round trip. This pins the agreement across the length
      # boundary and across every value class the contract refuses; a second
      # copy of the bound in either direction would fail one of these.
      candidates = [
        "alpha",
        " alpha ",
        "owner-with-dash_and.dot",
        "",
        "  ",
        String.duplicate("a", 120),
        String.duplicate("a", 121),
        String.duplicate("a", 500),
        "alpha" <> <<0xFF>>,
        <<255>>,
        "\tbeta",
        "beta\n"
      ]

      for value <- candidates do
        parsed = FindingFilters.parse(%{"owner" => value})
        emitted = CaseFilters.query_params(%{owner: value, environment: nil, before_id: nil})

        cond do
          :owner in parsed.invalid ->
            assert emitted == %{},
                   "expected #{inspect(value)} to be dropped, emitted #{inspect(emitted)}"

          parsed.owner == nil ->
            assert emitted == %{},
                   "expected blank #{inspect(value)} to emit nothing, emitted #{inspect(emitted)}"

          true ->
            assert emitted == %{owner: parsed.owner}
            assert FindingFilters.parse(%{"owner" => emitted.owner}) == parsed
        end
      end
    end
  end
end
