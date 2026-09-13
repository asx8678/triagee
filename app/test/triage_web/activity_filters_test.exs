defmodule TriageWeb.ActivityFiltersTest do
  @moduledoc """
  Parameter-contract tests for the What's New feed. `TriageWeb.ActivityFilters`
  delegates to `TriageWeb.CaseFilters`, so these tests pin the shared contract
  at this entry point rather than re-testing it abstractly.
  """

  use ExUnit.Case, async: true

  alias TriageWeb.ActivityFilters

  test "defaults are the intentional All/newest state with no invalid fields" do
    assert ActivityFilters.defaults() == %{
             owner: nil,
             environment: nil,
             before_id: nil,
             invalid: []
           }
  end

  test "absent and blank scope mean All; unrelated metadata is ignored" do
    parsed = ActivityFilters.parse(%{"owner" => "", "environment" => "", "q" => "ignored"})

    assert parsed.owner == nil
    assert parsed.environment == nil
    assert parsed.before_id == nil
    assert parsed.invalid == []
  end

  test "scope values are trimmed and the cursor parses to a positive bigint" do
    parsed = ActivityFilters.parse(%{"owner" => "  alpha  ", "before" => "42"})

    assert parsed.owner == "alpha"
    assert parsed.before_id == 42
    assert parsed.invalid == []
  end

  test "the reserved filters wrapper is invalid in URL parsing" do
    parsed = ActivityFilters.parse(%{"filters" => %{"owner" => "alpha"}})

    assert parsed.owner == nil
    assert :filters in parsed.invalid
  end

  test "every malformed cursor shape is rejected visibly" do
    for value <- ["0", "-1", "1.5", "abc", " 7", "9_223_372_036_854_775_808", "+", [], %{}] do
      parsed = ActivityFilters.parse(%{"before" => value})
      assert :before in parsed.invalid, "expected #{inspect(value)} to be rejected"
    end

    # int8 max is exactly acceptable.
    assert ActivityFilters.parse(%{"before" => "9223372036854775807"}).invalid == []
  end

  test "unsafe scope text is rejected instead of coerced" do
    assert :owner in ActivityFilters.parse(%{"owner" => "a\u0000b"}).invalid
    assert :owner in ActivityFilters.parse(%{"owner" => String.duplicate("a", 121)}).invalid

    invalid_utf8 = <<0xFF, 0xFE>>
    assert :owner in ActivityFilters.parse(%{"owner" => invalid_utf8}).invalid
  end

  test "one plain wrapper event is unwrapped and validated" do
    parsed =
      ActivityFilters.parse_event(%{"filters" => %{"owner" => "alpha"}, "_target" => ["owner"]})

    assert parsed.owner == "alpha"
    assert parsed.invalid == []
  end

  test "struct bodies, including an outer struct carrying filters, are rejected" do
    wrapped = ActivityFilters.parse_event(Map.put(%URI{}, "filters", %{"owner" => "alpha"}))
    assert wrapped.owner == nil
    assert :filters in wrapped.invalid

    flat_struct = ActivityFilters.parse_event(%URI{})
    assert flat_struct.owner == nil
    assert :filters in flat_struct.invalid
  end

  test "ambiguous wrapper plus a real flat cursor value is rejected" do
    parsed = ActivityFilters.parse_event(%{"filters" => %{"owner" => "alpha"}, "before" => "5"})

    assert :filters in parsed.invalid
  end

  test "non-map event bodies surface the invalid state instead of raising" do
    for body <- [nil, 1, "x", [], %URI{}] do
      assert :filters in ActivityFilters.parse_event(body).invalid
    end
  end

  test "query_params emits only validated non-nil values" do
    assert ActivityFilters.query_params(%{owner: "alpha", environment: nil, before_id: 7}) ==
             %{owner: "alpha", before: "7"}

    assert ActivityFilters.query_params(%{owner: nil, environment: nil, before_id: nil}) == %{}

    assert ActivityFilters.query_params(%{owner: "a\u0000b", environment: nil, before_id: 0}) ==
             %{}

    assert ActivityFilters.query_params(:nonsense) == %{}
  end
end
