defmodule TriageWeb.FindingFiltersTest do
  @moduledoc """
  Unit regressions for the shared scalar filter-validation contract used by
  the list and detail LiveViews and their filter events.
  """

  use ExUnit.Case, async: true

  alias TriageWeb.FindingFilters

  describe "parse/1" do
    test "absent or space-only blank fields are the intentional All choice" do
      assert FindingFilters.parse(%{}) ==
               %{
                 owner: nil,
                 environment: nil,
                 q: nil,
                 severity: nil,
                 include_suppressed: false,
                 sort: nil,
                 page: nil,
                 invalid: []
               }

      assert FindingFilters.parse(%{
               "owner" => "  ",
               "environment" => "",
               "q" => "   ",
               "severity" => "  ",
               "sort" => " ",
               "page" => ""
             }) ==
               %{
                 owner: nil,
                 environment: nil,
                 q: nil,
                 severity: nil,
                 include_suppressed: false,
                 sort: nil,
                 page: nil,
                 invalid: []
               }
    end

    test "raw control characters are rejected before trimming, even edge-only values" do
      # "\talpha" would trim into a real team name; control-only and
      # edge-control values must never become a scope or the All choice.
      for value <- ["\talpha", "alpha\n", "\ralpha", " \t ", "\t", "\n", "\u0000", "\u007F"] do
        parsed = FindingFilters.parse(%{"owner" => value, "environment" => value, "q" => value})

        assert :owner in parsed.invalid
        assert :environment in parsed.invalid
        assert :q in parsed.invalid
        assert parsed.owner == nil
      end

      # the suppressed field validates its raw binary too, not the trimmed one
      for value <- ["1\n", "\t1", "\t", "1\u0000"] do
        assert :suppressed in FindingFilters.parse(%{"suppressed" => value}).invalid
      end
    end

    test "invalid UTF-8 binaries are rejected before trimming, never coerced" do
      parsed = FindingFilters.parse(%{"owner" => "alpha" <> <<0xFF>>, "q" => <<0x80>>})

      assert :owner in parsed.invalid
      assert :q in parsed.invalid
      assert parsed.owner == nil
    end

    test "valid trimmed scalars are kept" do
      parsed =
        FindingFilters.parse(%{
          "owner" => " alpha ",
          "environment" => "prod-cluster-1",
          "q" => "busybox",
          "suppressed" => "on"
        })

      assert parsed.owner == "alpha"
      assert parsed.environment == "prod-cluster-1"
      assert parsed.q == "busybox"
      assert parsed.include_suppressed
      assert parsed.invalid == []
    end

    test "nonbinary values are rejected, never coerced with to_string" do
      for value <- [%{"0" => "alpha"}, ["alpha"], 123, :alpha] do
        parsed = FindingFilters.parse(%{"owner" => value})

        assert :owner in parsed.invalid
        assert parsed.owner == nil
      end
    end

    test "NUL and other control characters are rejected before database use" do
      for value <- ["al\u0000pha", "alpha\u0000", "al\u007fpha", "al\u0001pha"] do
        parsed = FindingFilters.parse(%{"owner" => value, "q" => value})

        assert :owner in parsed.invalid
        assert :q in parsed.invalid
      end
    end

    test "values longer than 120 characters are rejected, not truncated" do
      parsed = FindingFilters.parse(%{"owner" => String.duplicate("a", 121)})

      assert :owner in parsed.invalid
      assert parsed.owner == nil

      assert FindingFilters.parse(%{"owner" => String.duplicate("a", 120)}).owner ==
               String.duplicate("a", 120)
    end

    test "genuinely unrelated query/form metadata is ignored" do
      parsed =
        FindingFilters.parse(%{"_target" => ["owner"], "page" => "2", "sort" => "cve"})

      assert parsed.invalid == []
    end

    test "suppressed accepts the real checkbox values and rejects unknown ones" do
      assert FindingFilters.parse(%{"suppressed" => "1"}).include_suppressed
      assert FindingFilters.parse(%{"suppressed" => "true"}).include_suppressed
      assert FindingFilters.parse(%{"suppressed" => "on"}).include_suppressed
      assert FindingFilters.parse(%{"suppressed" => "false"}).include_suppressed == false
      assert FindingFilters.parse(%{"suppressed" => ""}).include_suppressed == false

      assert :suppressed in FindingFilters.parse(%{"suppressed" => "maybe"}).invalid
      assert :suppressed in FindingFilters.parse(%{"suppressed" => ["on"]}).invalid
    end
  end

  describe "parse_event/1" do
    test "flat form params parse like URL params" do
      parsed =
        FindingFilters.parse_event(%{
          "owner" => "beta",
          "environment" => "",
          "q" => "curl",
          "suppressed" => "false",
          "_target" => ["owner"]
        })

      assert parsed.owner == "beta"
      assert parsed.q == "curl"
      assert parsed.include_suppressed == false
      assert parsed.invalid == []
    end

    test "a nested filters wrapper is validated explicitly" do
      parsed = FindingFilters.parse_event(%{"filters" => %{"owner" => "beta", "q" => "curl"}})

      assert parsed.owner == "beta"
      assert parsed.q == "curl"
      assert parsed.invalid == []
    end

    test "a non-map filters wrapper is rejected instead of falling back" do
      parsed = FindingFilters.parse_event(%{"filters" => "not-a-map"})

      assert :filters in parsed.invalid
    end

    test "map-valued fields inside the wrapper are invalid" do
      parsed = FindingFilters.parse_event(%{"filters" => %{"owner" => %{"x" => "prod"}}})

      assert :owner in parsed.invalid
    end

    test "a doubly nested filters wrapper is rejected, never unwrapped to All" do
      parsed = FindingFilters.parse_event(%{"filters" => %{"filters" => %{"owner" => ["alpha"]}}})

      assert :filters in parsed.invalid
      assert parsed.owner == nil
      assert parsed.include_suppressed == false
    end

    test "a wrapper mixed with flat recognized fields carrying real values is rejected as ambiguous" do
      parsed = FindingFilters.parse_event(%{"filters" => %{"owner" => "beta"}, "q" => "curl"})

      assert :filters in parsed.invalid
      assert parsed.owner == nil
    end

    test "a wrapper alongside the form's serialized blank fields still parses" do
      # The real filter form serializes its own fields with the event: empty
      # selects/inputs and the unchecked checkbox are neutral and must not
      # make the legitimate wrapper ambiguous.
      parsed =
        FindingFilters.parse_event(%{
          "owner" => "",
          "environment" => "",
          "q" => "",
          "suppressed" => "false",
          "filters" => %{"owner" => "beta", "q" => "curl", "suppressed" => "on"},
          "_target" => ["filters"]
        })

      assert parsed.owner == "beta"
      assert parsed.q == "curl"
      assert parsed.include_suppressed
      assert parsed.invalid == []
    end

    test "a wrapper carrying only unrelated form metadata still parses" do
      parsed =
        FindingFilters.parse_event(%{"filters" => %{"owner" => "beta"}, "_target" => ["filters"]})

      assert parsed.owner == "beta"
      assert parsed.invalid == []
    end

    test "a reserved filters key in URL params is rejected, not treated as metadata" do
      parsed = FindingFilters.parse(%{"filters" => "x", "owner" => "beta"})

      assert :filters in parsed.invalid
      assert parsed.owner == nil
    end

    test "non-map event bodies are total: invalid state, no crash" do
      for body <- [123, nil, [], true, "not-a-map", :atom] do
        parsed = FindingFilters.parse_event(body)

        assert :filters in parsed.invalid
        assert parsed.owner == nil
      end
    end

    test "parse is total for non-map terms" do
      for body <- [123, nil, [], true] do
        assert :filters in FindingFilters.parse(body).invalid
      end
    end
  end

  describe "query_params/1" do
    test "drops blank All choices and encodes suppressed as 1" do
      assert FindingFilters.query_params(FindingFilters.parse(%{})) == %{}

      assert FindingFilters.query_params(FindingFilters.parse(%{"suppressed" => "true"})) ==
               %{suppressed: "1"}

      assert FindingFilters.query_params(
               FindingFilters.parse(%{"owner" => "alpha", "q" => "busybox"})
             ) == %{owner: "alpha", q: "busybox"}
    end

    test "carries the result order and page only when they were requested" do
      assert FindingFilters.query_params(
               FindingFilters.parse(%{"owner" => "alpha", "sort" => "cve", "page" => "2"})
             ) == %{owner: "alpha", sort: "cve", page: 2}
    end
  end

  describe "sort and page" do
    test "accepts only the published sort names, normalized" do
      for sort <- ~w(severity newest occurrences cve) do
        assert FindingFilters.parse(%{"sort" => sort}).sort == sort
      end

      assert FindingFilters.parse(%{"sort" => "  NEWEST  "}).sort == "newest"
      assert FindingFilters.parse(%{"sort" => ""}).sort == nil
    end

    test "an unknown or unsafe sort is an invalid filter, never a silent default" do
      for bad <- ["nonsense", "severity desc", "1; drop table findings", "sort\u0000"] do
        parsed = FindingFilters.parse(%{"sort" => bad})
        assert :sort in parsed.invalid
        assert parsed.sort == nil
      end

      assert :sort in FindingFilters.parse(%{"sort" => <<0xFF>>}).invalid
      assert :sort in FindingFilters.parse(%{"sort" => ["cve"]}).invalid
      assert :sort in FindingFilters.parse(%{"sort" => 1}).invalid
    end

    test "the accepted orders are the inventory's published orders, not a copy" do
      assert FindingFilters.sorts() == Triage.Inventory.group_sorts()

      for sort <- FindingFilters.sorts() do
        assert FindingFilters.parse(%{"sort" => sort}).invalid == []
      end

      assert FindingFilters.parse(%{"sort" => "shortlist"}).invalid == [:sort]
    end

    test "page numbers are bounded positive integers" do
      assert FindingFilters.parse(%{"page" => "3"}).page == 3
      assert FindingFilters.parse(%{"page" => " 3 "}).page == 3
      assert FindingFilters.parse(%{"page" => ""}).page == nil
    end

    test "an out-of-range, fractional or unsafe page is an invalid filter" do
      for bad <- ["0", "-1", "2.5", "1e3", "abc", "10001", "3\u0000", "0x10"] do
        assert :page in FindingFilters.parse(%{"page" => bad}).invalid
      end

      assert :page in FindingFilters.parse(%{"page" => <<0xFF>>}).invalid
      assert :page in FindingFilters.parse(%{"page" => 2}).invalid
    end

    test "a wrapper event carrying a real sort or page value is ambiguous" do
      assert :filters in FindingFilters.parse_event(%{"filters" => %{}, "sort" => "cve"}).invalid
      assert :filters in FindingFilters.parse_event(%{"filters" => %{}, "page" => "2"}).invalid
      assert FindingFilters.parse_event(%{"filters" => %{"sort" => "cve"}}).sort == "cve"
    end

    test "a real form's default order control does not make its wrapper event ambiguous" do
      # The shipped form serializes its order select on every event, so the
      # neutral default must unwrap; a non-default value there is a real conflict.
      unwrapped =
        FindingFilters.parse_event(%{"filters" => %{"owner" => "beta"}, "sort" => "severity"})

      assert unwrapped.owner == "beta"
      assert unwrapped.invalid == []

      assert :filters in FindingFilters.parse_event(%{
               "filters" => %{"owner" => "beta"},
               "sort" => "newest",
               "page" => "2"
             }).invalid
    end
  end
end
