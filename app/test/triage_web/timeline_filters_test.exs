defmodule TriageWeb.TimelineFiltersTest do
  use ExUnit.Case, async: true
  alias Triage.Timeline
  alias TriageWeb.TimelineFilters, as: Filters

  test "history cursors round-trip as positive bigint ids with scope and selection" do
    params = %{
      "owner" => "alpha",
      "environment" => "prod",
      "weeks" => "4",
      "cve" => "CVE-2026-1234",
      "events_after" => "9223372036854775807",
      "cases_after" => "9"
    }

    filters = Filters.parse(params)
    assert filters.invalid == []
    assert filters.events_after == 9_223_372_036_854_775_807
    assert filters.cases_after == 9

    assert Filters.query_params(filters) == %{
             owner: "alpha",
             environment: "prod",
             weeks: "4",
             cve: "CVE-2026-1234",
             events_after: "9223372036854775807",
             cases_after: "9"
           }
  end

  test "malformed and out-of-range cursors cannot silently widen a history read" do
    for field <- ~w(events_after cases_after),
        bad <- [
          0,
          true,
          [],
          %{},
          "0",
          "-1",
          "1.5",
          " 1",
          "1\n",
          <<255>>,
          "9223372036854775808",
          String.duplicate("1", 1000)
        ] do
      parsed = Filters.parse(%{"cve" => "CVE-2026-1234", field => bad})
      assert String.to_existing_atom(field) in parsed.invalid
    end

    assert :cve in Filters.parse(%{"events_after" => "1"}).invalid
    assert Filters.query_params(%{Filters.defaults() | events_after: 1}) == %{}
  end

  test "paging preserves scope and the independent cursor; explicit selection resets both" do
    filters =
      Filters.parse(%{
        "owner" => "alpha",
        "environment" => "prod",
        "weeks" => "4",
        "cve" => "CVE-2026-1234",
        "events_after" => "7",
        "cases_after" => "9"
      })

    next = params(Filters.path(filters, %{events_after: 8}))

    assert next == %{
             "owner" => "alpha",
             "environment" => "prod",
             "weeks" => "4",
             "cve" => "CVE-2026-1234",
             "events_after" => "8",
             "cases_after" => "9"
           }

    for extra <- [%{cve: "CVE-2026-5678"}, %{cve: filters.cve}, %{owner: "beta"}, %{weeks: 8}] do
      reset = params(Filters.path(filters, extra))
      refute Map.has_key?(reset, "events_after")
      refute Map.has_key?(reset, "cases_after")
    end

    closed = params(Filters.path(filters, %{cve: nil}))
    assert closed == %{"owner" => "alpha", "environment" => "prod", "weeks" => "4"}
    assert params(Filters.path(filters, %{events_after: nil}))["cases_after"] == "9"
  end

  test "cursor-bearing flat fields are not neutral beside a nested filters wrapper" do
    for key <- ~w(events_after cases_after) do
      assert Filters.parse_event(%{"filters" => %{"owner" => "alpha"}, key => "1"}).invalid == [
               :filters
             ]

      assert Filters.parse_event(%{"filters" => %{"owner" => "alpha"}, key => ""}).owner ==
               "alpha"
    end
  end

  test "domain validation rejects invalid cursors and malformed detail options before SQL" do
    for key <- [:events_after, :cases_after],
        value <- [0, -1, "1", false, 1.0, 9_223_372_036_854_775_808] do
      assert Timeline.cve_detail("CVE-2026-1234", [{key, value}]) == {:error, :invalid_cursor}
    end

    for invalid <- [nil, %{}, [1], "options"] do
      assert Timeline.cve_detail("CVE-2026-1234", invalid) == {:error, :invalid_request}
    end

    assert Timeline.list_timeline(events_after: 1) == {:error, :invalid_request}
    assert Timeline.list_timeline(cases_after: nil) == {:error, :invalid_request}
  end

  defp params(path), do: path |> URI.parse() |> Map.fetch!(:query) |> Plug.Conn.Query.decode()
end
