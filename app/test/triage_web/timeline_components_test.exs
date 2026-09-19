defmodule TriageWeb.TimelineComponentsTest do
  use ExUnit.Case, async: true
  import Phoenix.LiveViewTest
  alias Triage.Timeline.Days
  alias TriageWeb.TimelineFilters
  alias TriageWeb.TimelineLive.{Bands, Drawer}
  @endpoint TriageWeb.Endpoint

  test "multiple same-day events retain unique rows and actions" do
    finding = %{
      id: 42,
      cve: "CVE-2026-1234",
      severity: "HIGH",
      package_name: "demo",
      package_version: "1",
      fix: nil,
      suppressed: false,
      resolved_at: nil,
      reopen_count: 0
    }

    rows =
      for {id, kind} <- [{101, "appeared"}, {102, "resolved"}] do
        {%{id: id, event: kind, occurred_at: ~U[2026-09-15 10:00:00Z], note: nil}, finding,
         %{repository: "demo", tag: "1"}}
      end

    days = Days.build(%{from: ~D[2026-09-15], to: ~D[2026-09-15]}, rows, %{})

    document =
      render_component(&Bands.waterfall/1, %{days: days, filters: TimelineFilters.defaults()})
      |> LazyHTML.from_fragment()

    ids = document |> LazyHTML.query("[id]") |> LazyHTML.attribute("id")
    assert length(ids) == length(Enum.uniq(ids))

    for id <- [101, 102], prefix <- ~w(tl-row tl-open tl-advisory) do
      assert Enum.count(LazyHTML.query(document, "##{prefix}-#{id}")) == 1
    end
  end

  test "drawer pagination preserves scope and clearly links truncated previews to full records" do
    filters =
      TimelineFilters.parse(%{
        "owner" => "alpha",
        "environment" => "prod",
        "weeks" => "4",
        "cve" => "CVE-2026-1234",
        "cases_after" => "9"
      })

    page = %{total: 2, shown: 1, cursor: nil, has_more?: true, next_after: 101}

    detail = %{
      lane: %{
        severity: "HIGH",
        package_name: "demo",
        package_version: "1",
        fix: nil,
        occurrence_count: 1,
        open_count: 1,
        resolved_count: 0,
        window_observed_count: 1,
        observed_day_count: 73,
        first_seen: ~U[2026-09-15 10:00:00Z],
        last_seen: ~U[2026-09-15 10:00:00Z],
        resolved_at: nil,
        suppressed_count: 0,
        reopen_count: 0,
        url: nil
      },
      events: [
        %{
          id: 101,
          kind: "appeared",
          occurred_at: ~U[2026-09-15 10:00:00Z],
          note: nil,
          in_window?: true
        }
      ],
      event_page: page,
      cases:
        Map.merge(page, %{
          cursor: 9,
          next_after: 10,
          truncated_count: 1,
          rows: [
            %{
              id: 10,
              case: %{owner: "alpha", environment: "prod", revision: 30},
              entries: [],
              history_truncated?: true
            }
          ]
        })
    }

    document =
      render_component(&Drawer.cve_drawer/1, %{
        detail: detail,
        filters: filters,
        selected_cve: filters.cve
      })
      |> LazyHTML.from_fragment()

    assert query_params(document, "#tl-events-next") == %{
             "owner" => "alpha",
             "environment" => "prod",
             "weeks" => "4",
             "cve" => "CVE-2026-1234",
             "events_after" => "101",
             "cases_after" => "9"
           }

    refute Map.has_key?(query_params(document, "#tl-cases-first"), "cases_after")
    assert query_params(document, "#tl-cases-next")["cases_after"] == "10"
    closed = query_params(document, "#tl-drawer-close")
    refute Map.has_key?(closed, "cve")
    refute Map.has_key?(closed, "cases_after")
    assert Enum.count(LazyHTML.query(document, "#tl-case-truncated-10")) == 1

    assert LazyHTML.attribute(LazyHTML.query(document, "#tl-case-open-10"), "phx-click") == [
             "timeline-case"
           ]

    assert LazyHTML.attribute(LazyHTML.query(document, "#tl-case-open-10"), "phx-value-id") == [
             "10"
           ]

    assert LazyHTML.text(LazyHTML.query(document, "#tl-drawer-lane")) =~ "73 recorded day(s)"
  end

  defp query_params(document, selector) do
    [href] = document |> LazyHTML.query(selector) |> LazyHTML.attribute("href")
    href |> URI.parse() |> Map.fetch!(:query) |> Plug.Conn.Query.decode()
  end
end
