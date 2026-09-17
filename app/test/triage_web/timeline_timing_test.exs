defmodule TriageWeb.TimelineTimingTest do
  use TriageWeb.ConnCase, async: true
  import Phoenix.LiveViewTest
  alias TriageWeb.TimelineLive.Lanes
  @first ~U[2026-01-01 06:00:00Z]
  @action ~U[2026-01-03 06:00:00Z]

  defp render_lane(attrs) do
    lane =
      Map.merge(
        %{
          cve: "CVE-TEST",
          severity: "HIGH",
          first_seen: @first,
          resolved_at: nil,
          occurrence_count: 2,
          open_count: 2,
          resolved_count: 0,
          suppressed_count: 0,
          reopen_count: 0,
          observed_dates: [~D[2026-01-01]],
          judged_count: 0,
          state: :open,
          decisions: []
        },
        attrs
      )

    render_component(&Lanes.lane_table/1,
      lanes: %{total: 1, rows: [lane], truncated_count: 0},
      filters: TriageWeb.TimelineFilters.defaults()
    )
    |> LazyHTML.from_document()
  end

  defp cell(doc, n), do: doc |> LazyHTML.query("tbody tr > :nth-child(#{n})") |> LazyHTML.text()

  defp decision(attrs \\ %{}),
    do:
      Map.merge(
        %Triage.Decisions.Decision{
          id: 1,
          supersedes_id: nil,
          decision: "accepted_risk",
          decided_at: @action,
          expires_at: ~U[2099-01-01 00:00:00Z],
          placement_id: nil
        },
        attrs
      )

  test "fix date and duration use disappearance while retaining earlier whitelist history" do
    doc =
      render_lane(%{
        state: :no_longer_observed,
        resolved_at: @action,
        open_count: 0,
        resolved_count: 2,
        decisions: [decision()]
      })

    assert cell(doc, 3) =~ "03 Jan 2026"
    assert cell(doc, 4) =~ "2 days 0 h"
    assert cell(doc, 5) =~ "Fixed"
    assert cell(doc, 5) =~ "recorded disappearance"
    assert cell(doc, 6) =~ "Accepted risk"
  end

  test "whitelist response is distinct from waiting, expired and placement-only decisions" do
    doc = render_lane(%{decisions: [decision()]})
    assert cell(doc, 5) =~ "Whitelisted"
    assert cell(doc, 4) =~ "Time to whitelist"
    assert cell(doc, 4) =~ "2 days 0 h"
    doc = render_lane(%{decisions: [decision(%{placement_id: 123})]})
    assert cell(doc, 5) =~ "Partially whitelisted"
    doc = render_lane(%{decisions: [decision(%{expires_at: @action})]})
    assert cell(doc, 5) =~ "Awaiting action"
    assert cell(doc, 5) =~ "Whitelist expired"
    assert cell(doc, 4) =~ "Waiting since detection"
  end

  test "scanner whitelist never invents a date and partial coverage stays visible" do
    doc = render_lane(%{suppressed_count: 1})
    assert cell(doc, 5) =~ "Partially whitelisted"
    assert cell(doc, 3) =~ "Date unknown"
    assert cell(doc, 4) =~ "Unknown"
    doc = render_lane(%{suppressed_count: 2})
    assert cell(doc, 5) =~ "Whitelisted"
    refute cell(doc, 5) =~ "Partially"
  end

  test "reopened CVEs wait and invalid chronology stays unknown" do
    doc = render_lane(%{reopen_count: 1})
    assert cell(doc, 5) =~ "Awaiting action"
    assert cell(doc, 5) =~ "Detected again"
    doc = render_lane(%{first_seen: nil, decisions: [decision()]})
    assert cell(doc, 4) =~ "Unknown"
    doc = render_lane(%{first_seen: ~U[2026-01-04 00:00:00Z], decisions: [decision()]})
    assert cell(doc, 4) =~ "Unknown"
  end
end
