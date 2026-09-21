defmodule TriageWeb.TimelineLaneTimingTest do
  use TriageWeb.LegacyUICase, async: true
  import Phoenix.LiveViewTest
  alias TriageWeb.TimelineLive.Lanes
  @first ~U[2026-01-01 00:00:00Z]

  defp lane(attrs) do
    Map.merge(
      %{
        cve: "CVE-TEST",
        severity: "HIGH",
        first_seen: @first,
        resolved_at: nil,
        state: :open,
        occurrence_count: 2,
        open_count: 2,
        resolved_count: 0,
        suppressed_count: 0,
        reopen_count: 0,
        observed_dates: [],
        judged_count: 0,
        decisions: []
      },
      attrs
    )
  end

  defp render_lane(row) do
    render_component(&Lanes.lane_table/1,
      lanes: %{total: 1, rows: [row], truncated_count: 0},
      filters: TriageWeb.TimelineFilters.defaults()
    )
  end

  defp decision(attrs \\ %{}) do
    Map.merge(
      %Triage.Decisions.Decision{
        id: 1,
        cve: "CVE-TEST",
        decision: "not_affected",
        decided_at: DateTime.add(@first, 2 * 86_400)
      },
      attrs
    )
  end

  test "fixed proxy shows both dates and duration, retaining whitelist history" do
    html =
      render_lane(
        lane(%{
          state: :no_longer_observed,
          open_count: 0,
          resolved_count: 2,
          resolved_at: DateTime.add(@first, 5 * 86_400),
          decisions: [decision()]
        })
      )

    assert html =~ "Fixed"
    assert html =~ "not a verified repair"
    assert html =~ "2026-01-01T00:00:00Z"
    assert html =~ "2026-01-06T00:00:00Z"
    assert html =~ "5 days 0 h"
    assert html =~ "2 days 0 h"
    assert html =~ "Not affected"
  end

  test "operator and scanner whitelist use one vocabulary without invented dates" do
    html = render_lane(lane(%{decisions: [decision()]}))
    assert html =~ "Whitelisted"
    assert html =~ "Time to whitelist"
    assert html =~ "2 days 0 h"
    html = render_lane(lane(%{suppressed_count: 2}))
    assert html =~ "Whitelisted"
    assert html =~ "Via scanner"
    assert html =~ "Date unknown"
    assert html =~ "Whitelist date unknown"
    assert render_lane(lane(%{suppressed_count: 1})) =~ "Partially whitelisted"

    assert render_lane(lane(%{decisions: [decision(%{placement_id: 42})]})) =~
             "Partially whitelisted"
  end

  test "expired and future decisions do not stop waiting; reopened and unknown timing remain explicit" do
    expired = decision(%{expires_at: ~U[2026-01-04 00:00:00Z]})
    html = render_lane(lane(%{decisions: [expired]}))
    assert html =~ "Awaiting action"
    assert html =~ "Whitelist expired"
    assert html =~ "Waiting since detection"
    future = decision(%{decided_at: ~U[2099-01-01 00:00:00Z]})
    html = render_lane(lane(%{decisions: [future], reopen_count: 1}))
    assert html =~ "Awaiting action"
    assert html =~ "Detected again"
    assert html =~ "Scheduled"
    assert render_lane(lane(%{first_seen: nil})) =~ "Unknown"
    assert render_lane(lane(%{first_seen: ~U[2099-01-01 00:00:00Z]})) =~ "Unknown"
  end
end
