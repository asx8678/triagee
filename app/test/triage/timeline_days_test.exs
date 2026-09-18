defmodule Triage.TimelineDaysTest do
  use ExUnit.Case, async: true
  alias Triage.Timeline.Days

  @date ~D[2026-09-15]
  @at ~U[2026-09-15 10:00:00Z]

  test "all loaded events contribute to counts before the 25-row display cap" do
    kinds = List.duplicate("appeared", 26) ++ ["resolved", "resolved", "reopened"]
    rows = kinds |> Enum.with_index(1) |> Enum.map(fn {kind, id} -> row(id, kind, @at) end)
    assert [day] = Days.build(%{from: @date, to: @date}, rows, %{@date => 37})
    assert day.event_count == 29
    assert {day.new_count, day.resolved_count, day.reopened_count} == {26, 2, 1}
    assert length(day.rows) == Days.row_limit()
    assert day.truncated_count == 4
    assert day.judged_count == 37
  end

  test "one finding retains distinct identities for multiple same-day events" do
    [day] =
      Days.build(
        %{from: @date, to: @date},
        [row(101, "appeared", @at), row(102, "resolved", @at)],
        %{}
      )

    assert Enum.map(day.rows, & &1.event_id) == [101, 102]
    assert Enum.map(day.rows, & &1.finding_id) == [42, 42]
  end

  test "connectors and empty judged days preserve their separate meanings" do
    previous = Date.add(@date, -1)
    tomorrow = Date.add(@date, 1)

    [empty, today, yesterday] =
      Days.build(
        %{from: previous, to: tomorrow},
        [row(2, "reopened", @at), row(1, "appeared", DateTime.add(@at, -86_400))],
        %{tomorrow => 2}
      )

    refute empty.observed?
    assert empty.judged_count == 2
    assert empty.rows == []
    assert hd(today.rows).continues?
    refute hd(today.rows).continued_from?
    assert hd(yesterday.rows).continued_from?
    refute hd(yesterday.rows).continues?
  end

  defp row(id, kind, at) do
    {%{id: id, event: kind, occurred_at: at, note: nil},
     %{
       id: 42,
       cve: "CVE-2026-1234",
       severity: "HIGH",
       package_name: "demo",
       package_version: "1",
       fix: nil,
       suppressed: false,
       resolved_at: nil,
       reopen_count: 0
     }, %{repository: "demo", tag: "1"}}
  end
end
