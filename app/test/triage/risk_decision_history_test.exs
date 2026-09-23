defmodule Triage.RiskDecisionHistoryTest do
  use ExUnit.Case, async: true
  alias Triage.RiskDecisionHistory, as: History
  @now ~U[2026-09-23 12:00:00Z]

  test "one explicit operation groups placements without losing exact records" do
    rows = [record(1), record(2, %{placement_id: 22})]
    view = History.build(rows, %{}, @now)
    assert view.total == 1
    assert view.records == 2
    assert [%{id: 1, scopes: scopes, records: ^rows}] = view.rows
    assert Enum.map(scopes, & &1.placement_id) == [1, 22]
  end

  test "separate operations, approval facts and missing operation IDs never merge" do
    rows = [
      record(1),
      record(2, %{operation_id: "another"}),
      record(3, %{reason: "Another reason"}),
      record(4, %{actor: "Another reviewer"}),
      record(5, %{operation_id: nil}),
      record(6, %{operation_id: nil}),
      record(7, %{cve: "CVE-2099-7778"})
    ]

    assert History.build(rows, %{}, @now).total == 7
  end

  test "expiry honors exact inclusive/exclusive boundaries and no-limit legacy records" do
    exclusive = record(1, %{expires_at: @now})
    inclusive = record(2, %{expires_at: @now, metadata: %{"expiry_boundary" => "inclusive"}})
    soon = record(3, %{expires_at: DateTime.add(@now, 7, :day)})
    unlimited = record(4, %{expires_at: nil, placement_id: nil})
    old = record(5, %{expires_at: DateTime.add(@now, -2, :day)})
    view = History.build([exclusive, inclusive, soon, unlimited, old], %{}, @now)
    assert view.counts == %{"all" => 5, "valid" => 3, "expiring" => 2, "expired" => 2}
    assert Enum.find(view.rows, &(&1.id == 4)).legacy?
    assert Enum.find(view.rows, &(&1.id == 4)).status == "unlimited"
    assert Enum.find(view.rows, &(&1.id == 1)).status == "expired"
    assert Enum.find(view.rows, &(&1.id == 2)).status == "expiring"
  end

  test "filters are case insensitive for search and exact for historical scope" do
    a = record(1)
    b = record(2, %{metadata: %{"target" => %{"team" => "beta", "environment" => "dev"}}})

    view =
      History.build(
        [a, b],
        %{"risk_q" => "PATCH", "risk_team" => "alpha", "risk_environment" => "prod"},
        @now
      )

    assert view.records == 1
    assert [%{records: [^a]}] = view.rows
    assert view.teams == ["alpha", "beta"]
    assert History.build([a, b], %{"risk_team" => "unknown"}, @now).rows == []
    assert History.build([a, b], %{"risk_status" => "invalid"}, @now).rows == []
  end

  test "pagination is bounded, stable and filters reset an out-of-range page" do
    records = Enum.map(1..25, &record(&1, %{operation_id: nil}))
    assert %{page: 1, pages: 3, rows: first} = History.build(records, %{}, @now)
    assert length(first) == 12
    assert hd(first).id == 25
    assert %{page: 3, rows: [_]} = History.build(records, %{"risk_page" => "999999"}, @now)
    assert %{page: 1} = History.build(records, %{"risk_page" => "-1"}, @now)

    assert %{page: 1, rows: []} =
             History.build(records, %{"risk_q" => "no match", "risk_page" => "2"}, @now)
  end

  test "superseded approvals remain historical records rather than current coverage claims" do
    old = record(1, %{operation_id: nil, expires_at: DateTime.add(@now, -5, :day)})
    new = record(2, %{operation_id: nil, supersedes_id: 1})
    view = History.build([old, new], %{}, @now)
    assert view.total == 2
    assert Enum.find(view.rows, &(&1.id == 1)).status == "expired"
    assert [%{supersedes_id: 1}] = Enum.find(view.rows, &(&1.id == 2)).scopes
  end

  defp record(id, changes \\ %{}) do
    Map.merge(
      %{
        id: id,
        cve: "CVE-2099-7777",
        decision: "accepted_risk",
        actor: "Reviewer",
        reason: "Scheduled patch window",
        operation_id: "operation-1",
        placement_id: id,
        decided_at: DateTime.add(@now, -5, :day),
        expires_at: DateTime.add(@now, 30, :day),
        supersedes_id: nil,
        metadata: %{
          "expiry_boundary" => "exclusive",
          "target" => %{"team" => "alpha", "environment" => "prod", "namespace" => "payments"}
        }
      },
      changes
    )
  end
end
