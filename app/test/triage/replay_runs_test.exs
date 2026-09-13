defmodule Triage.Replay.RunsTest do
  use Triage.DataCase, async: false
  alias Triage.Replay.{Run, Runs}

  @empty ~s({"format":"triage.replay","version":1,"origin":"synthetic","environment":"test","engine":"trivy","owners":[],"inventories":[],"details":[]})
  @ttl 30 * 24 * 60 * 60

  setup do
    Repo.delete_all(Run)
    :ok
  end

  test "recomputes, stores only safe summary and hashed key, retry is immutable" do
    key = "potential-secret"
    assert {:ok, row} = Runs.record_result(key, @empty)
    assert {:ok, summary} = Triage.Replay.run(@empty)
    assert row.summary == summary
    assert row.key_hash == Base.encode16(:crypto.hash(:sha256, key), case: :lower)
    refute Jason.encode!(row.summary) =~ key
    assert row.outcome == "complete"
    assert DateTime.diff(row.expires_at, row.received_at) == @ttl
    assert {:ok, same} = Runs.record_result(key, " \n" <> @empty)
    assert same == row
    assert {:ok, ^row} = Runs.get(key)
    assert Repo.aggregate(Run, :count) == 1
  end

  test "different canonical input conflicts; incomplete is a persisted result" do
    assert {:ok, _} = Runs.record_result("key", @empty)
    other = @empty |> Jason.decode!() |> Map.put("environment", "staging") |> Jason.encode!()
    assert {:error, :idempotency_conflict} = Runs.record_result("key", other)
    incomplete = @empty |> Jason.decode!() |> Map.put("owners", ["team-a"]) |> Jason.encode!()
    assert {:ok, row} = Runs.record_result("incomplete", incomplete)
    assert row.outcome == "incomplete"
    assert row.summary["complete"] == false
    assert row.summary["historical_provenance"] == false
  end

  test "malformed input and keys do not reach SQL, arbitrary reports rejected" do
    handler = "replay-invalid-#{System.unique_integer([:positive])}"
    parent = self()

    :telemetry.attach(
      handler,
      [:triage, :repo, :query],
      fn _, _, _, _ -> send(parent, :sql) end,
      nil
    )

    try do
      assert {:error, :invalid_key} = Runs.record_result("", @empty)
      assert {:error, :invalid_key} = Runs.record_result(String.duplicate("x", 129), @empty)
      assert {:error, :invalid_key} = Runs.record_result(<<255>>, @empty)
      assert {:error, _} = Runs.record_result("key", "{")
      assert {:error, _} = Runs.record_result("key", %{"complete" => true})
      refute_received :sql
    after
      :telemetry.detach(handler)
    end

    assert Repo.aggregate(Run, :count) == 0
  end

  test "expired rows are hidden, consume quota, and require explicit purge" do
    assert {:ok, sample} = Runs.record_result("template", @empty)
    Repo.delete_all(Run)
    past = DateTime.add(DateTime.utc_now(), -@ttl - 60, :second)
    expired = attrs(sample, "expired", past)
    Repo.insert_all(Run, [expired])
    assert {:ok, nil} = Runs.get("expired")
    assert {:ok, []} = Runs.list()
    assert {:error, :expired} = Runs.record_result("expired", @empty)
    rows = for n <- 1..999, do: attrs(sample, "quota-#{n}", past)
    Repo.insert_all(Run, rows)
    assert {:error, :quota_exceeded} = Runs.record_result("new", @empty)
    assert Repo.aggregate(Run, :count) == 1000
    assert {:ok, 1000} = Runs.purge_expired!()
    assert {:ok, _} = Runs.record_result("new", @empty)
  end

  test "dedup works at quota; cursor pagination is bounded" do
    assert {:ok, sample} = Runs.record_result("template", @empty)
    now = DateTime.utc_now()
    Repo.insert_all(Run, for(n <- 1..999, do: attrs(sample, "quota-#{n}", now)))
    assert {:ok, ^sample} = Runs.record_result("template", @empty)
    assert {:error, :quota_exceeded} = Runs.record_result("overflow", @empty)
    assert {:ok, first} = Runs.list(limit: 100)
    assert length(first) == 100
    cursor = List.last(first).id
    assert {:ok, next} = Runs.list(limit: 100, after_id: cursor)
    assert length(next) == 100
    assert Enum.all?(next, &(&1.id > cursor))
    assert {:error, :invalid_pagination} = Runs.list(limit: 101)
    assert {:error, :invalid_pagination} = Runs.list(after_id: -1)
  end

  test "database rejects all updates without poisoning surrounding transaction" do
    assert {:ok, row} = Runs.record_result("key", @empty)

    assert {:error, %Postgrex.Error{}} =
             Repo.query(
               "UPDATE replay_runs SET expires_at = expires_at WHERE id = $1",
               [row.id],
               mode: :savepoint,
               log: false
             )

    assert {:ok, ^row} = Runs.get("key")
  end

  test "database constraints reject malformed hash, outcome, expiry and oversized JSON" do
    assert {:ok, row} = Runs.record_result("constraint-template", @empty)

    sql = """
    INSERT INTO replay_runs (key_hash, input_sha256, summary, outcome, received_at, expires_at)
    SELECT $1, input_sha256, summary, outcome, received_at, expires_at
    FROM replay_runs WHERE id = $2
    """

    assert {:error, %Postgrex.Error{}} =
             Repo.query(sql, ["bad", row.id], mode: :savepoint, log: false)

    for replacement <- ["'other'", "outcome"] do
      expiry = if replacement == "outcome", do: "received_at", else: "expires_at"

      assert {:error, %Postgrex.Error{}} =
               Repo.query(
                 """
                 INSERT INTO replay_runs (key_hash, input_sha256, summary, outcome, received_at, expires_at)
                 SELECT repeat('b', 64), input_sha256, summary, #{replacement}, received_at, #{expiry}
                 FROM replay_runs WHERE id = $1
                 """,
                 [row.id],
                 mode: :savepoint,
                 log: false
               )
    end

    assert {:error, %Postgrex.Error{}} =
             Repo.query(
               """
               INSERT INTO replay_runs (key_hash, input_sha256, summary, outcome, received_at, expires_at)
               SELECT repeat('c', 64), input_sha256,
                 summary || jsonb_build_object('padding', repeat('x', 65536)),
                 outcome, received_at, expires_at FROM replay_runs WHERE id = $1
               """,
               [row.id],
               mode: :savepoint,
               log: false
             )
  end

  test "outer rollback removes receipt and inventory is untouched" do
    before = inventory()

    assert {:error, :probe_rollback} =
             Repo.transaction(fn ->
               assert {:ok, _} = Runs.record_result("rolled-back", @empty)
               Repo.rollback(:probe_rollback)
             end)

    assert {:ok, nil} = Runs.get("rolled-back")
    assert {:ok, _} = Runs.record_result("kept", @empty)
    assert inventory() == before
  end

  defp attrs(sample, key, received_at) do
    %{
      key_hash: Base.encode16(:crypto.hash(:sha256, key), case: :lower),
      input_sha256: sample.input_sha256,
      summary: sample.summary,
      outcome: sample.outcome,
      received_at: received_at,
      expires_at: DateTime.add(received_at, @ttl, :second)
    }
  end

  defp inventory do
    for table <- ~w(images image_placements findings finding_events), into: %{} do
      {table, Repo.query!("SELECT to_jsonb(t) FROM #{table} t ORDER BY id", [], log: false).rows}
    end
  end
end
