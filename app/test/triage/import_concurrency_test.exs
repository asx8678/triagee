defmodule Triage.ImportConcurrencyTest do
  @moduledoc """
  Real separate-connection regression for concurrent imports.

  The other `Triage.Import` tests run inside the Ecto SQL sandbox, where two
  tasks share a single owner connection. A transaction-scoped advisory lock is
  re-entrant within one session, so that setup cannot prove serialization. This
  module requires an exact owned-empty-database opt-in before switching to
  `:auto` for its serial tests and committing for real. Ordinary runs skip it.
  Both imports must wait on separate PostgreSQL sessions behind a held advisory
  lock, then converge on success with exactly one row. Cleanup truncates only
  the explicitly opted-in, initially empty partition.
  """

  use ExUnit.Case, async: false

  alias Triage.{Import, Repo}
  alias Triage.Inventory.{Finding, FindingEvent, Image}

  import Ecto.Query

  # Destructive real-commit tests are never part of an ordinary shared-DB run.
  # Opt in only on a freshly created, verifier-owned empty partition, using its
  # exact database name (not a boolean). Setup independently verifies the target
  # and refuses preexisting rows BEFORE changing sandbox mode or truncating.
  @owned_db System.get_env("TRIAGE_IMPORT_CONCURRENCY_DB")
  if is_nil(@owned_db), do: @moduletag(skip: "requires an owned empty DB opt-in")

  @table_names ~w(images findings finding_events image_placements review_case_events review_reviews review_evidence_snapshots review_cases)
  @tables Enum.join(@table_names, ", ")
  @digest "sha256:" <> String.duplicate("b", 64)
  @seen ~U[2026-09-01 00:00:00Z]

  setup do
    assert_owned_database!()

    Ecto.Adapters.SQL.Sandbox.unboxed_run(Repo, fn ->
      assert_current_database!()

      for table <- @table_names do
        unless Repo.query!("SELECT EXISTS (SELECT 1 FROM #{table})").rows == [[false]] do
          raise "concurrency tests refuse a database with preexisting rows"
        end
      end
    end)

    :ok = Ecto.Adapters.SQL.Sandbox.mode(Repo, :auto)

    on_exit(fn ->
      try do
        truncate!()
      after
        :ok = Ecto.Adapters.SQL.Sandbox.mode(Repo, :manual)
      end
    end)

    :ok
  end

  # The module tag above is decided when this file is compiled, because a skip
  # has to be. The assertions below read the same opt-in at run time instead:
  # that is the value that matters when the connection is actually switched, and
  # reading it here also stops the type checker from folding a compile-time
  # literal into a conjunction it can prove is always false.
  defp owned_db, do: System.get_env("TRIAGE_IMPORT_CONCURRENCY_DB")

  defp assert_owned_database! do
    configured = Repo.config()[:database]
    owned = owned_db()

    unless Mix.env() == :test and is_binary(owned) and
             String.starts_with?(owned, "triage_test_") and
             configured == owned and
             configured == "triage_test#{System.get_env("MIX_TEST_PARTITION")}" do
      raise "concurrency tests require an exact owned test database opt-in"
    end
  end

  defp assert_current_database! do
    unless Repo.query!("SELECT current_database()").rows == [[owned_db()]] do
      raise "concurrency test connection database mismatch"
    end
  end

  defp truncate! do
    assert_owned_database!()
    assert_current_database!()
    Repo.query!("TRUNCATE TABLE #{@tables} CASCADE")
  end

  test "concurrent identical imports do not duplicate a lifecycle event" do
    # Baseline: the image, placement and finding exist with no events.
    assert {:ok, _} = Import.apply(snapshot([]))

    results =
      run_concurrently(snapshot([event(~U[2026-09-02 00:00:00Z])]), ~s(FROM "finding_events"))

    assert Enum.all?(results, &match?({:ok, _}, &1)), inspect(results)

    finding = Repo.get_by!(Finding, cve: "CVE-RACE-1")

    count =
      Repo.aggregate(from(e in FindingEvent, where: e.finding_id == ^finding.id), :count)

    assert count == 1
  end

  test "concurrent imports of an absent image converge on success with one row" do
    results = run_concurrently(snapshot([]), ~s(FROM "images"))

    assert Enum.all?(results, &match?({:ok, _}, &1)), inspect(results)
    assert Repo.aggregate(Image, :count) == 1
  end

  defp run_concurrently(snapshot, _needle) do
    supervisor = start_supervised!(Task.Supervisor)

    # Hold the production lock on a third connection, so neither importer can
    # win simply because the scheduler happened to run it to completion first.
    {:ok, tasks} =
      Repo.transaction(fn ->
        Repo.query!("SELECT pg_advisory_xact_lock($1)", [7_433_921_021_337])

        tasks =
          for _ <- 1..2 do
            Task.Supervisor.async_nolink(supervisor, fn -> Import.apply(snapshot) end)
          end

        await_lock_waiters!(System.monotonic_time(:millisecond) + 5_000)
        tasks
      end)

    Enum.map(tasks, &Task.await(&1, 15_000))
  end

  defp await_lock_waiters!(deadline) do
    %{rows: [[waiting]]} =
      Repo.query!(
        """
        SELECT count(DISTINCT pid) FROM pg_locks
        WHERE locktype = 'advisory' AND NOT granted
          AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
          AND classid = ($1::bigint >> 32)::oid
          AND objid = ($1::bigint & 4294967295)::oid
        """,
        [7_433_921_021_337]
      )

    cond do
      waiting == 2 -> :ok
      System.monotonic_time(:millisecond) < deadline -> await_lock_waiters!(deadline)
      true -> flunk("expected two distinct PostgreSQL import lock waiters, got #{waiting}")
    end
  end

  defp snapshot(events) do
    %{
      format: "triage.snapshot",
      version: 1,
      source: "race",
      generated_at: ~U[2026-09-09 00:00:00Z],
      images: [
        %{
          digest: @digest,
          repository: "race/app",
          tag: "1.0",
          description: nil,
          placements: [
            %{
              namespace: "web",
              owner: "team-race",
              environment: "prod",
              active: true,
              first_seen: @seen,
              last_seen: @seen
            }
          ],
          findings: [
            %{
              cve: "CVE-RACE-1",
              package_name: "busybox",
              package_version: "1.0",
              severity: "HIGH",
              fix: nil,
              url: nil,
              description: nil,
              suppressed: false,
              first_seen: @seen,
              last_seen: @seen,
              resolved_at: nil,
              events: events
            }
          ]
        }
      ]
    }
  end

  defp event(occurred_at) do
    %{event: "appeared", occurred_at: occurred_at, note: nil}
  end
end
