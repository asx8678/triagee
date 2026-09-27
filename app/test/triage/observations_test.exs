defmodule Triage.ObservationsTest do
  use Triage.DataCase, async: false

  alias Mix.Tasks.Triage.Collect
  alias Triage.Collection.Report
  alias Triage.CollectionFixture
  alias Triage.Evidence.Packet
  alias Triage.Inventory.{Finding, Image}
  alias Triage.Observations
  alias Triage.Observations.{Observation, Run}

  @fetched ~U[2026-09-25 12:00:00Z]
  @ingested ~U[2026-09-25 12:00:05Z]
  @source ~U[2026-09-25 11:00:00Z]
  @older ~U[2026-09-24 11:00:00Z]
  @sentinel_digest "sha256:observation-sentinel"
  @sentinel_seen ~U[2020-01-01 00:00:00Z]

  test "A14 fixture report ingestion persists fallback provenance and a bounded context row" do
    sentinel = sentinel!()
    before = inventory_counts()
    report = CollectionFixture.report!("authorized_positive")

    assert report.findings |> Enum.map(& &1.cve) == ["CVE-2024-3094"]
    assert {:ok, %{run: run, created?: true}} = ingest(report, source_observed_at: @source)
    assert {:ok, [row]} = Observations.pending_attention(limit: 1)

    assert run.identity_kind == "content_fallback"
    assert run.identity =~ ~r/^[0-9a-f]{64}$/
    assert run.content_hash == run.identity
    assert run.status_marker == "2026-09-03T12:00:00Z"
    assert run.source_observed_at == @source
    assert run.fetched_at == @fetched
    assert run.ingested_at == @ingested
    assert run.fetched_at != run.ingested_at
    assert run.paging_contract == "none"
    assert run.complete
    assert "paging_contract_absent" in run.blockers
    assert row.cve == "CVE-2024-3094"
    assert row.identity_kind == "content_fallback"
    assert row.source_observed_at == @source
    assert row.fetched_at == @fetched
    assert row.ingested_at == @ingested
    assert row.paging_contract == "none"
    assert row.complete
    assert inventory_counts() == before
    assert Repo.get!(Finding, sentinel.id).resolved_at == @sentinel_seen

    assert Packet.live_blockers() == [
             "register_provenance_unavailable",
             "scan_run_provenance_unavailable"
           ]

    packet = Packet.build(%{cve: row.cve, blockers: Packet.live_blockers()})
    assert "scan_run_provenance_unavailable" in packet.blockers
  end

  test "A14 source time stays nil when only an observational marker is present" do
    report = CollectionFixture.report!("authorized_positive")
    assert {:ok, %{run: run}} = ingest(report)

    assert run.status_marker == "2026-09-03T12:00:00Z"
    assert run.source_observed_at == nil
    assert {:ok, [row]} = Observations.pending_attention()
    assert row.source_observed_at == nil
  end

  test "A15 partial in-scope positive stays readable with blockers and does not resolve inventory" do
    sentinel = sentinel!()
    report = CollectionFixture.report!("partial")
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "detail missing"))

    assert {:ok, %{run: run}} = ingest(report)
    refute run.complete
    assert Enum.any?(run.blockers, &String.contains?(&1, "detail missing"))
    assert {:ok, [row]} = Observations.pending_attention()
    assert row.cve == "CVE-2024-3094"
    refute row.complete
    assert Enum.any?(row.blockers, &String.contains?(&1, "detail missing"))
    assert Repo.get!(Finding, sentinel.id).resolved_at == @sentinel_seen
  end

  test "A15 budget cutoff keeps the retained positive and does not infer the omitted finding" do
    report = CollectionFixture.report!("budget", max_records: 2)
    refute Report.complete?(report)
    assert Enum.map(report.findings, & &1.cve) == ["CVE-2024-3094"]

    assert {:ok, _} = ingest(report)
    assert {:ok, rows} = Observations.pending_attention()
    assert Enum.map(rows, & &1.cve) == ["CVE-2024-3094"]
    refute Enum.any?(rows, &(&1.cve == "CVE-2023-0001"))
  end

  test "A15 wrong-scope fixture rows are quarantined even if the payload says in scope" do
    report = CollectionFixture.report!("wrong_scope")
    forged = forge_in_scope(report, true)

    assert {:ok, %{run: run}} = ingest(forged)
    assert run.counts["quarantined"] == 1
    assert run.counts["eligible"] == 0
    assert "wrong_scope_quarantined" in run.blockers
    assert {:ok, []} = Observations.pending_attention()

    observation = Repo.one!(Observation)
    assert observation.quarantine
    refute observation.attention_eligible
    refute Repo.get_by(Image, digest: observation.digest)
  end

  test "A15 a payload cannot remove an in-contract owner from scope" do
    report = CollectionFixture.report!("authorized_positive")
    forged = forge_in_scope(report, false)

    assert {:ok, _} = ingest(forged)
    assert {:ok, [%{cve: "CVE-2024-3094"}]} = Observations.pending_attention()
  end

  test "A15 stale explicit source time does not move the current pointer" do
    assert {:ok, %{run: current}} =
             ingest(CollectionFixture.report!("authorized_positive"), source_observed_at: @source)

    assert {:ok, %{run: older, created?: true}} =
             ingest(CollectionFixture.report!("older_positive"), source_observed_at: @older)

    pointer = Repo.one!(Triage.Observations.Current)
    assert pointer.source_run_id == current.id
    assert pointer.source_observed_at == @source
    assert older.id != current.id
    assert {:ok, rows} = Observations.pending_attention()
    assert Enum.map(rows, & &1.cve) == ["CVE-2021-44228", "CVE-2024-3094"]
    assert Repo.get!(Run, current.id).fetched_at == @fetched
    assert Repo.get!(Run, older.id).source_observed_at == @older
  end

  test "A16 reordered fixture findings replay without rewriting times or duplicating attention" do
    report = CollectionFixture.report!("authorized_positive")
    assert {:ok, %{run: first, created?: true}} = ingest(report, source_observed_at: @source)

    reordered = %{
      report
      | findings: Enum.reverse(report.findings),
        images: Enum.reverse(report.images)
    }

    assert {:ok, %{run: second, created?: false}} =
             ingest(reordered,
               fetched_at: ~U[2026-09-26 00:00:00Z],
               ingested_at: ~U[2026-09-26 00:00:01Z]
             )

    assert second.id == first.id
    assert second.fetched_at == @fetched
    assert second.ingested_at == @ingested
    assert second.source_observed_at == @source
    assert Repo.aggregate(Run, :count) == 1
    assert Repo.aggregate(Observation, :count) == 1
    assert {:ok, [_one]} = Observations.pending_attention()
  end

  test "A16 duplicate finding identities collapse to one attention row" do
    report = CollectionFixture.report!("authorized_positive")
    duplicated = %{report | findings: report.findings ++ report.findings}

    assert {:ok, %{run: run}} = ingest(duplicated)
    assert "duplicate_findings_collapsed" in run.blockers
    assert Repo.aggregate(Observation, :count) == 1
    assert {:ok, [_one]} = Observations.pending_attention()
  end

  test "A16 shared-sandbox tasks converge on one run" do
    # These tasks share the test connection. This does not prove that two
    # independent transactions lock each other; the unique index is that
    # storage claim. The owned wrapper's concurrency mode runs only
    # import_concurrency_test.exs, so no second destructive probe is added.
    report = CollectionFixture.report!("authorized_positive")
    parent = self()

    tasks =
      for _ <- 1..4 do
        Task.async(fn ->
          send(parent, {:ready, self()})

          receive do
            :go -> ingest(report, source_observed_at: @source)
          end
        end)
      end

    Enum.each(tasks, fn task ->
      assert_receive {:ready, _pid}
      Ecto.Adapters.SQL.Sandbox.allow(Triage.Repo, self(), task.pid)
    end)

    Enum.each(tasks, fn task -> send(task.pid, :go) end)
    results = Task.await_many(tasks)

    assert Enum.all?(results, &match?({:ok, %{run: %Run{}}}, &1))
    assert Enum.count(results, fn {:ok, %{created?: created?}} -> created? end) == 1

    assert results |> Enum.map(fn {:ok, %{run: run}} -> run.id end) |> Enum.uniq() |> length() ==
             1

    assert Repo.aggregate(Observation, :count) == 1
  end

  test "A16 storage unique index rejects a second identity row" do
    assert {:ok, %{run: run}} = ingest(CollectionFixture.report!("authorized_positive"))

    assert Repo.query!(
             "SELECT indexname FROM pg_indexes WHERE indexname = 'source_runs_identity_index'"
           ).rows ==
             [["source_runs_identity_index"]]

    assert {:error, changeset} =
             %Run{}
             |> Run.changeset(%{
               source: run.source,
               scope_key: run.scope_key,
               identity_kind: run.identity_kind,
               identity: run.identity,
               status_marker: run.status_marker,
               fetched_at: run.fetched_at,
               ingested_at: run.ingested_at,
               paging_contract: run.paging_contract,
               complete: run.complete,
               blockers: run.blockers,
               counts: run.counts,
               content_hash: run.content_hash,
               query_version: run.query_version,
               environment: run.environment,
               engine: run.engine
             })
             |> Repo.insert()

    assert Enum.any?(changeset.errors, fn {_field, {_message, opts}} ->
             opts[:constraint] == :unique and
               opts[:constraint_name] == "source_runs_identity_index"
           end)
  end

  test "suppressed fixture findings are stored and are not attention eligible" do
    assert {:ok, %{run: run}} = ingest(CollectionFixture.report!("suppressed"))
    assert run.counts["suppressed"] == 1
    assert run.counts["eligible"] == 0
    assert {:ok, []} = Observations.pending_attention()
    refute Repo.one!(Observation).attention_eligible
  end

  test "an empty reconciled report does not resolve or invent findings" do
    sentinel = sentinel!()
    report = CollectionFixture.report!("authorized_positive")
    empty = %{report | findings: []}

    assert {:ok, %{run: run}} = ingest(empty)
    assert run.counts["findings"] == 0
    assert {:ok, []} = Observations.pending_attention()
    assert Repo.get!(Finding, sentinel.id).resolved_at == @sentinel_seen
  end

  test "malformed reports, clocks and self-authorized options write nothing" do
    report = CollectionFixture.report!("authorized_positive")
    before = Repo.aggregate(Run, :count)

    assert {:error, :invalid_report} = Observations.ingest(%{findings: []})
    assert {:error, :invalid_options} = ingest(report, verified_scan_id: "scan-1")
    assert {:error, :malformed_timestamp} = ingest(report, fetched_at: "2026-09-03T12:00:00Z")

    assert {:error, :malformed_timestamp} =
             ingest(report, source_observed_at: report.status_marker)

    assert {:error, :malformed_timestamp} =
             ingest(report, fetched_at: ~U[2026-09-25 12:00:00.123456Z])

    assert {:error, :malformed_timestamp} =
             ingest(report, fetched_at: ~U[2026-09-25 13:00:00Z], ingested_at: @ingested)

    assert {:error, :contract_mismatch} = ingest(%{report | environment: "prod"})

    assert {:error, :malformed_finding} =
             ingest(%{
               report
               | findings: [
                   %{
                     cve: nil,
                     digest: "sha256:aa",
                     package_name: "p",
                     package_version: "1",
                     suppressed: false
                   }
                 ]
             })

    conflicting = %{
      report
      | findings: [hd(report.findings), %{hd(report.findings) | severity: "LOW"}]
    }

    assert {:error, :conflicting_findings} = ingest(conflicting)

    assert {:error, :invalid_limit} = Observations.pending_attention(limit: 0)
    assert {:error, :invalid_limit} = Observations.pending_attention(limit: 101)
    assert {:error, :invalid_options} = Observations.pending_attention(owners: ["fixture-owner"])
    assert Repo.aggregate(Run, :count) == before
    assert Collect.execute([]) == {:error, :collection_disabled}
    assert Repo.aggregate(Run, :count) == before
  end

  test "a later partial, empty, or wrong-scope run does not hide an unresolved positive" do
    assert {:ok, %{run: first}} = ingest(CollectionFixture.report!("authorized_positive"))

    assert {:ok, _} = ingest(CollectionFixture.report!("partial_other"))

    assert {:ok, _} =
             ingest(%{
               CollectionFixture.report!("authorized_positive")
               | findings: [],
                 suppressed: []
             })

    assert {:ok, _} = ingest(CollectionFixture.report!("wrong_scope"))

    assert {:ok, rows} = Observations.pending_attention()
    assert Enum.map(rows, & &1.cve) == ["CVE-2021-44228", "CVE-2024-3094"]
    assert Repo.get!(Run, first.id).fetched_at == @fetched
    assert Repo.get_by!(Observation, source_run_id: first.id).severity == "HIGH"
  end

  test "a later nil-time positive is visible without moving the nil-time pointer" do
    assert {:ok, %{run: first}} = ingest(CollectionFixture.report!("authorized_positive"))

    assert {:ok, %{run: second, created?: true}} =
             ingest(CollectionFixture.report!("older_positive"))

    pointer = Repo.one!(Triage.Observations.Current)
    assert pointer.source_run_id == first.id
    assert pointer.source_observed_at == nil
    assert {:ok, rows} = Observations.pending_attention()
    assert Enum.map(rows, & &1.cve) == ["CVE-2021-44228", "CVE-2024-3094"]
    assert Enum.any?(rows, &(&1.source_run_id == second.id))
  end

  test "the same positive in a later coverage run is visible once and the first receipt stays immutable" do
    assert {:ok, %{run: partial}} = ingest(CollectionFixture.report!("partial"))

    assert {:ok, %{run: complete, created?: true}} =
             ingest(CollectionFixture.report!("authorized_positive"))

    refute partial.complete
    assert complete.complete
    assert partial.identity != complete.identity
    assert Repo.get!(Run, partial.id).fetched_at == @fetched
    assert Repo.get!(Run, partial.id).blockers == partial.blockers
    assert {:ok, [row]} = Observations.pending_attention()
    assert row.cve == "CVE-2024-3094"
    assert Repo.aggregate(Observation, :count) == 2
  end

  test "severity escalation is a new receipt and attention keeps the higher severity" do
    assert {:ok, %{run: first}} = ingest(CollectionFixture.report!("authorized_positive"))
    escalated = escalate(CollectionFixture.report!("authorized_positive"), "CRITICAL")
    lowered = escalate(CollectionFixture.report!("authorized_positive"), "LOW")

    assert {:ok, %{run: second, created?: true}} = ingest(escalated, source_observed_at: @older)
    assert {:ok, %{created?: true}} = ingest(lowered)
    assert first.identity != second.identity
    assert Repo.get_by!(Observation, source_run_id: first.id).severity == "HIGH"
    assert Repo.get!(Run, first.id).fetched_at == @fetched
    assert {:ok, [row]} = Observations.pending_attention()
    assert row.severity == "CRITICAL"
    assert row.source_run_id == second.id
  end

  defp ingest(report, overrides \\ []) do
    opts =
      Keyword.merge(
        [fetched_at: @fetched, ingested_at: @ingested],
        overrides
      )

    Observations.ingest(report, opts)
  end

  defp escalate(report, severity) do
    %{report | findings: Enum.map(report.findings, &%{&1 | severity: severity})}
  end

  defp forge_in_scope(report, flag) do
    images =
      Enum.map(report.images, fn image ->
        placements = Enum.map(image.placements, &Map.put(&1, :in_scope, flag))
        %{image | placements: placements}
      end)

    %{report | images: images}
  end

  defp sentinel! do
    image =
      Repo.insert!(%Image{
        digest: @sentinel_digest,
        repository: "sentinel"
      })

    Repo.insert!(%Finding{
      image_id: image.id,
      cve: "CVE-SENTINEL",
      package_name: "sentinel",
      package_version: "1",
      severity: "LOW",
      first_seen: @sentinel_seen,
      last_seen: @sentinel_seen,
      resolved_at: @sentinel_seen
    })
  end

  defp inventory_counts do
    Map.new(
      ~w(images findings image_placements advisory_decisions review_cases),
      fn table ->
        {table, Repo.query!("SELECT count(*) FROM #{table}").rows |> hd() |> hd()}
      end
    )
  end
end
