defmodule Triage.IntelGenerationTest do
  @moduledoc """
  Immutable intelligence generations (W01b, A01–A03).

  A refresh that cannot be verified never becomes current, citable history
  survives, and an older attempt finishing later cannot displace a newer valid
  generation. Legacy pre-generation rows stay readable until a generation
  exists, and are never retroactively certified as complete.
  """
  use Triage.DataCase, async: false

  import Triage.Fixtures

  alias Triage.{Intel, Workspace}
  alias Triage.Intel.Client

  defp kev_entries(range) do
    for n <- range do
      %{
        "cveID" => "CVE-2026-#{1000 + n}",
        "shortDescription" => "advisory #{n}",
        "dateAdded" => "2026-01-02"
      }
    end
  end

  defp fetch_kev(entries, declared \\ nil) do
    body = %{
      "vulnerabilities" => entries,
      "count" => if(is_nil(declared), do: length(entries), else: declared),
      "catalogVersion" => "2026.09.12",
      "dateReleased" => "2026-09-12T00:00:00.000Z",
      "title" => "CISA KEV"
    }

    Client.fetch_generation(:kev, %{req: fn _url -> {:ok, Jason.encode!(body)} end})
  end

  defp commit_kev!(entries, opts \\ []) do
    {:ok, parsed} = fetch_kev(entries)

    {:ok, result} =
      Intel.commit_generation("kev", parsed.rows,
        declared_count: parsed.declared_count,
        complete: parsed.complete?,
        catalog_version: parsed.catalog_version,
        metadata: parsed.metadata,
        started_at: Keyword.get(opts, :started_at),
        receipt: Keyword.get(opts, :receipt, true)
      )

    result
  end

  test "A01: the 51st and 80th KEV entries reach the cache and escalate Risk" do
    cve = "CVE-2026-1080"
    image = image!("kev-80")
    placement!(image, "alpha", "prod")
    finding!(image, cve, severity: "HIGH")

    {:ok, parsed} = fetch_kev(kev_entries(1..80))
    assert parsed.complete?
    assert parsed.declared_count == 80
    assert length(parsed.rows) == 80

    # Generation and success receipt are written together; UI limits never
    # truncate the stored set.
    assert {:ok, %{generation: generation, current?: true}} =
             Intel.commit_generation("kev", parsed.rows,
               declared_count: parsed.declared_count,
               complete: parsed.complete?,
               catalog_version: parsed.catalog_version,
               metadata: parsed.metadata,
               receipt: true
             )

    assert generation.row_count == 80
    assert generation.complete
    assert Intel.cached_advisory_count("kev") == 80

    receipt = Enum.find(Intel.latest_receipts(), &(&1.source == "kev"))
    assert receipt.succeeded
    assert receipt.item_count == 80

    for n <- [51, 80] do
      entry_cve = "CVE-2026-#{1000 + n}"
      assert [row] = Intel.cached_kev(entry_cve)
      assert row.external_id == entry_cve
      assert Map.has_key?(Intel.kev_index([entry_cve]), entry_cve)
    end

    # The end of the feed is not display-only: it escalates review priority
    # through the same cache read the workspace uses.
    assert [target] = Workspace.targets(%{"cve" => cve})
    assert target.risk.priority == "critical"
    assert Enum.any?(target.risk.reasons, &String.contains?(&1, "Actively exploited (KEV)"))
  end

  test "A02: an unverifiable catalogue never becomes current and writes no success receipt" do
    first = commit_kev!(kev_entries(1..3))
    assert first.current?
    assert Intel.cached_advisory_count("kev") == 3
    history = Intel.generation_history("kev")

    # Declared count disagreeing with the feed: refused before any write.
    assert {:error, :kev_declared_count_mismatch} = fetch_kev(kev_entries(1..3), 100)

    # No declared count at all: unverifiable, so refused.
    body = Jason.encode!(%{"vulnerabilities" => kev_entries(1..3)})

    assert {:error, :kev_declared_count_missing} =
             Client.fetch_generation(:kev, %{req: fn _ -> {:ok, body} end})

    # A suspicious empty catalogue: refused as unverified.
    assert {:error, :kev_empty_feed} = fetch_kev([])

    # The failure path records a receipt and leaves the current generation and
    # its history untouched.
    {:ok, _} =
      Intel.record_receipt("kev", false, nil, "KEV declared count does not match the feed")

    assert Intel.cached_advisory_count("kev") == 3
    assert Intel.current_generation("kev").id == first.generation.id
    assert Intel.generation_history("kev") == history
    assert Enum.find(Intel.latest_receipts(), &(&1.source == "kev")).succeeded == false

    # A row set that could never be read back is refused without partial writes.
    assert {:error, :invalid_rows} = Intel.commit_generation("kev", [%{summary: "no identity"}])
    assert Intel.cached_advisory_count("kev") == 3
  end

  test "A03: an older attempt completing later cannot displace a newer generation" do
    older = DateTime.utc_now() |> DateTime.add(-600, :second) |> DateTime.truncate(:second)
    newer = DateTime.utc_now() |> DateTime.truncate(:second)

    # The newer attempt commits first...
    newer_result = commit_kev!(kev_entries(1..2), started_at: newer)
    assert newer_result.current?
    assert Intel.current_generation("kev").id == newer_result.generation.id

    # ...then the older attempt finishes with a valid, different payload.
    older_result = commit_kev!(kev_entries(10..12), started_at: older)
    refute older_result.current?

    # History keeps both; the current pointer never moves backwards.
    assert Intel.current_generation("kev").id == newer_result.generation.id
    assert Intel.cached_advisory_count("kev") == 2
    assert [_, _] = Intel.generation_history("kev")
    assert length(Intel.generation_rows("kev", older_result.generation.id)) == 3
    assert length(Intel.generation_rows("kev", newer_result.generation.id)) == 2

    # Re-reading after a restart reads the same durable pointer.
    assert Intel.kev_status().generation.id == newer_result.generation.id
    assert Intel.kev_status().rows == 2

    # The superseded attempt is still recorded honestly.
    receipt = Enum.find(Intel.latest_receipts(), &(&1.source == "kev"))
    assert receipt.succeeded
    assert receipt.message =~ "stored as history"
  end

  test "legacy pre-generation rows stay readable until a generation exists" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.insert!(%Triage.Intel.Advisory{
      source: "kev",
      external_id: "CVE-2026-9001",
      summary: "pre-generation row",
      fetched_at: now,
      generation_id: nil
    })

    assert [row] = Intel.cached_kev("CVE-2026-9001")
    assert row.generation_id == nil
    assert Intel.cached_advisory_count("kev") == 1

    # Legacy rows are readable, but the status must never call them certified.
    assert Intel.kev_status().generation == nil

    # Once a generation commits, only that generation serves reads; the legacy
    # row is not mixed in and never becomes "certified" retroactively.
    result = commit_kev!(kev_entries(1..2))
    assert result.current?
    assert Intel.cached_kev("CVE-2026-9001") == []
    assert Intel.cached_advisory_count("kev") == 2
    assert Intel.kev_status().generation.complete
    assert Intel.generation_rows("kev", result.generation.id) |> length() == 2
  end
end
