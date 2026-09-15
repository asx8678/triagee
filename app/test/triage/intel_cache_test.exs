defmodule Triage.IntelCacheTest do
  use Triage.DataCase, async: false

  alias Triage.Intel

  test "disabled by default and KEV URL is HTTPS allowlisted" do
    refute Intel.Config.enabled?()
    assert Intel.safe_link?("https://example.com/notice")
    refute Intel.safe_link?("http://example.com/notice")
    refute Intel.safe_link?("data:text/html,<script>")
  end

  test "the canonical NVD source key is what the writer and the reader both use" do
    assert Intel.nvd_source("CVE-2024-3094") == "nvd:CVE-2024-3094"
    # Case and surrounding whitespace are normalized, so a refresh typed however the
    # operator spells it cannot land under a source the reader never looks up.
    assert Intel.nvd_source("  cve-2024-3094 ") == "nvd:CVE-2024-3094"

    {:ok, _} =
      Intel.replace_advisories(Intel.nvd_source("cve-2024-3094"), [
        %{
          external_id: "CVE-2024-3094",
          summary: "nvd row",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    assert [row] = Intel.cached_nvd("CVE-2024-3094")
    assert row.source == "nvd:CVE-2024-3094"
    assert Intel.cached_nvd("cve-2024-3094") != []

    # A differently cased source is a different source: this is exactly the mismatch
    # the CLI's failure path used to record against.
    assert Intel.cached_advisories("nvd:cve-2024-3094") == []
  end

  test "cached news are read without any network effect" do
    {:ok, _} =
      Intel.replace_news("synthetic", [
        %{
          item_id: "t1",
          title: "A",
          summary: "s",
          link: "https://x",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    rows = Intel.list_cached_news()
    assert length(rows) == 1
    assert hd(rows).title == "A"
  end

  test "replace_advisories replaces cache for a source only" do
    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{external_id: "CVE-1", summary: "first", published_at: ~U[2026-09-12 10:00:00Z]}
      ])

    assert length(Intel.cached_advisories("CVE-1")) == 1

    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{external_id: "CVE-2", summary: "second", published_at: ~U[2026-09-12 10:00:00Z]}
      ])

    assert Intel.cached_advisories("CVE-1") == []
    assert length(Intel.cached_advisories("CVE-2")) == 1
  end

  test "list_cached_news is bounded" do
    {:ok, _} =
      Intel.replace_news("synthetic", [
        %{item_id: "n1", title: "1", published_at: ~U[2026-09-12 10:00:00Z]},
        %{item_id: "n2", title: "2", published_at: ~U[2026-09-12 10:01:00Z]},
        %{item_id: "n3", title: "3", published_at: ~U[2026-09-12 10:02:00Z]}
      ])

    assert length(Intel.list_cached_news(2)) == 2
  end

  test "source row counts are independent of CVE matches and refresh receipt counts" do
    assert Intel.cached_advisory_count("kev") == 0

    {:ok, 2} =
      Intel.replace_advisories("kev", [
        %{external_id: "CVE-2026-2001"},
        %{external_id: "CVE-2026-2002"}
      ])

    {:ok, 1} = Intel.replace_advisories("nvd:CVE-2026-2001", [%{external_id: "CVE-2026-2001"}])
    {:ok, _} = Intel.record_receipt("kev", true, 99)
    {:ok, _} = Intel.record_receipt("kev", false, nil, "failed refresh")

    assert Intel.cached_advisory_count("kev") == 2
    assert Intel.cached_advisory_count("nvd:CVE-2026-2001") == 1
    assert Intel.cached_kev("CVE-2026-9999") == []
    {:ok, 0} = Intel.replace_advisories("kev", [])
    assert Intel.cached_advisory_count("kev") == 0
  end

  test "a rejected feed never reaches replacement and preserves the last good cache" do
    {:ok, 1} = Intel.replace_advisories("kev", [%{external_id: "CVE-2026-2001"}])
    before = Intel.cached_kev("CVE-2026-2001")
    transport = %{req: fn _ -> {:ok, ~s({"vulnerabilities":[{}]})} end}

    result =
      with {:ok, rows} <- Intel.Client.fetch(:kev, transport),
           do: Intel.replace_advisories("kev", rows)

    assert result == {:error, :kev_parse_failed}
    assert Intel.cached_kev("CVE-2026-2001") == before
  end

  test "latest_receipts returns the newest per source" do
    {:ok, _} = Intel.record_receipt("kev", true, 5)
    {:ok, _} = Intel.record_receipt("kev", false, nil, "later failure")
    {:ok, _} = Intel.record_receipt("nvd:x", true, 2)

    receipts = Intel.latest_receipts()
    by_source = Map.new(receipts, &{&1.source, &1})

    assert by_source["kev"].succeeded == false
    assert by_source["kev"].message == "later failure"
    assert by_source["nvd:x"].succeeded == true
  end

  test "KEV rows are found by CVE, because the source is not part of the external id" do
    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2024-3094",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    # `mix triage.intel --kev` writes source "kev" with the bare CVE as
    # external_id. A reader that looks up "kev:CVE-…" as an external id returns
    # nothing forever, so pin the writer/reader agreement here.
    assert [row] = Intel.cached_kev("CVE-2024-3094")
    assert row.source == "kev"
    assert row.external_id == "CVE-2024-3094"
    assert Intel.cached_kev("CVE-2024-9999") == []
    assert Intel.cached_nvd("CVE-2024-3094") == []

    # The defect this replaced: the advisory detail looked the row up as
    # external id "kev:CVE-…", which can never match a written row.
    assert Intel.cached_advisories("kev:CVE-2024-3094") == []
  end

  test "KEV actionability survives the cache round-trip" do
    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2026-2001",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z],
          required_action: "Apply updates per vendor instructions.",
          due_date: ~U[2026-01-23 00:00:00Z],
          known_ransomware: true
        }
      ])

    assert [row] = Intel.cached_kev("CVE-2026-2001")
    assert row.required_action == "Apply updates per vendor instructions."
    assert row.due_date == ~U[2026-01-23 00:00:00Z]
    assert row.known_ransomware == true

    # A row written without the action fields (an NVD row, or one cached before the
    # columns existed) reads back as nil, which the panel shows as absent.
    {:ok, _} =
      Intel.replace_advisories("nvd:CVE-2026-2001", [
        %{external_id: "CVE-2026-2001", summary: "nvd entry", published_at: nil}
      ])

    assert [nvd] = Intel.cached_nvd("CVE-2026-2001")
    assert nvd.required_action == nil
    assert nvd.due_date == nil
    assert nvd.known_ransomware == nil
  end

  test "kev_index batches one read, deduplicates, and keys only cached rows" do
    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2026-6001",
          summary: "cached row",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    index = Intel.kev_index(["CVE-2026-6001", "CVE-2026-6001", nil, "", "CVE-2026-6002"])

    assert Map.keys(index) == ["CVE-2026-6001"]
    assert index["CVE-2026-6001"].external_id == "CVE-2026-6001"

    # A missing row is a missing key: the caller renders no marker, never a claim
    # that the advisory is unexploited.
    assert Map.get(index, "CVE-2026-6002") == nil

    # An empty input and an empty cache both read as "nothing cached".
    assert Intel.kev_index([]) == %{}
    assert Intel.kev_index(:not_a_list) == %{}

    {:ok, _} = Intel.replace_advisories("kev", [])
    assert Intel.kev_index(["CVE-2026-6001"]) == %{}
  end

  test "NVD rows are found by their per-CVE source key" do
    {:ok, _} =
      Intel.replace_advisories("nvd:CVE-2024-3094", [
        %{
          external_id: "CVE-2024-3094",
          summary: "nvd entry",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    # The CLI uppercases the CVE into the source key, so lookups must be
    # case-insensitive and must not read another source's rows.
    assert [row] = Intel.cached_nvd("cve-2024-3094")
    assert row.source == "nvd:CVE-2024-3094"
    assert Intel.cached_nvd("CVE-2024-0000") == []
    assert Intel.cached_kev("CVE-2024-3094") == []
  end

  test "sanitize never renders hostile text as markup-safe input" do
    assert Triage.Intel.Sanitize.text("<script>alert(1)</script>\x00") ==
             "<script>alert(1)</script>"

    assert Triage.Intel.Sanitize.title("OK\n\tTitle\u0000") == "OK Title"

    assert Triage.Intel.Sanitize.valid_cve_id?("CVE-2024-3094")
    refute Triage.Intel.Sanitize.valid_cve_id?("CVE-2024-3094\n")
    refute Triage.Intel.Sanitize.valid_cve_id?("no")
  end
end
