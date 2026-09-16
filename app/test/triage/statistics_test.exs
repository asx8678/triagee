defmodule Triage.StatisticsTest do
  @moduledoc """
  Per-advisory timing rollup tests: grouping by advisory with the highest
  severity, whole-day durations for open and cleared advisories, local review
  target comparison by severity, reopened history flags, environment
  aggregation from placements, and the summary headline counts.
  """

  use Triage.DataCase, async: false

  alias Triage.Inventory.{Finding, Image, ImagePlacement}
  alias Triage.Repo
  alias Triage.Statistics

  @now ~U[2026-09-20 06:00:00Z]

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  defp image!(seed) do
    Repo.insert!(%Image{
      digest: "sha256:" <> String.duplicate(seed, 64),
      repository: "registry.internal/" <> seed,
      tag: "1.0"
    })
  end

  defp finding!(image, opts) do
    Repo.insert!(%Finding{
      image_id: image.id,
      cve: Keyword.fetch!(opts, :cve),
      package_name: Keyword.get(opts, :package_name, "busybox"),
      package_version: "1.0",
      severity: Keyword.get(opts, :severity, "HIGH"),
      suppressed: Keyword.get(opts, :suppressed, false),
      reopen_count: Keyword.get(opts, :reopen_count, 0),
      first_seen: Keyword.fetch!(opts, :first_seen),
      last_seen: Keyword.get(opts, :first_seen),
      resolved_at: Keyword.get(opts, :resolved_at)
    })
  end

  defp placement!(image, environment, opts \\ []) do
    Repo.insert!(%ImagePlacement{
      image_id: image.id,
      namespace: "web",
      owner: Keyword.get(opts, :owner, "alpha"),
      environment: environment,
      active: true,
      first_seen: @now,
      last_seen: @now
    })
  end

  defp days_before(days), do: DateTime.add(@now, -days * 86_400, :second)
  defp row_for(rows, cve), do: Enum.find(rows, &(&1.cve == cve))

  test "empty inventory yields no rows and a zeroed summary" do
    assert Statistics.advisory_lifecycles(@now) == []

    assert Statistics.summarize([]) == %{
             total: 0,
             open: 0,
             past_target: 0,
             median_clear_days: nil
           }
  end

  test "advisories group across images with max severity, min first observation and latest clearance" do
    first = days_before(20)

    image_a = image!("a")
    image_b = image!("b")
    placement!(image_a, "prod")
    placement!(image_a, "staging")
    placement!(image_b, "dev")

    finding!(image_a,
      cve: "CVE-1",
      severity: "MEDIUM",
      package_name: "openssl",
      first_seen: days_before(10),
      resolved_at: days_before(2)
    )

    finding!(image_b,
      cve: "CVE-1",
      severity: "CRITICAL",
      package_name: "openssl",
      first_seen: first,
      resolved_at: days_before(1)
    )

    [row] = Statistics.advisory_lifecycles(@now)

    assert row.cve == "CVE-1"
    assert row.severity == "CRITICAL"
    assert row.images == 2
    assert row.packages == 1
    assert row.occurrences == 2
    assert row.open_count == 0
    assert row.open? == false
    assert row.first_seen == first
    assert row.resolved_at == days_before(1)
    # 19 whole days from first observation to latest clearance.
    assert row.days == 19
    assert row.target == 7
    assert row.on_target? == false
    assert row.status == :cleared_past_target
    assert row.environments == ["dev", "prod", "staging"]
  end

  test "open advisories age from first observation and compare against their severity target" do
    image_a = image!("a")
    image_b = image!("b")

    finding!(image_a, cve: "CVE-CRIT", severity: "CRITICAL", first_seen: days_before(10))
    finding!(image_b, cve: "CVE-HIGH", severity: "HIGH", first_seen: days_before(10))

    rows = Statistics.advisory_lifecycles(@now)
    critical = row_for(rows, "CVE-CRIT")
    high = row_for(rows, "CVE-HIGH")

    assert critical.days == 10
    assert critical.target == 7
    assert critical.on_target? == false
    assert critical.status == :open_past_target

    assert high.days == 10
    assert high.target == 14
    assert high.on_target? == true
    assert high.status == :open_within_target
  end

  test "cleared advisories compare elapsed days against their severity target" do
    image = image!("a")

    finding!(image,
      cve: "CVE-FAST",
      severity: "MEDIUM",
      first_seen: days_before(5),
      resolved_at: days_before(2)
    )

    finding!(image,
      cve: "CVE-SLOW",
      package_name: "zlib",
      severity: "LOW",
      first_seen: days_before(80),
      resolved_at: days_before(10)
    )

    rows = Statistics.advisory_lifecycles(@now)
    fast = row_for(rows, "CVE-FAST")
    slow = row_for(rows, "CVE-SLOW")

    assert fast.days == 3
    assert fast.status == :cleared_within_target

    assert slow.days == 70
    assert slow.target == 60
    assert slow.status == :cleared_past_target
  end

  test "an advisory is open while any occurrence lacks a recorded disappearance" do
    image = image!("a")
    placement!(image, "prod")

    finding!(image,
      cve: "CVE-MIX",
      package_name: "curl",
      first_seen: days_before(9),
      resolved_at: days_before(3)
    )

    finding!(image, cve: "CVE-MIX", package_name: "zlib", first_seen: days_before(9))

    [row] = Statistics.advisory_lifecycles(@now)

    assert row.open? == true
    assert row.open_count == 1
    assert row.days == 9
    # Open advisories are never labelled by their latest clearance, though the
    # cleared occurrence keeps the latest disappearance recorded for context.
    assert row.status == :open_within_target
  end

  test "reopened and suppressed occurrences are flagged, never conflated with clearance" do
    image = image!("a")

    finding!(image,
      cve: "CVE-REOPEN",
      severity: "HIGH",
      first_seen: days_before(40),
      reopen_count: 1
    )

    finding!(image, cve: "CVE-SUP", package_name: "zlib", suppressed: true, first_seen: @now)

    rows = Statistics.advisory_lifecycles(@now)

    assert row_for(rows, "CVE-REOPEN").reopened_count == 1
    assert row_for(rows, "CVE-SUP").suppressed_count == 1
  end

  test "unreported severity yields no severity name and the most permissive target" do
    image = image!("a")
    finding!(image, cve: "CVE-NIL", severity: nil, first_seen: days_before(30))

    [row] = Statistics.advisory_lifecycles(@now)

    assert row.severity == nil
    assert row.target == 90
    assert Statistics.target_days(nil) == 90
    assert row.status == :open_within_target
  end

  test "ordering puts open past-target advisories first, then open within target, then cleared" do
    image = image!("a")

    finding!(image, cve: "CVE-Z-OPEN-LATE", severity: "CRITICAL", first_seen: days_before(9))
    finding!(image, cve: "CVE-A-OPEN-OK", package_name: "zlib", first_seen: @now)

    finding!(image,
      cve: "CVE-CLEARED",
      package_name: "curl",
      first_seen: days_before(4),
      resolved_at: days_before(1)
    )

    cves = Statistics.advisory_lifecycles(@now) |> Enum.map(& &1.cve)

    assert cves == ["CVE-Z-OPEN-LATE", "CVE-A-OPEN-OK", "CVE-CLEARED"]
  end

  test "summary counts and median clearance days reflect only cleared advisories" do
    image = image!("a")

    finding!(image, cve: "CVE-OPEN", severity: "CRITICAL", first_seen: days_before(9))

    finding!(image,
      cve: "CVE-C1",
      package_name: "zlib",
      first_seen: days_before(4),
      resolved_at: days_before(1)
    )

    finding!(image,
      cve: "CVE-C2",
      package_name: "curl",
      first_seen: days_before(10),
      resolved_at: days_before(2)
    )

    summary = Statistics.summarize(Statistics.advisory_lifecycles(@now))

    assert summary.total == 3
    assert summary.open == 1
    assert summary.past_target == 1
    assert summary.median_clear_days == 5.5
  end
end
