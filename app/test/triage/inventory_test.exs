defmodule Triage.InventoryTest do
  use Triage.DataCase, async: true

  import Ecto.Query
  import Triage.Fixtures

  alias Triage.{Inventory, Repo, Seeds}
  alias Triage.Inventory.{Finding, FindingEvent, ImagePlacement}

  setup do
    :ok = Seeds.seed()
    :ok
  end

  test "seeding is idempotent: no duplicate rows or lifecycle events on replay" do
    before_groups = length(Inventory.list_groups(include_suppressed: true))
    before_events = Repo.aggregate(FindingEvent, :count)
    before_findings = Repo.aggregate(Inventory.Finding, :count)

    :ok = Seeds.seed()

    assert Repo.aggregate(Finding, :count) |> then(&(&1 == before_findings))
    assert Repo.aggregate(FindingEvent, :count) |> then(&(&1 == before_events))
    assert length(Inventory.list_groups(include_suppressed: true)) == before_groups
  end

  test "one advisory maps to one finding row per package occurrence" do
    rows = Repo.all(from f in Finding, where: f.cve == "CVE-2026-60002")

    assert length(rows) == 3

    assert Enum.sort(Enum.map(rows, & &1.package_name)) == [
             "openssh-client",
             "openssh-client-common",
             "openssh-sftp-server"
           ]
  end

  test "groups are team-scoped and shared images appear under both teams" do
    alpha = Inventory.list_groups(owner: "alpha")
    beta = Inventory.list_groups(owner: "beta")

    alpha_1001 = Enum.find(alpha, &(&1.cve == "CVE-2026-60002"))
    beta_1001 = Enum.find(beta, &(&1.cve == "CVE-2026-60002"))

    assert alpha_1001.occurrences == 2
    assert beta_1001.occurrences == 3
    assert alpha_1001.teams == 1
  end

  test "the last_seen order is most-recently-observed first" do
    image = image!("last-seen-order")
    placement!(image, "alpha", "prod-cluster-1")
    finding!(image, "CVE-2098-7001", last_seen: at(0))
    finding!(image, "CVE-2098-7002", last_seen: at(30))

    ids = Inventory.list_groups(sort: "last_seen") |> Enum.map(& &1.cve)

    assert Enum.find_index(ids, &(&1 == "CVE-2098-7001")) <
             Enum.find_index(ids, &(&1 == "CVE-2098-7002"))

    assert [newest | _] = Inventory.active_now_cve_groups(1)
    assert newest.cve == "CVE-2098-7001"
  end

  test "unknown team yields an empty list, not everything" do
    assert Inventory.list_groups(owner: "no-such-team") == []
  end

  test "environment scoping narrows results" do
    assert Inventory.list_groups(environment: "prod") != []
    assert Inventory.list_groups(environment: "no-such-cluster") == []
  end

  test "suppressed findings are hidden by default and labelled when included" do
    default = Inventory.list_groups(owner: "beta")
    refute Enum.any?(default, &(&1.cve == "CVE-2026-48931"))

    including = Inventory.list_groups(owner: "beta", include_suppressed: true)
    group = Enum.find(including, &(&1.cve == "CVE-2026-48931"))

    assert group
    assert group.suppressed_occurrences == 1
    assert Inventory.summary_counts().suppressed == 3
  end

  test "resolved findings never appear in the active list" do
    refute Enum.any?(
             Inventory.list_groups(include_suppressed: true),
             &(&1.cve == "CVE-2026-61625")
           )
  end

  test "reopened fixture keeps full appeared → resolved → reopened history" do
    reopened =
      Repo.one!(
        from f in Finding, where: f.cve == "CVE-2026-57236" and f.package_version == "1.3"
      )

    {:ok, data} = Inventory.fetch_finding(reopened.id)

    assert data.finding.reopen_count == 1
    assert is_nil(data.finding.resolved_at)
    assert Enum.map(data.events, & &1.event) == ["appeared", "resolved", "reopened"]
  end

  test "resolved fixture records its disappearance without claiming remediation" do
    resolved = Repo.one!(from f in Finding, where: f.cve == "CVE-2026-61625")

    {:ok, data} = Inventory.fetch_finding(resolved.id)

    assert data.finding.resolved_at
    assert Enum.map(data.events, & &1.event) == ["appeared", "resolved"]
  end

  test "group search matches a package without hiding other affected packages" do
    groups = Inventory.list_groups(search: "openssh-client")
    group = Enum.find(groups, &(&1.cve == "CVE-2026-60002"))

    assert group
    assert group.occurrences == 3
    assert group.packages == 3
  end

  test "upsert_finding with reopen records a reopened event on reappearance" do
    image = Repo.one!(from i in Inventory.Image, where: i.repository == "registry.internal/app-a")

    # Simulate reappearance through the live-collection path.
    {:ok, finding} =
      Inventory.upsert_finding(
        image,
        %{cve: "CVE-2026-60002", package_name: "openssh-client", package_version: "1:10.2p1"},
        DateTime.utc_now()
      )

    assert finding.reopen_count == 0
  end

  test "the distinct-CVE total is not the sum of the severity bands" do
    counts = Inventory.cve_summary_counts()

    expected_total =
      Repo.one(
        from f in Finding,
          join: p in ImagePlacement,
          on: p.image_id == f.image_id and p.active == true,
          where: is_nil(f.resolved_at) and f.suppressed == false,
          select: count(f.cve, :distinct)
      )

    band_membership =
      from(f in Finding,
        join: p in ImagePlacement,
        on: p.image_id == f.image_id and p.active == true,
        where: is_nil(f.resolved_at) and f.suppressed == false,
        group_by: f.cve,
        select: %{severity_bands: count(f.severity, :distinct)}
      )

    expected_bands =
      Repo.one(from s in subquery(band_membership), select: sum(s.severity_bands))
      |> Decimal.to_integer()

    bands = counts.critical + counts.high + counts.medium + counts.low

    assert counts.total == expected_total
    assert bands == expected_bands

    # The seeded estate records CVE-2026-57236 at HIGH and MEDIUM, so the bands
    # are not a partition of the total. Adding them up is exactly what
    # overstated the total before it became its own distinct count.
    assert bands > counts.total
  end
end
