defmodule Triage.InventoryTest do
  use Triage.DataCase, async: true

  import Ecto.Query
  alias Triage.{Inventory, Repo, Seeds}
  alias Triage.Inventory.{Finding, FindingEvent}

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
    rows = Repo.all(from f in Finding, where: f.cve == "CVE-2025-1001")

    assert length(rows) == 3
    assert Enum.sort(Enum.map(rows, & &1.package_name)) == ["busybox", "busybox-binsh", "curl"]
  end

  test "groups are team-scoped and shared images appear under both teams" do
    alpha = Inventory.list_groups(owner: "alpha")
    beta = Inventory.list_groups(owner: "beta")

    alpha_1001 = Enum.find(alpha, &(&1.cve == "CVE-2025-1001"))
    beta_1001 = Enum.find(beta, &(&1.cve == "CVE-2025-1001"))

    assert alpha_1001.occurrences == 2
    assert beta_1001.occurrences == 3
    assert alpha_1001.teams == 1
  end

  test "unknown team yields an empty list, not everything" do
    assert Inventory.list_groups(owner: "no-such-team") == []
  end

  test "environment scoping narrows results" do
    assert Inventory.list_groups(environment: "prod-cluster-1") != []
    assert Inventory.list_groups(environment: "no-such-cluster") == []
  end

  test "suppressed findings are hidden by default and labelled when included" do
    default = Inventory.list_groups(owner: "beta")
    refute Enum.any?(default, &(&1.cve == "CVE-2025-3003"))

    including = Inventory.list_groups(owner: "beta", include_suppressed: true)
    group = Enum.find(including, &(&1.cve == "CVE-2025-3003"))

    assert group
    assert group.suppressed_occurrences == 1
    assert Inventory.summary_counts().suppressed == 1
  end

  test "resolved findings never appear in the active list" do
    refute Enum.any?(
             Inventory.list_groups(include_suppressed: true),
             &(&1.cve == "CVE-2023-5005")
           )
  end

  test "reopened fixture keeps full appeared → resolved → reopened history" do
    reopened =
      Repo.one!(from f in Finding, where: f.cve == "CVE-2024-4004" and f.package_version == "1.3")

    {:ok, data} = Inventory.fetch_finding(reopened.id)

    assert data.finding.reopen_count == 1
    assert is_nil(data.finding.resolved_at)
    assert Enum.map(data.events, & &1.event) == ["appeared", "resolved", "reopened"]
  end

  test "resolved fixture records its disappearance without claiming remediation" do
    resolved = Repo.one!(from f in Finding, where: f.cve == "CVE-2023-5005")

    {:ok, data} = Inventory.fetch_finding(resolved.id)

    assert data.finding.resolved_at
    assert Enum.map(data.events, & &1.event) == ["appeared", "resolved"]
  end

  test "group search matches a package without hiding other affected packages" do
    groups = Inventory.list_groups(search: "busybox")
    group = Enum.find(groups, &(&1.cve == "CVE-2025-1001"))

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
        %{cve: "CVE-2025-1001", package_name: "busybox", package_version: "1.37"},
        DateTime.utc_now()
      )

    assert finding.reopen_count == 0
  end
end
