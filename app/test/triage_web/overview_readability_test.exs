defmodule TriageWeb.OverviewReadabilityTest do
  use TriageWeb.ConnCase, async: false

  import Ecto.Query

  alias Triage.{Cases, Intel, Repo, Seeds}
  alias Triage.Inventory.Finding

  setup do
    Triage.DataCase.reset_inventory!()
    :ok = Seeds.seed()
    :ok
  end

  test "counts link to findings and the suppressed link uses the real filter param", %{
    conn: conn
  } do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(
             document,
             "#open-occurrence-count #overview-open-link[href='/findings']"
           )
           |> Enum.count() == 1

    assert LazyHTML.query(
             document,
             "#suppressed-occurrence-count #overview-suppressed-link[href='/findings?suppressed=1']"
           )
           |> Enum.count() == 1
  end

  test "the overview marks a cached critical row and claims nothing without one", %{conn: conn} do
    # Nothing cached yet: the critical table renders no marker and no source note.
    before = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(before, "[id^='home-critical-kev-']") |> Enum.count() == 0
    assert LazyHTML.query(before, "#home-critical-kev-note") |> Enum.count() == 0

    # CVE-2024-2002 is the seeds' one CRITICAL advisory in the overview table.
    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2024-2002",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert document
           |> LazyHTML.query("#home-critical-kev-CVE-2024-2002")
           |> LazyHTML.text() == "Known exploited (KEV cache)"

    assert LazyHTML.query(document, "#home-critical-kev-note") |> Enum.count() == 1
  end

  test "recent cases state whether an assessment exists using saved data", %{conn: conn} do
    finding_id =
      Repo.one!(from f in Finding, where: f.package_name == "busybox", select: f.id, limit: 1)

    {:ok, opened} = Cases.open_case(finding_id, owner: "alpha", environment: "prod-cluster-1")
    case_id = opened.case.id

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(document, "#overview-case-#{case_id}-assessment") |> LazyHTML.text() =~
             "No assessment recorded"
  end

  test "local inventory leads the overview and the discovery list is renamed", %{conn: conn} do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(document, "#home-inventory, #home-newest, #recent-cases-title")
           |> LazyHTML.attribute("id") == ["home-inventory", "home-newest", "recent-cases-title"]

    assert LazyHTML.query(document, "#home-inventory-title") |> LazyHTML.text() ==
             "Local inventory"

    assert LazyHTML.query(document, "#recent-cases-title") |> LazyHTML.text() ==
             "Recently discovered new CVEs"

    assert LazyHTML.query(document, "#overview-inventory-title") |> LazyHTML.text() ==
             "Occurrence counts"
  end

  test "the overview is posture only: no page header, section chrome or search", %{conn: conn} do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    # One h1 and an accessible section name survive in the document, but
    # neither is drawn: the first visible element is the posture band.
    assert LazyHTML.query(document, "h1") |> Enum.count() == 1
    assert document |> LazyHTML.query("#home-title") |> LazyHTML.attribute("class") == ["sr-only"]

    assert document
           |> LazyHTML.query("#home-inventory-title")
           |> LazyHTML.attribute("class") == ["sr-only"]

    assert document
           |> LazyHTML.query("#home-inventory-intro")
           |> LazyHTML.attribute("class") == ["sr-only"]

    # No search form, no page header, no duplicated bottom link row.
    assert LazyHTML.query(document, "#overview-search") |> Enum.count() == 0
    assert LazyHTML.query(document, "#home-workflows") |> Enum.count() == 0
    assert LazyHTML.query(document, ".page-header") |> Enum.count() == 0
    assert LazyHTML.query(document, ".overview-tools") |> Enum.count() == 0
  end

  test "local inventory distinguishes distinct CVEs from occurrences and names the critical table",
       %{conn: conn} do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(document, "#home-inventory-intro") |> LazyHTML.text() =~
             "one distinct CVE"

    assert LazyHTML.query(document, "#home-critical-list caption") |> LazyHTML.text() =~
             "not CVE publication time"

    headers =
      document
      |> LazyHTML.query("#home-critical-list th")
      |> LazyHTML.text()

    assert headers =~ "CVE"
    assert headers =~ "Images"
    assert headers =~ "Occurrences"
    refute headers =~ "Severity"
    assert LazyHTML.query(document, "#home-critical-caption") |> Enum.count() == 1
  end

  test "severity posture links to filtered findings and the mix label matches the tiles", %{
    conn: conn
  } do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    for {count_id, severity} <- [
          {"home-critical-count", "CRITICAL"},
          {"home-high-count", "HIGH"},
          {"home-medium-count", "MEDIUM"},
          {"home-low-count", "LOW"}
        ] do
      assert document
             |> LazyHTML.query("##{count_id} a[href='/findings?severity=#{severity}']")
             |> Enum.count() == 1
    end

    assert LazyHTML.query(document, "#home-summary .ov-kpi-critical") |> Enum.count() == 1

    counts =
      for id <- [
            "home-critical-count",
            "home-high-count",
            "home-medium-count",
            "home-low-count"
          ] do
        document |> LazyHTML.query("##{id}") |> LazyHTML.text() |> String.trim()
      end

    expected =
      ["critical", "high", "medium", "low"]
      |> Enum.zip(counts)
      |> Enum.map_join(", ", fn {word, count} -> "#{count} #{word}" end)

    [mix_label] = LazyHTML.query(document, ".ov-sevbar") |> LazyHTML.attribute("aria-label")

    assert mix_label =~ "distinct CVEs"
    assert mix_label =~ expected
  end

  test "the newest rail shows five and says how many it withheld", %{conn: conn} do
    add_recent_advisories!(4)

    total = length(Triage.Inventory.newest_cve_groups(10))
    assert total > 5

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(document, "#home-newest-list li") |> Enum.count() == 5

    truncated = LazyHTML.query(document, "#home-newest-truncated")

    assert truncated |> LazyHTML.text() =~ "5 of #{total}"

    assert truncated |> LazyHTML.query("a[href='/findings?sort=newest']") |> Enum.count() == 1
  end

  test "the newest rail counts withheld advisories against the real total", %{conn: conn} do
    add_recent_advisories!(12)

    total = Triage.Inventory.count_groups([])
    assert total > 10, "the rail must be truncated beyond its ten-row read"

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(document, "#home-newest-list li") |> Enum.count() == 5

    # The rail reads ten rows but shows five: the withheld count must be the
    # real total, not the size of the slice it happened to read.
    assert document |> LazyHTML.query("#home-newest-truncated") |> LazyHTML.text() =~
             "5 of #{total}"
  end

  test "a critical list longer than the overview slice is capped and labelled", %{conn: conn} do
    add_critical_advisories!(12)

    total = Triage.Inventory.count_groups(severity: "CRITICAL")
    assert total > 10, "the critical table must be truncated by the overview slice"

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert document |> LazyHTML.query("#home-critical-caption") |> LazyHTML.text() =~
             "Top 10 of #{total} critical CVEs"

    assert LazyHTML.query(document, "#home-critical-list tbody tr") |> Enum.count() == 10

    assert document |> LazyHTML.query("#home-critical-all") |> LazyHTML.text() =~
             "See all #{total} critical advisories"
  end

  test "the rail does not claim to withhold advisories when it shows them all", %{conn: conn} do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    total = length(Triage.Inventory.newest_cve_groups(10))
    assert LazyHTML.query(document, "#home-newest-list li") |> Enum.count() == total
    assert LazyHTML.query(document, "#home-newest-truncated") |> Enum.count() == 0
  end

  test "an empty inventory renders zero posture without claiming a clean estate", %{conn: conn} do
    Triage.DataCase.reset_inventory!()

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert document |> LazyHTML.query("#home-critical-count") |> LazyHTML.text() |> String.trim() ==
             "0"

    assert document |> LazyHTML.query("#home-critical-empty") |> Enum.count() == 1
    assert document |> LazyHTML.query("#home-newest-empty") |> Enum.count() == 1

    assert document |> LazyHTML.query("#home-newest-empty") |> LazyHTML.text() =~
             "not proof of a clean estate"
  end

  # Critical advisories beyond the overview slice, built through the app's own
  # public inventory writes so the cap is exercised by real group rows.
  defp add_critical_advisories!(count) do
    {:ok, image} =
      Triage.Inventory.upsert_image(
        %{
          digest: "sha256:" <> String.duplicate("a", 64),
          repository: "registry.internal/overview-critical-cap",
          tag: "1.0",
          description: "Fixture for the bounded critical table"
        },
        ~U[2026-09-10 12:00:00Z]
      )

    {:ok, _placement} =
      Triage.Inventory.upsert_placement(
        image,
        %{namespace: "web", owner: "alpha", environment: "prod-cluster-1"},
        ~U[2026-09-10 12:00:00Z]
      )

    for n <- 1..count do
      {:ok, _finding} =
        Triage.Inventory.upsert_finding(
          image,
          %{
            cve: "CVE-2098-9501#{n}",
            package_name: "critical-cap-package-#{n}",
            package_version: "1.#{n}",
            severity: "CRITICAL",
            fix: nil,
            description: "Bounded critical table fixture #{n}",
            suppressed: false
          },
          DateTime.add(~U[2026-09-10 12:00:00Z], n, :minute),
          reopen: false
        )
    end

    :ok
  end

  # Extra advisories beyond the rail's five, built through the app's own public
  # inventory writes so the cap is exercised by real group rows.
  defp add_recent_advisories!(count) do
    now = ~U[2026-09-10 12:00:00Z]

    {:ok, image} =
      Triage.Inventory.upsert_image(
        %{
          digest: "sha256:" <> String.duplicate("d", 64),
          repository: "registry.internal/overview-rail-cap",
          tag: "1.0",
          description: "Fixture for the bounded newest rail"
        },
        now
      )

    {:ok, _placement} =
      Triage.Inventory.upsert_placement(
        image,
        %{namespace: "web", owner: "alpha", environment: "prod-cluster-1"},
        now
      )

    for n <- 1..count do
      {:ok, _finding} =
        Triage.Inventory.upsert_finding(
          image,
          %{
            cve: "CVE-2098-9001#{n}",
            package_name: "rail-cap-package-#{n}",
            package_version: "1.#{n}",
            severity: "LOW",
            fix: nil,
            description: "Bounded rail fixture #{n}",
            suppressed: false
          },
          DateTime.add(now, n, :minute),
          reopen: false
        )
    end
  end
end
