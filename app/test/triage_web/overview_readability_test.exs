defmodule TriageWeb.OverviewReadabilityTest do
  use TriageWeb.ConnCase, async: false

  alias Triage.{Inventory, Seeds}

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

  test "overview renders one canonical recent-findings list in last-observed order", %{conn: conn} do
    rows = Inventory.active_now_cve_groups(5)
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    # Exactly one list, one ordering label, one scope link. No second mode and
    # no review CTA this page cannot act on: review starts in Triage only.
    assert LazyHTML.query(document, "#home-activity .ov-list") |> Enum.count() == 1
    assert LazyHTML.query(document, "#home-view-tabs") |> Enum.count() == 0
    assert LazyHTML.query(document, "#home-review-critical") |> Enum.count() == 0
    assert LazyHTML.query(document, "#home-rails-coincide") |> Enum.count() == 0
    assert LazyHTML.query(document, "#home-newest") |> Enum.count() == 0

    assert LazyHTML.query(document, "#home-activity-title") |> LazyHTML.text() ==
             "Recent findings"

    assert LazyHTML.text(document) =~ "Last observed locally, newest first"

    assert LazyHTML.query(document, "#home-active-list .ov-list-title a")
           |> Enum.map(&LazyHTML.text/1) == Enum.map(rows, & &1.cve)

    assert LazyHTML.query(document, "#home-active-all[href='/findings?sort=last_seen']")
           |> Enum.count() == 1

    # Timestamps match the label: last observation, not first discovery.
    for {row, item} <- Enum.zip(rows, LazyHTML.query(document, "#home-active-list .ov-list-row")) do
      dom = LazyHTML.query(item, "time") |> Enum.at(0)
      assert dom |> LazyHTML.attribute("datetime") |> hd() == DateTime.to_iso8601(row.last_seen)
    end

    # Read-only browsing: nothing was created, approved or activated.
    assert LazyHTML.query(document, "#home-activity form") |> Enum.count() == 0
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

  test "the total tile counts a mixed-severity CVE once, not once per band", %{conn: conn} do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    count = fn id ->
      document
      |> LazyHTML.query("##{id}")
      |> LazyHTML.text()
      |> String.trim()
      |> String.to_integer()
    end

    bands =
      count.("home-critical-count") + count.("home-high-count") + count.("home-medium-count") +
        count.("home-low-count")

    total = count.("home-total-count")

    assert total == Inventory.cve_summary_counts().total
    assert bands > total, "the seeded estate records CVE-2024-4004 at two severities"
  end

  test "old overview modes redirect to the canonical list and invalid modes fail visibly", %{
    conn: conn
  } do
    for view <- ["recent", "newest"] do
      assert conn |> get("/?view=" <> view) |> redirected_to() == ~p"/"
    end

    for query <- ["view=unexpected", "view[]=newest", "view[nested]=recent"] do
      assert conn |> get("/?" <> query) |> response(400) =~ "Invalid overview view"
    end
  end

  test "the severity mix names its band order and titles every band", %{conn: conn} do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    # The four fills are a colour ramp; naming the order is the key that makes
    # them readable, and each band carries its own count on hover.
    caption =
      document |> LazyHTML.query(".ov-sevbar-wrap > p.supporting") |> LazyHTML.text()

    assert caption =~ "left to right"
    assert caption =~ "critical, high, medium, low"

    titles = document |> LazyHTML.query(".ov-sevbar-seg") |> LazyHTML.attribute("title")
    assert length(titles) == 4

    for {title, word} <- Enum.zip(titles, ~w(critical high medium low)) do
      assert title =~ word
    end
  end

  test "the active rail shows five of the real total and links its own order", %{conn: conn} do
    add_recent_advisories!(12)

    total = Inventory.count_groups([])
    assert total > 5, "the rail must be truncated beyond its five-row read"

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(document, "#home-active-list li") |> Enum.count() == 5

    assert document |> LazyHTML.query("#home-active-caption") |> LazyHTML.text() =~
             "Showing 5 of #{total}"

    # The header link is the one enumator: exact order, no caption duplication.
    assert document
           |> LazyHTML.query("#home-active-all[href='/findings?sort=last_seen']")
           |> Enum.count() == 1

    assert LazyHTML.query(document, "#home-active-caption a") |> Enum.count() == 0
  end

  test "a rail does not claim to withhold advisories when it shows them all", %{conn: conn} do
    total = Inventory.count_groups([])
    assert total <= 5, "the seeded estate must fit in one rail for this assertion"

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(document, "#home-active-list li") |> Enum.count() == total
    assert LazyHTML.query(document, "#home-active-caption") |> LazyHTML.text() =~ "Showing all"
  end

  test "an empty inventory renders zero posture without claiming a clean estate", %{conn: conn} do
    Triage.DataCase.reset_inventory!()

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert document |> LazyHTML.query("#home-critical-count") |> LazyHTML.text() |> String.trim() ==
             "0"

    assert document |> LazyHTML.query("#home-active-empty") |> Enum.count() == 1

    assert document |> LazyHTML.query("#home-active-empty") |> LazyHTML.text() =~
             "not proof of a clean estate"
  end

  # Advisories built through the app's own public inventory writes, so the rail
  # cap is exercised by real group rows.
  defp add_recent_advisories!(count) do
    now = DateTime.utc_now()

    {:ok, image} =
      Triage.Inventory.upsert_image(
        %{
          digest: "sha256:" <> String.duplicate("d", 64),
          repository: "registry.internal/overview-rail-cap",
          tag: "1.0",
          description: "Fixture for the bounded overview rails"
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

    :ok
  end
end
