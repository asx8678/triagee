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

  test "the overview is posture plus two rails, with the removed blocks gone", %{conn: conn} do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    # Section order: posture first, then the two bounded rails.
    assert LazyHTML.query(document, "#home-inventory, #home-active, #home-newest")
           |> LazyHTML.attribute("id") == ["home-inventory", "home-active", "home-newest"]

    assert LazyHTML.query(document, "#home-inventory-title") |> LazyHTML.text() ==
             "Local inventory"

    assert LazyHTML.query(document, "#overview-inventory-title") |> LazyHTML.text() ==
             "Occurrence counts"

    assert LazyHTML.query(document, "#home-active-title") |> LazyHTML.text() == "Active now"

    assert LazyHTML.query(document, "#home-newest-title") |> LazyHTML.text() ==
             "Newest discovered"

    # The three blocks this redesign removed: a critical table (Triage owns it),
    # a cases preview (the case pages own it) and the news feed (Intel owns it).
    for removed <- ["#home-critical-list", "#home-critical-title", "#overview-recent-cases"] do
      assert LazyHTML.query(document, removed) |> Enum.count() == 0
    end

    assert LazyHTML.query(document, "#home-news") |> Enum.count() == 0
    assert LazyHTML.query(document, "#home-news-list") |> Enum.count() == 0

    # The capabilities are still one link away rather than silently dropped.
    assert LazyHTML.query(document, "#home-scope-note a[href='/triage']") |> Enum.count() == 1
    assert LazyHTML.query(document, "#home-scope-note a[href='/intel']") |> Enum.count() == 1
    assert LazyHTML.query(document, "#home-scope-note a[href='/findings']") |> Enum.count() == 1
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

  test "coincident rails say so instead of reading as a duplicated render", %{conn: conn} do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    rail = fn id ->
      document |> LazyHTML.query("#{id} .ov-list-title") |> LazyHTML.text() |> String.trim()
    end

    note = LazyHTML.query(document, "#home-rails-coincide")

    # The note is a property of the data, not of the layout: it appears exactly
    # when the two orders coincide, so it can never claim a divergence that is
    # not there, nor stay silent about one that is.
    assert rail.("#home-active-list") == rail.("#home-newest-list") ==
             (Enum.count(note) == 1)

    if Enum.count(note) == 1 do
      assert LazyHTML.text(note) =~ "first observed on the day it was last observed"
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

    assert document
           |> LazyHTML.query("#home-active-caption a[href='/findings?sort=last_seen']")
           |> Enum.count() == 1
  end

  test "the newest rail shows five of the real total and links its own order", %{conn: conn} do
    add_recent_advisories!(12)

    total = Inventory.count_groups([])
    assert total > 5, "the rail must be truncated beyond its five-row read"

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(document, "#home-newest-list li") |> Enum.count() == 5

    assert document |> LazyHTML.query("#home-newest-caption") |> LazyHTML.text() =~
             "Showing 5 of #{total}"

    assert document
           |> LazyHTML.query("#home-newest-caption a[href='/findings?sort=newest']")
           |> Enum.count() == 1
  end

  test "a rail does not claim to withhold advisories when it shows them all", %{conn: conn} do
    total = Inventory.count_groups([])
    assert total <= 5, "the seeded estate must fit in one rail for this assertion"

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(document, "#home-active-list li") |> Enum.count() == total
    assert LazyHTML.query(document, "#home-active-caption") |> LazyHTML.text() =~ "Showing all"
    assert LazyHTML.query(document, "#home-newest-caption") |> LazyHTML.text() =~ "Showing all"
  end

  test "an empty inventory renders zero posture without claiming a clean estate", %{conn: conn} do
    Triage.DataCase.reset_inventory!()

    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert document |> LazyHTML.query("#home-critical-count") |> LazyHTML.text() |> String.trim() ==
             "0"

    assert document |> LazyHTML.query("#home-active-empty") |> Enum.count() == 1
    assert document |> LazyHTML.query("#home-newest-empty") |> Enum.count() == 1

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
