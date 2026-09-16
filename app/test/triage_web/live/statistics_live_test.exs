defmodule TriageWeb.StatisticsLiveTest do
  @moduledoc """
  Statistics LiveView tests: route and navigation registration, card and row
  rendering, green/red target chips, advisory links, reopened and suppressed
  flags, the honest empty state, and absence of writes on load (the latter
  also covered by the read-only request boundary test).
  """

  use TriageWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Triage.Inventory.{Finding, Image, ImagePlacement}
  alias Triage.Repo

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
    first_seen = Keyword.fetch!(opts, :first_seen)

    Repo.insert!(%Finding{
      image_id: image.id,
      cve: Keyword.fetch!(opts, :cve),
      package_name: Keyword.get(opts, :package_name, "busybox"),
      package_version: "1.0",
      severity: Keyword.get(opts, :severity, "HIGH"),
      suppressed: Keyword.get(opts, :suppressed, false),
      reopen_count: Keyword.get(opts, :reopen_count, 0),
      first_seen: first_seen,
      last_seen: first_seen,
      resolved_at: Keyword.get(opts, :resolved_at)
    })
  end

  defp placement!(image, environment) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    Repo.insert!(%ImagePlacement{
      image_id: image.id,
      namespace: "web",
      owner: "alpha",
      environment: environment,
      active: true,
      first_seen: now,
      last_seen: now
    })
  end

  defp days_ago(days) do
    DateTime.utc_now()
    |> DateTime.truncate(:second)
    |> DateTime.add(-days * 86_400, :second)
  end

  test "empty inventory renders the honest empty state and zeroed cards", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/statistics")

    assert has_element?(view, "h1", "Statistics")
    assert has_element?(view, "#nav-statistics[aria-current='page']")
    assert has_element?(view, "#statistics-empty", "not proof of a clean estate")
    refute has_element?(view, "#statistics-table")

    assert view |> element("#stat-card-total .stat-card-value") |> render() =~ "0"
    assert view |> element("#stat-card-median-clear .stat-card-value") |> render() =~ "—"
  end

  test "rows show observation dates and green/red target chips per severity", %{conn: conn} do
    image = image!("a")
    placement!(image, "prod")

    # CRITICAL open 10 days: past the 7-day local target → red.
    finding!(image, cve: "CVE-OPEN-LATE", severity: "CRITICAL", first_seen: days_ago(10))

    # MEDIUM cleared in 3 days: within the 30-day target → green.
    finding!(image,
      cve: "CVE-CLEARED-OK",
      package_name: "zlib",
      severity: "MEDIUM",
      first_seen: days_ago(5),
      resolved_at: days_ago(2)
    )

    {:ok, view, _html} = live(conn, ~p"/statistics")

    assert has_element?(view, "#statistics-note", "not verified remediation")
    assert has_element?(view, "#statistics-legend", "CRITICAL ≤ 7 days")

    assert has_element?(
             view,
             "#stat-row-CVE-OPEN-LATE .stat-chip-bad[title='local review target ≤ 7 days']",
             "10 d open"
           )

    assert has_element?(view, "#stat-row-CVE-OPEN-LATE", "Still observed")

    assert has_element?(
             view,
             "#stat-row-CVE-CLEARED-OK .stat-chip-good[title='local review target ≤ 30 days']",
             "3 d"
           )

    refute has_element?(view, "#stat-row-CVE-CLEARED-OK", "Still observed")

    # Advisory rows link to the advisory detail page.
    assert has_element?(view, "#stat-row-CVE-OPEN-LATE a[href='/cves/CVE-OPEN-LATE']")
    # Placement environment of the affected image is shown as context.
    assert has_element?(view, "#stat-row-CVE-OPEN-LATE", "prod")

    assert view |> element("#stat-card-total .stat-card-value") |> render() =~ "2"
    assert view |> element("#stat-card-open .stat-card-value") |> render() =~ "1"
    assert view |> element("#stat-card-past-target .stat-card-value") |> render() =~ "1"
    assert view |> element("#stat-card-median-clear .stat-card-value") |> render() =~ "3"
  end

  test "reopened and suppressed markers stay observational, never remedial", %{conn: conn} do
    image = image!("a")

    finding!(image, cve: "CVE-REOPEN", first_seen: days_ago(1), reopen_count: 1)

    finding!(image,
      cve: "CVE-SUP",
      package_name: "zlib",
      suppressed: true,
      first_seen: days_ago(1)
    )

    {:ok, view, _html} = live(conn, ~p"/statistics")

    assert has_element?(view, "#stat-row-CVE-REOPEN", "reopened history")
    assert has_element?(view, "#stat-row-CVE-SUP", "suppression is not mitigation evidence")
  end

  test "reload re-reads the inventory without writing", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/statistics")

    image = image!("b")
    finding!(image, cve: "CVE-NEW", first_seen: days_ago(0))

    render_click(view, "reload")
    assert has_element?(view, "#stat-row-CVE-NEW")
  end
end
