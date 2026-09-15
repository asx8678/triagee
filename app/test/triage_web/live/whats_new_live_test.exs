defmodule TriageWeb.WhatsNewLiveTest do
  @moduledoc """
  What's New LiveView tests (PR 4): route registration, scope filtering and
  cursor resets, hostile parameter handling that clears rather than widens,
  the empty state's structural position outside the stream container, detail
  link scoping, and read-only purity of the rendered feed.
  """

  use TriageWeb.ConnCase, async: false

  import Ecto.Query
  import Phoenix.LiveViewTest

  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}
  alias Triage.Repo

  @now ~U[2026-09-09 06:00:00Z]

  setup do
    # Inventory-wide feed: start from a known-empty baseline.
    # See Triage.DataCase.reset_inventory!/0 for the full rationale.
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
      cve: Keyword.get(opts, :cve, "CVE-2025-1001"),
      package_name: Keyword.get(opts, :package_name, "busybox"),
      package_version: Keyword.get(opts, :package_version, "1.0"),
      severity: Keyword.get(opts, :severity, "HIGH"),
      suppressed: Keyword.get(opts, :suppressed, false),
      resolved_at: Keyword.get(opts, :resolved_at),
      first_seen: @now,
      last_seen: @now
    })
  end

  defp event!(finding, name, opts) do
    Repo.insert!(%FindingEvent{
      finding_id: finding.id,
      event: name,
      occurred_at: Keyword.get(opts, :occurred_at, @now),
      note: Keyword.get(opts, :note)
    })
  end

  defp placement!(image, owner, environment, opts \\ []) do
    Repo.insert!(%ImagePlacement{
      image_id: image.id,
      namespace: Keyword.get(opts, :namespace, "web"),
      owner: owner,
      environment: environment,
      active: Keyword.get(opts, :active, true),
      first_seen: @now,
      last_seen: @now
    })
  end

  defp feed!(seed, opts \\ []) do
    image = image!(seed)
    finding = finding!(image, opts)

    placement!(
      image,
      Keyword.get(opts, :owner, "alpha"),
      Keyword.get(opts, :environment, "prod-cluster-1"),
      active: Keyword.get(opts, :active, true)
    )

    event!(finding, Keyword.get(opts, :event, "appeared"),
      occurred_at: Keyword.get(opts, :occurred_at, @now)
    )

    finding
  end

  test "the route is registered and renders the feed", %{conn: conn} do
    _finding = feed!("route")

    {:ok, view, _html} = live(conn, ~p"/whats-new")

    assert has_element?(view, "#whats-new-form")
    assert has_element?(view, "#events-stream")
    refute has_element?(view, "#events-error")

    html = render(view)
    assert has_element?(view, "h1", "Activity")
    assert html =~ "First observed locally"
    assert html =~ "Recorded observation time"
  end

  test "scope filters patch the URL, keep the scope on detail links and reset the cursor",
       %{conn: conn} do
    finding = feed!("scoped", owner: "alpha")
    _other = feed!("outside", owner: "beta")

    {:ok, view, _html} = live(conn, ~p"/whats-new")

    render_patch(view, ~p"/whats-new?owner=alpha")
    assert_patch(view, ~p"/whats-new?owner=alpha")

    qs = %{owner: "alpha", activity: %{from: "activity", owner: "alpha"}}

    assert has_element?(
             view,
             "#event-link-#{Enum.at(event_ids(finding), 0)}[href='#{~p"/findings/#{finding.id}?#{qs}"}']"
           )

    # The row's advisory id opens the advisory aggregate under the same activity
    # filter, never widened to every team.
    assert has_element?(
             view,
             "#event-cve-#{Enum.at(event_ids(finding), 0)}[href='#{~p"/cves/#{finding.cve}?owner=alpha"}']"
           )

    # Scope change discards any previous cursor.
    render_patch(view, ~p"/whats-new?owner=alpha&before=1")
    assert_patch(view, ~p"/whats-new?owner=alpha&before=1")
  end

  test "unknown but valid scope renders the honest empty state outside the stream",
       %{conn: conn} do
    _finding = feed!("emptyscope")

    {:ok, view, _html} = live(conn, ~p"/whats-new?owner=ghost-team")

    assert has_element?(view, "#events-empty")
    refute has_element?(view, "#events-error")
    refute has_element?(view, "#events-stream #events-empty")
    refute has_element?(view, "[id^='event-link-']")
  end

  test "the empty state is absent while rows exist", %{conn: conn} do
    _finding = feed!("withrows")

    {:ok, view, _html} = live(conn, ~p"/whats-new")

    refute has_element?(view, "#events-empty")
    assert has_element?(view, "#events-stream [id^='event-']")
  end

  test "invalid parameters clear rows, links and pagination without widening", %{conn: conn} do
    finding = feed!("invalid")
    _ = finding

    {:ok, view, _html} = live(conn, ~p"/whats-new")
    assert has_element?(view, "#events-stream [id^='event-']")

    render_patch(view, ~p"/whats-new?before=abc")

    assert has_element?(view, "#events-error")
    refute has_element?(view, "#events-stream [id^='event-']")
    refute has_element?(view, "[id^='event-link-']")
    refute has_element?(view, "#older-events")
    refute has_element?(view, "#events-empty")
  end

  test "a malformed filter event keeps the channel alive and clears the empty state",
       %{conn: conn} do
    _finding = feed!("malformed")

    {:ok, view, _html} = live(conn, ~p"/whats-new")

    render_patch(view, ~p"/whats-new?owner=ghost-team")
    assert has_element?(view, "#events-empty")

    render_change(view, "filter", %{"filters" => %{"owner" => ["alpha"]}})

    assert has_element?(view, "#events-error")
    refute has_element?(view, "#events-empty")

    # Recovery, on the same mount.
    render_patch(view, ~p"/whats-new")
    refute has_element?(view, "#events-error")
    assert has_element?(view, "#events-stream [id^='event-']")
  end

  test "rows to empty to error to rows on one mount", %{conn: conn} do
    _finding = feed!("transitions")

    {:ok, view, _html} = live(conn, ~p"/whats-new")
    assert has_element?(view, "#events-stream [id^='event-']")
    refute has_element?(view, "#events-empty")

    render_patch(view, ~p"/whats-new?owner=ghost-team")
    assert has_element?(view, "#events-empty")
    refute has_element?(view, "#events-error")

    render_patch(view, ~p"/whats-new?before=abc")
    assert has_element?(view, "#events-error")
    refute has_element?(view, "#events-empty")

    render_patch(view, ~p"/whats-new")
    refute has_element?(view, "#events-error")
    assert has_element?(view, "#events-stream [id^='event-']")
  end

  test "an inactive-only scoped row shows no detail link", %{conn: conn} do
    finding = feed!("inactive", owner: "alpha", active: false)

    {:ok, view, _html} = live(conn, ~p"/whats-new?owner=alpha")

    assert has_element?(view, "#events-stream [id^='event-']")
    refute has_element?(view, "#event-link-#{Enum.at(event_ids(finding), 0)}")
    refute has_element?(view, "[id^='event-link-']")
  end

  test "hostile text is rendered as text", %{conn: conn} do
    image = image!("hostile")

    finding =
      finding!(image, cve: "CVE-2025-1001", package_name: "<script>alert('x')</script>")

    placement!(image, "alpha", "prod-cluster-1")
    event!(finding, "appeared", note: "<img src=x onerror=alert(1)>")

    {:ok, _view, html} = live(conn, ~p"/whats-new")

    refute html =~ "<script>alert('x')</script>"
    refute html =~ "<img src=x onerror=alert(1)>"
    assert html =~ "&lt;script&gt;"
  end

  test "the feed performs no writes", %{conn: conn} do
    _finding = feed!("purity")

    before = table_counts()

    {:ok, view, _html} = live(conn, ~p"/whats-new")
    render_patch(view, ~p"/whats-new?owner=alpha")
    render(view)

    assert table_counts() == before
  end

  test "recorded facts stay separate from changed current metadata and backdated events keep ID order",
       %{conn: conn} do
    image = image!("event-facts")
    finding = finding!(image, severity: "LOW")
    placement!(image, "today-team", "current-env", namespace: "current-namespace")
    first = event!(finding, "appeared", occurred_at: ~U[2026-09-10 06:00:00Z])

    last =
      event!(finding, "resolved",
        occurred_at: ~U[2026-08-01 06:00:00Z],
        note: "<img src=x onerror=alert(1)>"
      )

    Repo.update_all(from(f in Finding, where: f.id == ^finding.id),
      set: [severity: "CRITICAL", suppressed: true]
    )

    before = table_counts()
    {:ok, view, _html} = live(conn, ~p"/whats-new")

    assert has_element?(view, "#events-stream > li:first-child#event-#{last.id}")
    assert has_element?(view, "#events-stream > li:last-child#event-#{first.id}")
    assert has_element?(view, "#events-pagination", "record ID order")

    assert has_element?(
             view,
             "#event-facts-#{last.id} h2",
             "No longer observed in local inventory"
           )

    assert has_element?(view, "#event-facts-#{last.id}", "not verified remediation")
    assert has_element?(view, "#event-facts-#{last.id}", "<img src=x onerror=alert(1)>")
    refute has_element?(view, "#event-facts-#{last.id} img")
    refute has_element?(view, "#event-facts-#{last.id} .status-badge")
    refute has_element?(view, "#event-facts-#{last.id}", "today-team")
    assert has_element?(view, "#event-current-#{last.id}", "Current local metadata")
    assert has_element?(view, "#event-current-#{last.id}", "CRITICAL")
    assert has_element?(view, "#event-current-#{last.id}", "Open in local inventory")
    assert has_element?(view, "#event-current-#{last.id}", "Suppressed — not mitigation evidence")
    assert has_element?(view, "#event-current-#{last.id}", "today-team")
    assert has_element?(view, "#event-current-#{last.id}", "current-namespace")

    assert has_element?(
             view,
             "#event-facts-#{last.id} time[datetime='2026-08-01T06:00:00Z'][title='2026-08-01T06:00:00Z']"
           )

    assert has_element?(view, "#event-digest-#{last.id}-copy[data-copy-value='#{image.digest}']")
    assert has_element?(view, "#feed-banner", "not historical event ownership")

    view |> element("#reload-events") |> render_click()
    assert table_counts() == before
  end

  test "page count and older navigation preserve record order, scoped cursor and one row per event",
       %{conn: conn} do
    image = image!("pages")
    finding = finding!(image, [])
    placement!(image, "alpha", "prod-cluster-1")
    placement!(image, "alpha", "prod-cluster-1", namespace: "worker")

    events =
      for n <- 1..27,
          do: event!(finding, "appeared", occurred_at: DateTime.add(@now, -n, :second))

    displayed = events |> Enum.reverse() |> Enum.take(25)
    cursor = List.last(displayed).id
    scope = %{owner: "alpha", environment: "prod-cluster-1"}
    older = ~p"/whats-new?#{Map.put(scope, :before, cursor)}"
    before = table_counts()

    {:ok, view, _html} = live(conn, ~p"/whats-new?#{scope}")
    assert has_element?(view, "#activity-summary", "25 events on this page")
    assert has_element?(view, "#older-events[href='#{older}']")
    assert activity_row_ids(view) == Enum.map(displayed, &"event-#{&1.id}")

    view |> element("#older-events") |> render_click()
    assert_patch(view, older)
    assert has_element?(view, "#activity-summary", "2 events on this page")

    assert activity_row_ids(view) ==
             events |> Enum.take(2) |> Enum.reverse() |> Enum.map(&"event-#{&1.id}")

    refute has_element?(view, "#older-events")
    assert has_element?(view, "#newest-events[href='#{~p"/whats-new?#{scope}"}']")

    view
    |> element("#whats-new-form")
    |> render_change(%{"owner" => "alpha", "environment" => ""})

    assert_patch(view, ~p"/whats-new?owner=alpha")
    refute has_element?(view, "#newest-events")
    assert has_element?(view, "#activity-summary", "25 events on this page")

    render_patch(view, older)
    event = Enum.at(events, 1)
    result = view |> element("#event-link-#{event.id}") |> render_click()
    {:ok, detail, _html} = follow_redirect(result, conn)
    assert has_element?(detail, "#back-to-activity[href='#{older}']")
    assert has_element?(detail, "#finding-display-scope", "alpha · prod-cluster-1")
    back = detail |> element("#back-to-activity") |> render_click()
    {:ok, returned, _html} = follow_redirect(back, conn)
    assert has_element?(returned, "#activity-summary", "2 events on this page")
    assert table_counts() == before
  end

  test "missing placement and severity stay explicit, and invalid params hide stale page counts",
       %{conn: conn} do
    image = image!("missing-metadata")
    finding = finding!(image, severity: nil)
    event = event!(finding, "appeared", [])
    {:ok, view, _html} = live(conn, ~p"/whats-new")

    assert has_element?(view, "#event-current-#{event.id}", "No placements recorded")
    assert has_element?(view, "#event-current-#{event.id} .status-badge", "Not reported")
    assert has_element?(view, "#event-link-#{event.id}")
    assert has_element?(view, "#activity-summary", "1 event on this page")

    render_patch(view, ~p"/whats-new?before=invalid")
    assert has_element?(view, "#events-error[role='alert']")
    refute has_element?(view, "#activity-summary")
    refute has_element?(view, "#events-stream > li")
    refute has_element?(view, "#events-pagination")

    view |> element("#reset-activity") |> render_click()
    assert_patch(view, ~p"/whats-new")
    assert has_element?(view, "#event-link-#{event.id}")
    refute has_element?(view, "#events-error")
  end

  defp activity_row_ids(view) do
    view
    |> render()
    |> LazyHTML.from_fragment()
    |> LazyHTML.query("#events-stream > li")
    |> LazyHTML.attribute("id")
  end

  defp event_ids(finding) do
    Repo.all(
      from e in FindingEvent,
        where: e.finding_id == ^finding.id,
        order_by: [desc: e.id],
        select: e.id
    )
  end

  defp table_counts do
    %{
      events: Repo.aggregate(FindingEvent, :count),
      findings: Repo.aggregate(Finding, :count),
      images: Repo.aggregate(Image, :count),
      placements: Repo.aggregate(ImagePlacement, :count),
      cards: Repo.aggregate(Triage.Cases.ReviewCase, :count),
      snapshots: Repo.aggregate(Triage.Cases.EvidenceSnapshot, :count),
      reviews: Repo.aggregate(Triage.Cases.Review, :count),
      case_events: Repo.aggregate(Triage.Cases.CaseEvent, :count)
    }
  end
end
