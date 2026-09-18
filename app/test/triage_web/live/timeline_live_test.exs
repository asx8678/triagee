defmodule TriageWeb.TimelineLiveTest do
  @moduledoc """
  End-to-end tests for the read-only CVE timeline LiveView.

  Fixtures are dated relative to today, and every test starts from an empty
  inventory, so a count assertion can only be satisfied by the rows the test
  itself created.
  """
  use TriageWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import Triage.Fixtures

  alias Triage.Cases
  alias Triage.Intel

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  # The window ends today and is Monday-aligned, so its newest week is partial:
  # it holds whole weeks back plus today's weekday. That is 56 days only on a
  # Sunday, which is why these assertions must not hard-code 56.
  defp window_days(weeks), do: 7 * (weeks - 1) + Date.day_of_week(today(), :monday)

  defp count(document, selector), do: document |> LazyHTML.query(selector) |> Enum.count()

  defp svg_width(document) do
    document
    |> LazyHTML.query("#tl-chart svg.tl-chart")
    |> LazyHTML.attribute("width")
    |> List.first()
    |> String.to_integer()
  end

  test "fit responds to container width without changing the selected history", %{conn: conn} do
    image = image!("responsive-chart")
    placement!(image, "alpha", "prod")
    finding = finding!(image, "CVE-2026-8001")
    event!(finding, "appeared", at(0, ~T[09:00:00]))
    {:ok, view, _} = live(conn, ~p"/timeline")
    assert has_element?(view, "#tl-chart-scroll[phx-hook='TimelineWidth']")
    assert has_element?(view, "select[name='weeks'] option[value='12'][selected]")

    for width <- [1390, 1870, 1000] do
      html = render_hook(view, "plot_width", %{"width" => width})

      [actual] =
        html
        |> LazyHTML.from_document()
        |> LazyHTML.query("svg.tl-chart")
        |> LazyHTML.attribute("width")

      {measured, _} = Float.parse(actual)
      assert abs(measured - width) < 0.01
      assert has_element?(view, "select[name='weeks'] option[value='12'][selected]")
    end
  end

  test "same-day lifecycle events have distinct row and action identities", %{conn: conn} do
    image = image!("same-day-events")
    finding = finding!(image, "CVE-2026-7100")
    appeared = event!(finding, "appeared", at(1))
    resolved = event!(finding, "resolved", at(1, ~T[07:00:00]))
    {:ok, view, html} = live(conn, ~p"/timeline")

    for event <- [appeared, resolved] do
      assert has_element?(view, "#tl-row-#{event.id}")
      assert has_element?(view, "#tl-open-#{event.id}")
      assert has_element?(view, "#tl-advisory-#{event.id}")
    end

    ids = html |> LazyHTML.from_document() |> LazyHTML.query("[id]") |> LazyHTML.attribute("id")
    assert length(ids) == length(Enum.uniq(ids))
  end

  test "drawer event paging preserves scope and can return to the first page", %{conn: conn} do
    image = image!("live-event-pages")
    placement!(image, "alpha", "prod")
    finding = finding!(image, "CVE-2026-7101")
    events = for second <- 1..51, do: event!(finding, "appeared", DateTime.add(at(2), second))

    {:ok, view, _} =
      live(
        conn,
        ~p"/timeline?#{%{cve: finding.cve, owner: "alpha", environment: "prod", weeks: 4}}"
      )

    assert has_element?(view, "#tl-events-next")
    refute has_element?(view, "#tl-events-first")
    assert has_element?(view, "#tl-event-#{hd(events).id}")
    view |> element("#tl-events-next") |> render_click()

    assert_patch(
      view,
      ~p"/timeline?#{%{cve: finding.cve, owner: "alpha", environment: "prod", weeks: 4, events_after: Enum.at(events, 49).id}}"
    )

    assert has_element?(view, "#tl-event-#{List.last(events).id}")
    refute has_element?(view, "#tl-event-#{hd(events).id}")
    refute has_element?(view, "#tl-events-next")
    view |> element("#tl-events-first") |> render_click()
    assert has_element?(view, "#tl-event-#{hd(events).id}")
    assert has_element?(view, "#tl-events-next")
  end

  test "drawer case paging reaches every saved case", %{conn: conn} do
    image = image!("live-case-pages")
    placement!(image, "alpha", "prod")

    cases =
      for index <- 1..11 do
        finding = finding!(image, "CVE-2026-7102", package_name: "package-#{index}")
        event!(finding, "appeared", at(1))

        assert {:ok, %{case: cse}} =
                 Cases.open_case(finding.id, owner: "alpha", environment: "prod")

        cse
      end

    {:ok, view, _} =
      live(conn, ~p"/timeline?#{%{cve: "CVE-2026-7102", owner: "alpha", environment: "prod"}}")

    assert has_element?(view, "#tl-case-#{hd(cases).id}")
    assert has_element?(view, "#tl-cases-next")
    view |> element("#tl-cases-next") |> render_click()
    assert has_element?(view, "#tl-case-#{List.last(cases).id}")
    refute has_element?(view, "#tl-case-#{hd(cases).id}")
    refute has_element?(view, "#tl-cases-next")
    view |> element("#tl-cases-first") |> render_click()
    assert has_element?(view, "#tl-case-#{hd(cases).id}")
  end

  describe "a window with recorded observations" do
    setup do
      image = image!("live-bands")
      placement!(image, "alpha", "prod-cluster-1")

      # Recorded yesterday and today: renders with a connector in both directions.
      continuing = finding!(image, "CVE-2026-5001", package_name: "openssl")
      older_event = event!(continuing, "appeared", at(1, ~T[07:00:00]))
      today_event = event!(continuing, "reopened", at(0, ~T[07:00:00]))

      # Recorded only today, and critical.
      single = finding!(image, "CVE-2026-5002", package_name: "libc", severity: "CRITICAL")
      single_event = event!(single, "appeared", at(0, ~T[09:00:00]))

      %{
        continuing: continuing,
        single: single,
        older_event: older_event,
        today_event: today_event,
        single_event: single_event
      }
    end

    test "selection highlights the upper chart, not dated rows, and persists until another selection",
         %{
           conn: conn,
           today_event: today_event,
           single_event: single_event
         } do
      {:ok, view, _} = live(conn, ~p"/timeline")
      refute has_element?(view, ".tl-selected")
      view |> element("#tl-open-#{today_event.id}") |> render_click()

      for selector <- [
            "#tl-lane-CVE-2026-5001",
            "#tl-track-CVE-2026-5001"
          ] do
        assert has_element?(view, selector <> ".tl-selected[aria-current='true']")
      end

      assert has_element?(view, "#tl-lane-CVE-2026-5001 .tl-selection-label", "Selected")
      render_hook(view, "plot_width", %{"width" => 1200})
      assert has_element?(view, "#tl-track-CVE-2026-5001.tl-selected")

      render_change(view, "filter", %{
        "weeks" => "12",
        "scale" => "detail",
        "owner" => "",
        "environment" => ""
      })

      assert has_element?(view, "#tl-track-CVE-2026-5001.tl-selected")
      {:ok, refreshed, _} = live(conn, ~p"/timeline?cve=CVE-2026-5001&scale=detail")
      assert has_element?(refreshed, "#tl-track-CVE-2026-5001.tl-selected")
      view |> element("#tl-lane-open-CVE-2026-5002") |> render_click()
      refute has_element?(view, "#tl-track-CVE-2026-5001.tl-selected")
      refute has_element?(view, "#tl-lane-CVE-2026-5001.tl-selected")

      refute has_element?(
               view,
               "#tl-row-#{today_event.id}.tl-selected"
             )

      assert has_element?(view, "#tl-track-CVE-2026-5002.tl-selected")
      assert has_element?(view, "#tl-lane-CVE-2026-5002.tl-selected")
      refute has_element?(view, "#tl-row-#{single_event.id}.tl-selected")
      assert has_element?(view, "#tl-chart-scroll[data-selected-cve='CVE-2026-5002']")
      refute has_element?(view, "#tl-bands .tl-selected")
      view |> element("#timeline-reset") |> render_click()
      refute has_element?(view, ".tl-selected")
    end

    test "renders the bands, the grid, the summary, the lanes and the tab", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/timeline")
      document = LazyHTML.from_document(html)

      assert has_element?(view, "#nav-timeline[aria-current='page']")
      assert has_element?(view, "#tl-summary")
      assert has_element?(view, "#tl-bands")
      assert has_element?(view, "#tl-lanes-table")
      assert has_element?(view, "#tl-grid-table")
      assert has_element?(view, "#tl-chart")

      # One band per day of the window: empty days are rendered explicitly.
      assert document |> LazyHTML.query("#tl-band-list li.tl-band") |> Enum.count() ==
               window_days(12)

      # Both wide tables live in their own scroll region, so the page itself
      # never scrolls horizontally at a narrow viewport (WCAG 2.2 SC 1.4.10).
      assert has_element?(view, "#tl-grid-scroll.table-region[role='region'][tabindex='0']")
      assert has_element?(view, "#tl-lanes-scroll.table-region[role='region'][tabindex='0']")
      assert has_element?(view, "#tl-grid-scroll > table#tl-grid-table")
      assert has_element?(view, "#tl-lanes-scroll > table#tl-lanes-table")

      # The grid is a real table with a caption and one row per weekday.
      assert document |> LazyHTML.query("#tl-grid-table caption") |> Enum.count() == 1

      assert document |> LazyHTML.query("#tl-grid-table tbody tr") |> Enum.count() == 7

      for weekday <- ~w(Mon Tue Wed Thu Fri Sat Sun) do
        assert has_element?(view, "#tl-grid-#{weekday}")
      end

      # The current week's column still holds the days after today, and they say
      # so: a day that has not happened is never presented as a quiet day.
      for date <- future_days_in_current_week() do
        assert html =~ "#{Calendar.strftime(date, "%d %b %Y")}: not yet observed"
      end
    end

    test "the newest band is today, and an empty day says so", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/timeline")
      document = LazyHTML.from_document(html)

      first_band = document |> LazyHTML.query("#tl-band-list li.tl-band") |> Enum.at(0)
      assert LazyHTML.attribute(first_band, "id") == ["tl-band-#{Date.to_iso8601(today())}"]

      assert has_element?(view, "#tl-band-#{Date.to_iso8601(today())}.tl-band-observed")

      empty_date = Date.add(today(), -2) |> Date.to_iso8601()
      assert has_element?(view, "#tl-band-#{empty_date}.tl-band-empty")
      assert has_element?(view, "#tl-band-empty-#{empty_date}")
      assert render(view) =~ "An empty day is not a clean day"
    end

    test "a CVE recorded on adjacent days is joined by connectors", %{
      conn: conn,
      today_event: today_event,
      older_event: older_event,
      single_event: single_event
    } do
      {:ok, view, _html} = live(conn, ~p"/timeline")
      today_key = "#tl-row-#{today_event.id}"
      older_key = "#tl-row-#{older_event.id}"

      assert has_element?(view, "#{today_key} .tl-connector-down")
      assert has_element?(view, "#{older_key} .tl-connector-up")

      # The glyph is decorative and has a text equivalent in the same row.
      assert has_element?(view, "#{today_key} .tl-arrow[aria-hidden='true']")
      assert has_element?(view, "#{today_key} .sr-only")
      assert element(view, today_key) |> render() =~ "observed again locally"

      # A CVE recorded only today has no connector in either direction.
      single_key = "#tl-row-#{single_event.id}"
      assert has_element?(view, single_key)
      refute has_element?(view, "#{single_key} .tl-connector-up")
      refute has_element?(view, "#{single_key} .tl-connector-down")
    end

    test "the lane table lists the window's CVEs with linkable detail", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/timeline")

      assert has_element?(view, "#tl-lane-CVE-2026-5001")
      assert has_element?(view, "#tl-lane-CVE-2026-5002")

      # Severity ordering: the critical CVE is listed first.
      html = render(view)
      critical_at = :binary.match(html, "CVE-2026-5002") |> elem(0)
      high_at = :binary.match(html, "CVE-2026-5001") |> elem(0)
      assert critical_at < high_at

      # The detail link is a plain patch URL, so the drawer is addressable.
      assert has_element?(
               view,
               "a#tl-lane-open-CVE-2026-5001[href='/timeline?cve=CVE-2026-5001']"
             )

      assert element(view, "#tl-lane-CVE-2026-5001") |> render() =~ "Open in local inventory"

      # A lane's CVE id reaches the advisory aggregate, matching the bands rows.
      assert has_element?(view, "#tl-lane-cve-CVE-2026-5001[href='/cves/CVE-2026-5001']")
    end

    test "a cached KEV row marks its lane, and a missing row marks nothing", %{conn: conn} do
      {:ok, plain, _html} = live(conn, ~p"/timeline")

      # Nothing is cached: no lane carries a marker and the source note is absent,
      # so the page makes no claim either way.
      refute has_element?(plain, "[id^='tl-lane-kev-']")
      refute has_element?(plain, "#tl-lanes-kev-note")

      {:ok, _} =
        Intel.replace_advisories("kev", [
          %{
            external_id: "CVE-2026-5001",
            summary: "kev entry",
            published_at: ~U[2026-09-12 10:00:00Z]
          }
        ])

      {:ok, view, _html} = live(conn, ~p"/timeline")

      assert has_element?(view, "#tl-lane-kev-CVE-2026-5001", "Known exploited (KEV cache)")
      assert has_element?(view, "#tl-lanes-kev-note")

      # The other lane has no cached row: absence renders as no marker at all.
      refute has_element?(view, "#tl-lane-kev-CVE-2026-5002")
    end

    test "clicking a lane opens the drawer, which then closes", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/timeline")

      refute has_element?(view, "#tl-drawer")

      view |> element("#tl-lane-open-CVE-2026-5001") |> render_click()
      assert_patch(view, "/timeline?cve=CVE-2026-5001")
      assert has_element?(view, "#tl-drawer")
      assert has_element?(view, "#tl-drawer-events")
      assert has_element?(view, "#tl-drawer-lane")
      assert render(view) =~ "First recorded observation"

      view |> element("#tl-drawer-close") |> render_click()
      assert_patch(view, "/timeline")
      refute has_element?(view, "#tl-drawer")
    end

    test "the drawer also opens from a direct link and includes out-of-window history", %{
      conn: conn
    } do
      image = image!("live-outside")
      finding = finding!(image, "CVE-2026-5099")
      event!(finding, "appeared", at(100))

      {:ok, view, _html} = live(conn, ~p"/timeline?cve=CVE-2026-5099&weeks=4")

      assert has_element?(view, "#tl-drawer")
      assert render(view) =~ "outside the selected window"
      # The finding has no in-window observation, so it is not a lane row.
      refute has_element?(view, "#tl-lane-CVE-2026-5099")
    end

    test "the team filter patches the window and keeps rendering rows", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/timeline")

      view
      |> form("#timeline-form", %{"owner" => "alpha"})
      |> render_change()

      # The form submits every field, so the patched URL states the whole view
      # rather than only the field that changed.
      assert_patch(view, "/timeline?owner=alpha&weeks=12")
      assert has_element?(view, "#tl-lane-CVE-2026-5001")
    end

    test "the window size changes the number of bands", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/timeline")

      assert html
             |> LazyHTML.from_document()
             |> LazyHTML.query("#tl-band-list li.tl-band")
             |> Enum.count() == window_days(12)

      view
      |> form("#timeline-form", %{"weeks" => "4"})
      |> render_change()

      assert_patch(view, "/timeline?weeks=4")

      assert render(view)
             |> LazyHTML.from_document()
             |> LazyHTML.query("#tl-band-list li.tl-band")
             |> Enum.count() == window_days(4)
    end

    test "a scope with no matching placement is empty without claiming a clean estate", %{
      conn: conn
    } do
      {:ok, view, _html} = live(conn, ~p"/timeline?owner=beta")

      assert has_element?(view, "#tl-lanes-empty")
      refute has_element?(view, "#tl-lanes-table")
      assert render(view) =~ "not evidence of a clean estate"
    end

    test "an invalid parameter shows an error state with no rows", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/timeline?weeks=99")

      assert has_element?(view, "#timeline-error")
      refute has_element?(view, "#tl-bands")
      refute has_element?(view, "#tl-summary")
      assert render(view) =~ "Timeline could not be loaded"
    end

    test "a non-numeric window is an error, not a silently different window", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/timeline?weeks=soon")

      assert has_element?(view, "#timeline-error")
      assert render(view) =~ "window"
    end

    test "an unknown CVE reports a drawer error and keeps the timeline usable", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/timeline?cve=CVE-9999-0001")

      assert has_element?(view, "#timeline-detail-error")
      refute has_element?(view, "#tl-drawer")
      assert has_element?(view, "#tl-bands")
      assert render(view) =~ "No finding in the selected scope records that CVE"
    end
  end

  describe "the connected chart" do
    setup do
      image = image!("live-chart")
      placement!(image, "alpha", "prod-cluster-1")

      # Recorded three days apart: the segment between them is a gap, and must
      # be drawn and described as a gap.
      gap = finding!(image, "CVE-2026-5200", package_name: "openssl")
      event!(gap, "appeared", at(6))
      event!(gap, "resolved", at(3))

      # Recorded on adjacent days: a solid segment with an arrowhead.
      solid = finding!(image, "CVE-2026-5201", package_name: "libc", severity: "CRITICAL")
      event!(solid, "appeared", at(2))
      event!(solid, "reopened", at(1))

      # Recorded on one day only: a pin, never a line.
      single = finding!(image, "CVE-2026-5202", package_name: "zlib")
      event!(single, "appeared", at(1, ~T[09:00:00]))

      %{gap: gap, solid: solid, single: single}
    end

    test "draws one track per lane on a labelled axis that marks today", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/timeline")
      document = LazyHTML.from_document(html)

      assert has_element?(view, "#tl-chart svg.tl-chart[aria-hidden='true'][focusable='false']")
      assert has_element?(view, "#tl-chart-scroll.table-region[role='region'][tabindex='0']")

      # One track per lane row, in the lane table's own severity order.
      assert document |> LazyHTML.query("#tl-chart .tl-chart-track") |> Enum.count() == 3

      assert document
             |> LazyHTML.query("#tl-chart .tl-chart-track")
             |> Enum.at(0)
             |> LazyHTML.attribute("id") == ["tl-track-CVE-2026-5201"]

      assert has_element?(view, "#tl-track-CVE-2026-5200")
      assert has_element?(view, "#tl-track-CVE-2026-5202")

      # Fit emphasizes weeks; Daily detail retains every weekday label.
      refute has_element?(view, "#tl-chart .tl-c-weekday")
      {:ok, _, detail_html} = live(conn, ~p"/timeline?scale=detail")

      assert detail_html
             |> LazyHTML.from_document()
             |> LazyHTML.query("#tl-chart .tl-c-weekday")
             |> Enum.count() == window_days(12)

      # Twelve week starts plus the gutter's own CVE label.
      assert document |> LazyHTML.query("#tl-chart .tl-c-week-label") |> Enum.count() == 13
      assert document |> LazyHTML.query("#tl-chart svg.tl-chart .tl-c-today") |> Enum.count() == 1

      # One marker and one description per recorded day, and one arrowhead
      # definition per state, so a state never reuses another state's arrow.
      # Scoped to the chart itself: the legend keys below it reuse these classes.
      assert document |> LazyHTML.query("#tl-chart svg.tl-chart .tl-c-dot") |> Enum.count() == 5

      assert document
             |> LazyHTML.query("#tl-chart svg.tl-chart .tl-c-point title")
             |> Enum.count() == 5

      assert document |> LazyHTML.query("#tl-chart svg.tl-chart marker") |> Enum.count() == 4
    end

    test "joins adjacent recorded days solid, and a gap dashed", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/timeline")
      document = LazyHTML.from_document(html)

      solid =
        document |> LazyHTML.query("#tl-track-CVE-2026-5201 .tl-c-seg-solid") |> Enum.to_list()

      assert length(solid) == 1
      assert LazyHTML.attribute(hd(solid), "marker-end") == ["url(#tl-c-arrow-reopened)"]

      assert element(view, "#tl-track-CVE-2026-5201") |> render() =~
               "adjacent days this CVE is recorded on"

      dashed =
        document |> LazyHTML.query("#tl-track-CVE-2026-5200 .tl-c-seg-dashed") |> Enum.to_list()

      assert length(dashed) == 1
      assert LazyHTML.attribute(hd(dashed), "marker-end") == ["url(#tl-c-arrow-ended)"]

      # The gap segment is described as a gap, not as continuous presence.
      assert element(view, "#tl-track-CVE-2026-5200") |> render() =~
               "the days in between have none recorded"

      # A single recorded day draws a pin and no segment in either direction.
      assert document |> LazyHTML.query("#tl-track-CVE-2026-5202 .tl-c-seg") |> Enum.count() == 0
      assert document |> LazyHTML.query("#tl-track-CVE-2026-5202 .tl-c-pin") |> Enum.count() == 1
    end

    test "the legend states what a line means and what it does not", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/timeline")
      html = render(view)

      assert html =~ "recorded on two adjacent days"
      assert html =~ "recorded at both ends; nothing recorded in between"
      assert html =~ "also recorded before this window starts"
      assert html =~ "today, where the window ends"
      assert html =~ "a single recorded day, so no line is drawn"
      assert html =~ "suppression flag currently set (imported scanner data)"
      assert html =~ "hidden from screen readers"
      assert has_element?(view, "#tl-chart figcaption")

      refute html =~ "Severity chips — current scanner severity"
      refute html =~ "Scanner severity is not assessed impact"
      refute has_element?(view, "#tl-chart .tl-chart-legend-groups .tl-c-key-chip")
    end

    test "a lane recorded before the window starts with an entry tick", %{conn: conn} do
      Triage.DataCase.reset_inventory!()

      image = image!("live-chart-before")
      placement!(image, "alpha", "prod-cluster-1")
      finding = finding!(image, "CVE-2026-5300", first_seen: at(100))
      event!(finding, "appeared", at(1))

      {:ok, view, html} = live(conn, ~p"/timeline")
      document = LazyHTML.from_document(html)

      assert has_element?(view, "#tl-track-CVE-2026-5300 .tl-c-entry")
      assert document |> LazyHTML.query("#tl-track-CVE-2026-5300 .tl-c-seg") |> Enum.count() == 0

      assert element(view, "#tl-track-CVE-2026-5300") |> render() =~
               "Also recorded before this window starts"
    end

    test "the chart is bounded and says what it left to the table", %{conn: conn} do
      Triage.DataCase.reset_inventory!()

      image = image!("live-chart-bound")
      placement!(image, "alpha", "prod-cluster-1")

      for index <- 1..13 do
        cve = "CVE-2026-54" <> String.pad_leading(Integer.to_string(index), 2, "0")

        image
        |> finding!(cve)
        |> event!("appeared", at(1))
      end

      {:ok, view, html} = live(conn, ~p"/timeline")
      document = LazyHTML.from_document(html)

      assert document |> LazyHTML.query("#tl-chart .tl-chart-track") |> Enum.count() == 12
      assert document |> LazyHTML.query("#tl-chart svg.tl-chart .tl-c-dot") |> Enum.count() == 12
      assert render(view) =~ "ranked by current scanner severity"

      # The cap is stated before the chart as well as after it: an operator who
      # stops at the figure must not read the unplotted lanes as quiet ones.
      assert has_element?(view, "#tl-chart-truncation")

      truncation =
        document |> LazyHTML.query("#tl-chart-truncation") |> LazyHTML.text()

      assert truncation =~ "12 of 13 CVEs"
      assert truncation =~ "Unplotted lanes are not quiet lanes"
      assert has_element?(view, "#tl-chart-truncation a[href='#tl-lanes-table']")
      assert has_element?(view, "#tl-chart > .tl-chart-legend-groups")
      refute has_element?(view, "#tl-chart-key .tl-chart-legend-groups")

      assert document
             |> LazyHTML.query("#tl-chart-truncation + .tl-chart-figure")
             |> Enum.count() == 1

      # The bound hides nothing: the table still lists every lane.
      assert has_element?(view, "#tl-lane-CVE-2026-5413")
    end

    test "the scale control changes spacing without changing what is drawn", %{conn: conn} do
      Triage.DataCase.reset_inventory!()

      image = image!("live-chart-scale")
      placement!(image, "alpha", "prod-cluster-1")

      for index <- 1..3 do
        cve = "CVE-2026-55" <> String.pad_leading(Integer.to_string(index), 2, "0")

        image
        |> finding!(cve)
        |> event!("appeared", at(1))
      end

      {:ok, fit_view, fit_html} = live(conn, ~p"/timeline")
      fit = LazyHTML.from_document(fit_html)

      {:ok, detail_view, detail_html} = live(conn, ~p"/timeline?scale=detail")
      detail = LazyHTML.from_document(detail_html)

      # Same lanes and same marks in both modes: the control is a drawing scale,
      # not a filter, so it can never hide an observation.
      for selector <- [
            "#tl-chart .tl-chart-track",
            "#tl-chart svg.tl-chart .tl-c-dot",
            "#tl-chart svg.tl-chart .tl-c-week-label"
          ] do
        assert count(fit, selector) == count(detail, selector),
               "#{selector} differs between fit and detail"
      end

      assert count(fit, "#tl-chart .tl-chart-track") == 3

      # It does change the drawing, and the control says which mode is in force.
      assert svg_width(fit) < svg_width(detail)
      assert has_element?(fit_view, "svg.tl-chart-fit")
      assert has_element?(detail_view, "svg.tl-chart-detail")
      refute has_element?(fit_view, ".tl-c-weekday")
      assert has_element?(detail_view, ".tl-c-weekday")
      assert has_element?(fit_view, "#timeline-form", "Fit window")
      assert has_element?(detail_view, "#timeline-form", "Daily detail")
    end

    test "the scale contract rejects what it does not offer and keeps URLs clean" do
      # The default is the absence of the parameter, so a default view never
      # restates a choice nobody made.
      assert TriageWeb.TimelineFilters.path(TriageWeb.TimelineFilters.defaults()) == "/timeline"

      parsed = TriageWeb.TimelineFilters.parse(%{"scale" => "detail"})
      assert parsed.scale == "detail"
      assert parsed.invalid == []
      assert TriageWeb.TimelineFilters.path(parsed) =~ "scale=detail"

      # An unrecognized value is reported, never silently swapped for one of the
      # offered scales.
      assert TriageWeb.TimelineFilters.parse(%{"scale" => "huge"}).invalid == [:scale]
      assert TriageWeb.TimelineFilters.parse(%{"scale" => "fit"}).scale == "fit"
    end
  end

  describe "recorded assessments and imported state" do
    setup do
      image = image!("live-judged")
      placement!(image, "alpha", "prod-cluster-1")

      judged = finding!(image, "CVE-2026-5100", package_name: "openssl")
      event!(judged, "appeared", at(2))

      suppressed = finding!(image, "CVE-2026-5101", package_name: "zlib", suppressed: true)
      event!(suppressed, "appeared", at(1, ~T[08:00:00]))

      assert {:ok, %{case: review_case, snapshot: snapshot}} =
               Cases.open_case(judged.id, owner: "alpha", environment: "prod-cluster-1")

      assert {:ok, %{review: _review}} =
               Cases.submit_review(
                 review_case.id,
                 review_case.revision,
                 snapshot.id,
                 Ecto.UUID.generate(),
                 review_attrs()
               )

      %{review_case: review_case}
    end

    test "the drawer shows the assessment, its rationale and the actor caveat", %{
      conn: conn,
      review_case: review_case
    } do
      {:ok, view, _html} = live(conn, ~p"/timeline?cve=CVE-2026-5100")
      html = render(view)

      assert has_element?(view, "#tl-case-#{review_case.id}")
      assert html =~ "Assessment recorded"
      assert html =~ "Synthetic fixture assessment."
      assert html =~ "Affected"
      assert html =~ "Normal review"
      assert html =~ "local-operator"
      assert html =~ "not a verified person"

      assert html =~
               "does not approve an exception, suppress a finding, verify a fix or close this CVE"

      assert has_element?(
               view,
               "a#tl-case-open-#{review_case.id}[href='/cases/#{review_case.id}']"
             )

      # The drawer's own advisory link, unscoped here because this visit is.
      assert has_element?(view, "#tl-drawer-advisory[href='/cves/CVE-2026-5100']")

      # Under a scope, the advisory opens on the same team and environment the
      # drawer is describing, and the expectation is built the same way the page
      # builds it so the two cannot drift.
      {:ok, scoped, _html} =
        live(conn, ~p"/timeline?cve=CVE-2026-5100&owner=alpha&environment=prod-cluster-1")

      expected = ~p"/cves/CVE-2026-5100?#{%{owner: "alpha", environment: "prod-cluster-1"}}"
      assert has_element?(scoped, "#tl-drawer-advisory[href='#{expected}']")

      # The same rule on every other advisory link the timeline renders: the lanes
      # table's CVE cell and the bands rows' own "Advisory page" button.
      assert has_element?(scoped, "#tl-lane-cve-CVE-2026-5100[href='#{expected}']")
      assert has_element?(scoped, "[id^='tl-advisory-'][href='#{expected}']")
    end

    test "a suppression flag is described as imported state, not an action", %{conn: conn} do
      {:ok, view, _html} = live(conn, ~p"/timeline?cve=CVE-2026-5101")
      html = render(view)

      assert html =~ "suppression flag currently set from the imported scanner data"
      assert html =~ "no recorded date or author"
      assert html =~ "did not take that action"
    end

    test "an assessment with no in-window observation still counts on its day", %{conn: conn} do
      document = conn |> get(~p"/timeline") |> html_response(200) |> LazyHTML.from_document()
      summary = LazyHTML.query(document, "#tl-summary") |> LazyHTML.text()

      assert summary =~ "Assessments recorded"
      assert summary =~ "1"
    end
  end

  test "an entirely empty inventory renders an honest empty timeline", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/timeline")

    assert has_element?(view, "#tl-bands")
    assert has_element?(view, "#tl-lanes-empty")

    # No lane means no track to draw, so the chart is absent rather than empty.
    refute has_element?(view, "#tl-chart")

    assert render(view) =~ "No recorded observation on this day"
    assert render(view) =~ "not evidence of a clean estate"
  end

  # The days after today that the current week's grid column still renders. The
  # list is empty on a Sunday, when today closes its own week.
  defp future_days_in_current_week do
    today = today()

    today
    |> Date.beginning_of_week(:monday)
    |> Date.range(Date.add(today, 7 - Date.day_of_week(today)))
    |> Enum.filter(&(Date.compare(&1, today) == :gt))
  end
end
