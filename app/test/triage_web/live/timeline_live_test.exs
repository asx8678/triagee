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

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  describe "a window with recorded observations" do
    setup do
      image = image!("live-bands")
      placement!(image, "alpha", "prod-cluster-1")

      # Recorded yesterday and today: renders with a connector in both directions.
      continuing = finding!(image, "CVE-2026-5001", package_name: "openssl")
      event!(continuing, "appeared", at(1, ~T[07:00:00]))
      event!(continuing, "reopened", at(0, ~T[07:00:00]))

      # Recorded only today, and critical.
      single = finding!(image, "CVE-2026-5002", package_name: "libc", severity: "CRITICAL")
      event!(single, "appeared", at(0, ~T[09:00:00]))

      %{continuing: continuing, single: single}
    end

    test "renders the bands, the grid, the summary, the lanes and the tab", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/timeline")
      document = LazyHTML.from_document(html)

      assert has_element?(view, "#nav-timeline[aria-current='page']")
      assert has_element?(view, "#tl-summary")
      assert has_element?(view, "#tl-bands")
      assert has_element?(view, "#tl-lanes-table")
      assert has_element?(view, "#tl-grid-table")

      # One band per day of the window: empty days are rendered explicitly.
      assert document |> LazyHTML.query("#tl-band-list > li") |> Enum.count() == 56

      # The grid is a real table with a caption and one row per weekday.
      assert document |> LazyHTML.query("#tl-grid-table caption") |> Enum.count() == 1

      assert document |> LazyHTML.query("#tl-grid-table tbody tr") |> Enum.count() == 7

      for weekday <- ~w(Mon Tue Wed Thu Fri Sat Sun) do
        assert has_element?(view, "#tl-grid-#{weekday}")
      end
    end

    test "the newest band is today, and an empty day says so", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/timeline")
      document = LazyHTML.from_document(html)

      first_band = document |> LazyHTML.query("#tl-band-list > li") |> Enum.at(0)
      assert LazyHTML.attribute(first_band, "id") == ["tl-band-#{Date.to_iso8601(today())}"]

      assert has_element?(view, "#tl-band-#{Date.to_iso8601(today())}.tl-band-observed")

      empty_date = Date.add(today(), -2) |> Date.to_iso8601()
      assert has_element?(view, "#tl-band-#{empty_date}.tl-band-empty")
      assert has_element?(view, "#tl-band-empty-#{empty_date}")
      assert render(view) =~ "An empty day is not a clean day"
    end

    test "a CVE recorded on adjacent days is joined by connectors", %{
      conn: conn,
      continuing: continuing,
      single: single
    } do
      {:ok, view, _html} = live(conn, ~p"/timeline")
      today_key = "#tl-row-#{continuing.id}-#{Date.to_iso8601(today())}"
      older_key = "#tl-row-#{continuing.id}-#{Date.to_iso8601(Date.add(today(), -1))}"

      assert has_element?(view, "#{today_key} .tl-connector-down")
      assert has_element?(view, "#{older_key} .tl-connector-up")

      # The glyph is decorative and has a text equivalent in the same row.
      assert has_element?(view, "#{today_key} .tl-arrow[aria-hidden='true']")
      assert has_element?(view, "#{today_key} .sr-only")
      assert element(view, today_key) |> render() =~ "observed again locally"

      # A CVE recorded only today has no connector in either direction.
      single_key = "#tl-row-#{single.id}-#{Date.to_iso8601(today())}"
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
      assert_patch(view, "/timeline?owner=alpha&weeks=8")
      assert has_element?(view, "#tl-lane-CVE-2026-5001")
    end

    test "the window size changes the number of bands", %{conn: conn} do
      {:ok, view, html} = live(conn, ~p"/timeline")

      assert html
             |> LazyHTML.from_document()
             |> LazyHTML.query("#tl-band-list > li")
             |> Enum.count() == 56

      view
      |> form("#timeline-form", %{"weeks" => "4"})
      |> render_change()

      assert_patch(view, "/timeline?weeks=4")

      assert render(view)
             |> LazyHTML.from_document()
             |> LazyHTML.query("#tl-band-list > li")
             |> Enum.count() == 28
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
    assert render(view) =~ "No recorded observation on this day"
    assert render(view) =~ "not evidence of a clean estate"
  end
end
