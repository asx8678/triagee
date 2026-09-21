defmodule TriageWeb.TimelineReadabilityTest do
  @moduledoc """
  Honesty and structure assertions for the read-only CVE timeline.

  These tests guard the wording, not the styling: a recorded observation must
  never be presented as remediation, an imported suppression flag must never be
  presented as a local action, and a picture must never be the only carrier of
  meaning.
  """
  use TriageWeb.LegacyUICase, async: false

  import Triage.Fixtures

  setup do
    Triage.DataCase.reset_inventory!()

    image = image!("readable")
    placement!(image, "alpha", "prod-cluster-1")

    resolving = finding!(image, "CVE-2026-6001", package_name: "openssl", resolved_at: at(1))
    event!(resolving, "appeared", at(3))
    event!(resolving, "resolved", at(1))

    suppressed = finding!(image, "CVE-2026-6002", package_name: "zlib", suppressed: true)
    event!(suppressed, "appeared", at(2, ~T[08:00:00]))

    %{}
  end

  test "states what a recorded observation is, and what it is not", %{conn: conn} do
    document = conn |> get(~p"/timeline") |> html_response(200) |> LazyHTML.from_document()
    text = LazyHTML.text(document)

    for required <- [
          "recorded observation",
          "not remediation",
          "no recorded date or author",
          "local-operator",
          "not a clean day",
          "Newest day first"
        ] do
      assert text =~ required, "expected the timeline to state #{inspect(required)}"
    end
  end

  test "never claims a result the records cannot support", %{conn: conn} do
    html = conn |> get(~p"/timeline") |> html_response(200)
    text = html |> LazyHTML.from_document() |> LazyHTML.text()

    for forbidden <- [
          "was remediated",
          "remediation complete",
          "fix applied",
          "verified fixed",
          "added to the whitelist",
          "whitelisted by",
          "has been approved",
          "approved by",
          "scan completed at",
          "last scanned",
          "no risk remains",
          "estate is clean"
        ] do
      refute text =~ forbidden, "the timeline must not claim #{inspect(forbidden)}"
    end
  end

  test "a disappearance is described as an observation, not a fix", %{conn: conn} do
    text =
      conn
      |> get(~p"/timeline")
      |> html_response(200)
      |> LazyHTML.from_document()
      |> LazyHTML.text()

    assert text =~ "no longer observed in local inventory"
    assert text =~ "Currently no longer observed in local inventory"
  end

  test "suppression is labelled as imported scanner state", %{conn: conn} do
    text =
      conn
      |> get(~p"/timeline")
      |> html_response(200)
      |> LazyHTML.from_document()
      |> LazyHTML.text()

    assert text =~ "suppression flag currently set from the imported scanner data"

    # The detail view states the missing provenance rather than inventing it.
    drawer =
      conn
      |> get(~p"/timeline?cve=CVE-2026-6002")
      |> html_response(200)
      |> LazyHTML.from_document()
      |> LazyHTML.text()

    assert drawer =~ "Suppressed on 1 occurrence(s) as reported by the imported scanner data"
    assert drawer =~ "records no suppression date or author and did not take that action"
  end

  test "every arrow has a text equivalent and connectors are decorative", %{conn: conn} do
    document = conn |> get(~p"/timeline") |> html_response(200) |> LazyHTML.from_document()

    arrows =
      LazyHTML.query(document, "#tl-bands .tl-row .tl-arrow[aria-hidden='true']") |> Enum.count()

    equivalents = LazyHTML.query(document, "#tl-bands .tl-row .sr-only") |> Enum.count()

    assert arrows > 0
    assert arrows == equivalents

    for connector <- LazyHTML.query(document, "#tl-bands .tl-connector") do
      assert LazyHTML.attribute(connector, "aria-hidden") == ["true"]
    end
  end

  test "the grid is a labelled table whose future cells are marked", %{conn: conn} do
    document = conn |> get(~p"/timeline") |> html_response(200) |> LazyHTML.from_document()

    assert document |> LazyHTML.query("table#tl-grid-table") |> Enum.count() == 1
    assert document |> LazyHTML.query("#tl-grid-table caption") |> Enum.count() == 1

    assert document
           |> LazyHTML.query("#tl-grid-table thead th[scope='col']")
           |> Enum.count() == 13

    assert document
           |> LazyHTML.query("#tl-grid-table tbody th[scope='row']")
           |> Enum.count() == 7

    # Future days are rendered as explicitly not yet observed.
    for cell <- LazyHTML.query(document, "#tl-grid-table td.tl-cell-future") do
      assert cell |> LazyHTML.text() =~ "not yet observed"
    end

    assert LazyHTML.text(document) =~ "not evidence that no vulnerable image existed"
  end

  test "the empty-day and empty-window states avoid a clean-estate claim", %{conn: conn} do
    text =
      conn
      |> get(~p"/timeline")
      |> html_response(200)
      |> LazyHTML.from_document()
      |> LazyHTML.text()

    assert text =~ "An empty day is not a clean day"

    Triage.DataCase.reset_inventory!()

    empty =
      conn
      |> get(~p"/timeline")
      |> html_response(200)
      |> LazyHTML.from_document()
      |> LazyHTML.text()

    assert empty =~ "An empty window is not evidence of a clean estate"
    assert empty =~ "No recorded observation on this day"
  end

  test "the connected chart is decorative and every meaning is in text too", %{conn: conn} do
    document = conn |> get(~p"/timeline") |> html_response(200) |> LazyHTML.from_document()

    svg = LazyHTML.query(document, "#tl-chart svg.tl-chart")
    assert Enum.count(svg) == 1
    assert svg |> Enum.at(0) |> LazyHTML.attribute("aria-hidden") == ["true"]
    assert svg |> Enum.at(0) |> LazyHTML.attribute("focusable") == ["false"]

    text = document |> LazyHTML.text() |> String.replace(~r/\s+/, " ")

    # The current status chart replaced observation-only connectors. Preserve
    # textual equivalents for every status/color and explicit evidence limits.
    for required <- [
          "Red dots record detection",
          "black line behind them carries the open state",
          "a red dot at the window edge",
          "Black dots record a whitelist decision",
          "grey line behind the black dot",
          "Green dots record disappearance, not a verified fix",
          "hidden from screen readers"
        ] do
      assert text =~ required, "expected the chart legend to state #{inspect(required)}"
    end

    assert text =~ "Lines show recorded status, not verified continuous exposure."
    assert text =~ "Missing observations do not prove safety or continuous exposure."
  end

  test "the lane table labels its scope and its counts", %{conn: conn} do
    document = conn |> get(~p"/timeline") |> html_response(200) |> LazyHTML.from_document()

    assert document
           |> LazyHTML.query("#tl-lanes-table #tl-lane-CVE-2026-6001 th[scope='row']")
           |> Enum.count() == 1

    assert document
           |> LazyHTML.query("#tl-lanes-table thead th[scope='col']")
           |> Enum.count() == 6

    assert LazyHTML.text(document) =~ "not necessarily the whole CVE"
    assert LazyHTML.text(document) =~ "not a verified repair"
  end

  test "the page names the local operator identity it actually has", %{conn: conn} do
    text =
      conn
      |> get(~p"/timeline")
      |> html_response(200)
      |> LazyHTML.from_document()
      |> LazyHTML.text()

    assert text =~ "unauthenticated"
    assert text =~ "local-operator"
  end
end
