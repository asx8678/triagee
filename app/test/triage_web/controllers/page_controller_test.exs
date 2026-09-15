defmodule TriageWeb.PageControllerTest do
  use TriageWeb.ConnCase

  test "GET / presents the local Triage overview and every workflow", %{conn: conn} do
    document = conn |> get(~p"/") |> html_response(200) |> LazyHTML.from_document()

    assert LazyHTML.query(document, "title") |> LazyHTML.text() == "Overview · Triage"
    assert LazyHTML.query(document, "#home-title") |> LazyHTML.text() == "Overview"

    assert LazyHTML.query(document, "#environment-notice") |> LazyHTML.text() =~
             "Live collection is disabled"

    # The workflow links live in the persistent top navigation; the overview
    # itself carries no page header.
    for {key, path} <- [
          {"triage", "/triage"},
          {"findings", "/findings"},
          {"timeline", "/timeline"},
          {"replay", "/replay"},
          {"imports", "/imports"},
          {"intel", "/intel"}
        ] do
      assert document |> LazyHTML.query("#nav-#{key}[href='#{path}']") |> Enum.count() == 1
    end

    assert document |> LazyHTML.query("#home-workflows .triage-action-card") |> Enum.count() == 0

    # The overview is a posture dashboard: no search form and no page header,
    # because every workflow is one click away in the top navigation.
    assert LazyHTML.query(document, "#overview-search") |> Enum.count() == 0
    assert LazyHTML.query(document, "#home-workflows") |> Enum.count() == 0
    assert LazyHTML.query(document, ".page-header") |> Enum.count() == 0

    assert document |> LazyHTML.query("#environment-notice") |> Enum.count() == 1
    assert document |> LazyHTML.query("#overview-counts") |> Enum.count() == 1
    assert document |> LazyHTML.query("nav[aria-label='Primary']") |> Enum.count() == 1
    assert document |> LazyHTML.query("#nav-home[aria-current='page']") |> Enum.count() == 1

    assert document |> LazyHTML.query("img[src='/images/triage-wordmark-v2.png']") |> Enum.count() ==
             1

    assert document |> LazyHTML.query("a[href^='https://']") |> Enum.count() == 0
    refute LazyHTML.query(document, "body") |> LazyHTML.text() =~ "Peace of mind from prototype"
    refute LazyHTML.query(document, "h1") |> LazyHTML.text() =~ "Phoenix Framework"
  end
end
