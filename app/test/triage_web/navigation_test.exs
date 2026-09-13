defmodule TriageWeb.NavigationTest do
  use TriageWeb.ConnCase, async: true

  @links [
    {"home", "/"},
    {"findings", "/findings"},
    {"cases", "/cases"},
    {"whats-new", "/whats-new"},
    {"replay", "/replay"},
    {"replay-history", "/replay/history"},
    {"imports", "/imports"}
  ]

  # Read-only mounts: no seed or fixture writes are needed for navigation.
  for {active, path} <- @links do
    test "#{path} has one complete primary navigation", %{conn: conn} do
      document = conn |> get(unquote(path)) |> html_response(200) |> LazyHTML.from_document()
      assert_navigation(document, unquote(active))
    end
  end

  test "detail error states retain their section navigation", %{conn: conn} do
    for {path, active} <- [
          {"/findings/1?owner[]=invalid", "findings"},
          {"/cases/invalid", "cases"}
        ] do
      {:ok, view, html} = live(conn, path)
      assert has_element?(view, "#nav-#{active}[aria-current='page']")
      assert_navigation(LazyHTML.from_document(html), active)
    end
  end

  defp assert_navigation(document, active) do
    assert document |> LazyHTML.query("a[href='#main-content']") |> Enum.count() == 1
    assert document |> LazyHTML.query("main#main-content[tabindex='-1']") |> Enum.count() == 1
    assert document |> LazyHTML.query("nav[aria-label='Primary']") |> Enum.count() == 1
    assert document |> LazyHTML.query("#primary-navigation a") |> Enum.count() == 7
    assert LazyHTML.query(document, "#nav-home") |> LazyHTML.text() |> String.trim() == "Overview"

    assert LazyHTML.query(document, "#nav-whats-new") |> LazyHTML.text() |> String.trim() ==
             "Activity"

    assert document |> LazyHTML.query("#navigation-menu > summary") |> Enum.count() == 1
    assert document |> LazyHTML.query("#environment-notice") |> Enum.count() == 1

    assert document
           |> LazyHTML.query(
             "#connection-notice[hidden][role='status'][phx-disconnected][phx-connected]"
           )
           |> Enum.count() == 1

    assert LazyHTML.query(document, "#safety-details") |> LazyHTML.text() =~ "access control"

    assert LazyHTML.query(document, "#environment-notice") |> LazyHTML.text() =~
             "Production coverage is unknown"

    assert document |> LazyHTML.query("#primary-navigation [aria-current='page']") |> Enum.count() ==
             1

    assert document |> LazyHTML.query("#nav-#{active}[aria-current='page']") |> Enum.count() == 1

    for {key, path} <- @links do
      assert document |> LazyHTML.query("#nav-#{key}[href='#{path}']") |> Enum.count() == 1
    end
  end
end
