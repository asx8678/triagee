defmodule TriageWeb.OverviewReadabilityTest do
  use TriageWeb.LegacyUICase

  test "homepage is the searchable vulnerability workspace, not dashboard previews", %{conn: conn} do
    {:ok, view, _} = live(conn, "/")
    assert has_element?(view, "h1", "Vulnerabilities")
    assert has_element?(view, "#filter-form")
    assert has_element?(view, "#inventory-totals")
    assert has_element?(view, "select[name='sort'] option[value='severity'][selected]")
    refute has_element?(view, "#home-active-list")
    refute has_element?(view, "#home-workflows")
    assert has_element?(view, "#nav-findings[aria-current='page']")
  end

  test "filters are quiet by default but visible for active or invalid input", %{conn: conn} do
    {:ok, view, _} = live(conn, "/")
    assert has_element?(view, "#inventory-filters:not([open])")
    assert has_element?(view, "#inventory-search-details:not([open])")

    for query <- ["severity=HIGH", "sort=cve", "owner[]=invalid"] do
      {:ok, filtered, _} = live(conn, "/?" <> query)
      assert has_element?(filtered, "#inventory-filters[open]")
    end
  end

  test "old inventory bookmark still opens the same workspace", %{conn: conn} do
    {:ok, view, _} = live(conn, "/findings")
    assert has_element?(view, "h1", "Vulnerabilities")
    assert has_element?(view, "#filter-form")
  end

  test "invalid homepage filters fail visibly rather than claiming an empty estate", %{conn: conn} do
    {:ok, view, _} = live(conn, "/?owner[]=invalid")
    assert has_element?(view, "#invalid-filters")
    refute has_element?(view, "#triage-empty")
  end
end
