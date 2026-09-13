defmodule TriageWeb.FindingLive.PagingTest do
  @moduledoc """
  Regressions for the bounded findings list: the page size, the filters, order
  and page number carried into page links, the clamped page-past-the-end state,
  and the visible invalid-page filter state.
  """

  use TriageWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Triage.{Inventory, Seeds}

  # Mirrors FindingLive.Index @per_page. Pinned deliberately: the page size is a
  # user-visible contract, so changing it must fail this suite.
  @per_page 25
  @now ~U[2026-09-10 12:00:00Z]

  setup do
    Triage.DataCase.reset_inventory!()
    :ok = Seeds.seed()
    :ok = add_advisories!(27)
    :ok
  end

  test "the list renders one page of groups and says which page it is", %{conn: conn} do
    total = Inventory.count_groups([])
    pages = div(total + @per_page - 1, @per_page)
    assert pages > 1, "fixture must span more than one page"

    {:ok, _view, html} = live(conn, ~p"/findings?sort=cve")

    assert row_ids(html) ==
             Inventory.list_groups(sort: "cve", limit: @per_page) |> Enum.map(&"group-#{&1.cve}")

    assert LazyHTML.text(LazyHTML.query(LazyHTML.from_document(html), "#findings-page-status")) =~
             "Page 1 of #{pages}"

    assert html =~ "Showing 1–#{@per_page} of #{total} matching advisories"

    refute html =~ "findings-page-prev"
    assert html =~ "findings-page-next"
  end

  test "a page link carries the filters, the order and the page number", %{conn: conn} do
    scoped = Inventory.count_groups(owner: "alpha", severity: "HIGH")
    assert div(scoped + @per_page - 1, @per_page) > 1, "fixture must span more than one page"

    {:ok, view, _html} = live(conn, ~p"/findings?owner=alpha&severity=HIGH&sort=cve")
    first_page = row_ids(render(view))
    assert first_page != []

    href = page_link_href(view, "#findings-page-next")
    assert href =~ "owner=alpha"
    assert href =~ "severity=HIGH"
    assert href =~ "sort=cve"
    assert href =~ "page=2"

    view |> element("#findings-page-next") |> render_click()

    assert render(view) =~ "Page 2 of"
    assert row_ids(render(view)) != first_page
    assert render(view) =~ "findings-page-prev"
  end

  test "the default order and the first page stay out of the links", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings?sort=severity&page=1")

    href = page_link_href(view, "#findings-page-next")

    assert href =~ "page=2"
    refute href =~ "sort="
  end

  test "a page past the end renders the last page instead of an empty table", %{conn: conn} do
    total = Inventory.count_groups([])
    pages = div(total + @per_page - 1, @per_page)
    last_page_rows = total - (pages - 1) * @per_page

    {:ok, _view, html} = live(conn, ~p"/findings?sort=cve&page=9999")

    assert html =~ "Page #{pages} of #{pages}"
    assert length(row_ids(html)) == last_page_rows

    assert row_ids(html) ==
             Inventory.list_groups(sort: "cve", limit: @per_page, offset: (pages - 1) * @per_page)
             |> Enum.map(&"group-#{&1.cve}")

    assert html =~ "findings-page-prev"
    refute html =~ "findings-page-next"
  end

  test "an out-of-range or malformed page is a visible invalid filter", %{conn: conn} do
    for bad <- ["0", "-3", "2.5", "abc", "1000000"] do
      {:ok, view, html} = live(conn, ~p"/findings?page=#{bad}")

      assert has_element?(view, "#invalid-filters")

      assert LazyHTML.text(LazyHTML.query(LazyHTML.from_document(html), "#invalid-filters")) =~
               "page"

      assert row_ids(html) == []
      refute html =~ "findings-summary"
      refute html =~ "findings-page-next"
    end
  end

  test "the page shows the order it is actually sorted by", %{conn: conn} do
    {:ok, _view, newest_html} = live(conn, ~p"/findings?sort=newest")

    assert newest_html =~ "Newest first observed"
    assert newest_html =~ "Sorted by first local observation"
    refute newest_html =~ "Sorted by highest scanner severity"

    assert row_ids(newest_html) ==
             Inventory.list_groups(sort: "newest", limit: @per_page)
             |> Enum.map(&"group-#{&1.cve}")

    {:ok, _view, severity_html} = live(conn, ~p"/findings")

    assert severity_html =~ "Sorted by highest scanner severity"
    assert severity_html =~ "affected image count"
  end

  test "the sort control offers exactly the published orders and reflects the URL", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/findings?sort=newest")
    document = LazyHTML.from_document(html)

    values =
      document
      |> LazyHTML.query("#filter-form select[name='sort'] option")
      |> LazyHTML.attribute("value")

    assert values == Inventory.group_sorts()

    assert document
           |> LazyHTML.query("#filter-form select[name='sort'] option[selected]")
           |> LazyHTML.attribute("value") == ["newest"]
  end

  test "changing the order keeps the scope and starts from the first page", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings?owner=alpha&page=2")

    view
    |> element("#filter-form")
    |> render_change(%{
      "owner" => "alpha",
      "environment" => "",
      "q" => "",
      "severity" => "",
      "suppressed" => false,
      "sort" => "cve"
    })

    html = render(view)

    assert html =~ "Page 1 of"
    assert html =~ "alpha"

    assert row_ids(html) ==
             Inventory.list_groups(owner: "alpha", sort: "cve", limit: @per_page)
             |> Enum.map(&"group-#{&1.cve}")
  end

  defp row_ids(html) do
    html
    |> LazyHTML.from_document()
    |> LazyHTML.query("#groups tr")
    |> LazyHTML.attribute("id")
  end

  defp page_link_href(view, selector) do
    view
    |> element(selector)
    |> render()
    |> LazyHTML.from_document()
    |> LazyHTML.query("a")
    |> LazyHTML.attribute("href")
    |> List.first()
  end

  defp add_advisories!(count) do
    {:ok, image} =
      Inventory.upsert_image(
        %{
          digest: "sha256:" <> String.duplicate("f", 64),
          repository: "registry.internal/findings-paging",
          tag: "1.0",
          description: "Fixture for the bounded findings list"
        },
        @now
      )

    {:ok, _placement} =
      Inventory.upsert_placement(
        image,
        %{namespace: "web", owner: "alpha", environment: "prod-cluster-1"},
        @now
      )

    for n <- 1..count do
      {:ok, _finding} =
        Inventory.upsert_finding(
          image,
          %{
            cve: "CVE-2098-8001#{n}",
            package_name: "findings-paging-package-#{n}",
            package_version: "1.#{n}",
            # Uniform severity so a severity-filtered scope also spans pages;
            # severity variety is covered by the inventory paging suite.
            severity: "HIGH",
            fix: nil,
            description: "Findings paging fixture #{n}",
            suppressed: false
          },
          DateTime.add(@now, n, :minute),
          reopen: false
        )
    end

    :ok
  end
end
