defmodule TriageWeb.FindingLive.PagingTest do
  @moduledoc """
  Regressions for the bounded findings list: one slice per request, the
  positions carried into the slice links, the whole-list walk through those
  links, the visible past-the-end state, and the visible invalid-position
  state.
  """

  use TriageWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Triage.Inventory
  alias Triage.Inventory.GroupCursor
  alias Triage.Seeds

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

  test "the list renders the newest slice and says what it is showing", %{conn: conn} do
    total = Inventory.count_groups([])
    assert total > @per_page, "fixture must span more than one slice"

    {:ok, _view, html} = live(conn, ~p"/findings?sort=cve")

    assert row_ids(html) ==
             Inventory.list_groups(sort: "cve", limit: @per_page) |> Enum.map(&"group-#{&1.cve}")

    status = LazyHTML.text(LazyHTML.query(LazyHTML.from_document(html), "#findings-page-status"))
    summary = LazyHTML.text(LazyHTML.query(LazyHTML.from_document(html), "#findings-summary"))

    assert status =~ "Showing #{@per_page} in this slice"
    assert status =~ "newest slice"
    assert status =~ "#{@per_page} per page"

    # The matching total is stated exactly once, next to the filters that produce
    # it; the slice status describes position only, so the two cannot disagree.
    assert summary =~ "#{total} matching advisories"
    refute status =~ "matching advisories"

    assert html =~ "older-advisories"
    refute html =~ "newest-advisories"
  end

  test "a slice link carries the filters, the order and the position", %{conn: conn} do
    scoped = Inventory.count_groups(owner: "alpha", severity: "HIGH")
    assert div(scoped + @per_page - 1, @per_page) > 1, "fixture must span more than one slice"

    {:ok, view, _html} = live(conn, ~p"/findings?owner=alpha&severity=HIGH&sort=cve")
    first_slice = row_ids(render(view))
    assert first_slice != []

    href = link_href(view, "#older-advisories")
    assert href =~ "owner=alpha"
    assert href =~ "severity=HIGH"
    assert href =~ "sort=cve"
    assert href =~ "before="

    view |> element("#older-advisories") |> render_click()

    assert row_ids(render(view)) != first_slice
    assert render(view) =~ "newest-advisories"
    assert render(view) =~ "later slice"
  end

  test "removing a filter preserves other choices and resets only the page position", %{
    conn: conn
  } do
    {:ok, view, _} = live(conn, ~p"/findings?owner=alpha&severity=HIGH&sort=cve&suppressed=1")
    view |> element("#older-advisories") |> render_click()
    assert has_element?(view, "#newest-advisories")
    assert has_element?(view, "#findings-active-sort", "Advisory id (A–Z)")

    view
    |> element("#active-filters a[aria-label='Remove filter: Severity High']")
    |> render_click()

    assert_patch(view, ~p"/findings?owner=alpha&sort=cve&suppressed=1")
    refute has_element?(view, "#newest-advisories")
    refute has_element?(view, "#active-filters a[aria-label='Remove filter: Severity High']")
    assert has_element?(view, "#active-filters a[aria-label='Remove filter: Team alpha']")

    assert has_element?(
             view,
             "#active-filters a[aria-label='Remove filter: Suppressed included']"
           )

    view |> element("#reset-findings") |> render_click()
    assert_patch(view, ~p"/findings")
    refute has_element?(view, "#active-filters")
  end

  test "aggregate and occurrence links retain the full paginated list context", %{conn: conn} do
    {:ok, view, _} = live(conn, ~p"/findings?owner=alpha&severity=HIGH&sort=cve&suppressed=1")
    view |> element("#older-advisories") |> render_click()

    aggregate = link_href(view, "#groups > tr:first-child th > a[href^='/cves/']")
    occurrence = link_href(view, "#groups > tr:first-child a[aria-label^='View occurrence']")
    assert URI.parse(aggregate).path =~ "/cves/"
    assert URI.parse(occurrence).path =~ "/findings/"
    assert URI.parse(aggregate).query == URI.parse(occurrence).query
    query = URI.decode_query(URI.parse(aggregate).query)
    assert query["owner"] == "alpha"
    assert query["severity"] == "HIGH"
    assert query["sort"] == "cve"
    assert query["suppressed"] == "1"
    assert query["before"] != nil

    {:ok, detail, _} = live(conn, aggregate)
    back = link_href(detail, "#cve-back-to-list")
    assert URI.decode_query(URI.parse(back).query) == query
  end

  test "following only the positions it hands out walks the whole list exactly once", %{
    conn: conn
  } do
    total = Inventory.count_groups(owner: "alpha")
    assert total > @per_page, "fixture must span more than one slice"

    # The bound keeps a repeated position from looping forever: a broken walk
    # fails the comparison below instead of hanging.
    bound = div(total, @per_page) + 2

    {:ok, view, _html} = live(conn, ~p"/findings?owner=alpha&sort=cve")

    walked =
      Enum.reduce_while(1..bound, [], fn _slice, acc ->
        current = row_ids(render(view))

        if has_element?(view, "#older-advisories") do
          view |> element("#older-advisories") |> render_click()
          {:cont, acc ++ current}
        else
          {:halt, acc ++ current}
        end
      end)

    assert walked ==
             Inventory.list_groups(owner: "alpha", sort: "cve") |> Enum.map(&"group-#{&1.cve}")

    assert walked == Enum.uniq(walked)
  end

  test "the default order and the newest slice stay out of the links", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings?sort=severity")

    href = link_href(view, "#older-advisories")

    assert href =~ "before="
    refute href =~ "sort="
  end

  test "a position past the end is a visible notice, not an empty estate", %{conn: conn} do
    encoded =
      Inventory.list_groups(sort: "cve")
      |> List.last()
      |> then(&GroupCursor.encode("cve", &1))

    {:ok, view, html} = live(conn, ~p"/findings?#{%{sort: "cve", before: encoded}}")

    assert has_element?(view, "#findings-beyond-end")
    refute html =~ "findings-empty"
    assert row_ids(html) == []

    assert LazyHTML.text(LazyHTML.query(LazyHTML.from_document(html), "#findings-beyond-end")) =~
             "past the end"
  end

  test "a malformed position is a visible invalid filter, never a guessed slice", %{conn: conn} do
    for bad <- ["nonsense", "4~12", "04~12~CVE-x", "5~12~CVE-x", "4~12~ CVE-x"] do
      {:ok, view, html} = live(conn, ~p"/findings?#{%{before: bad}}")

      assert has_element?(view, "#invalid-filters")
      assert row_ids(html) == []
      refute html =~ "findings-summary"
      refute html =~ "older-advisories"
    end
  end

  test "the list shows the order it is actually sorted by", %{conn: conn} do
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

  test "changing the order keeps the scope and starts from the newest slice", %{conn: conn} do
    # A real position for the default order, so dropping it is observable: the
    # changed order must not carry the old one.
    encoded =
      GroupCursor.encode("severity", %{severity_rank: 4, images: 1, cve: "CVE-2098-80011"})

    {:ok, view, _html} = live(conn, ~p"/findings?#{%{owner: "alpha", before: encoded}}")

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

    assert html =~ "alpha"
    refute html =~ "newest-advisories"

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

  defp link_href(view, selector) do
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
            # Uniform severity so a severity-filtered scope also spans slices;
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
