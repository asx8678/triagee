defmodule TriageWeb.TriageLiveTest do
  @moduledoc """
  End-to-end tests for the Triage page: lanes, per-scope work items, the exact
  filter complement, and the visible invalid-filter state.
  """
  use TriageWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import Triage.Fixtures

  alias Triage.Cases

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  defp critical!(name, cve) do
    image = image!(name)
    placement!(image, "alpha", "prod-cluster-1")
    finding!(image, cve, severity: "CRITICAL", package_name: "openssl")
  end

  # The idempotency token is server-generated in the product, so the test uses a
  # real UUID, and the current revision comes from the submit result.
  defp assess!(finding, attrs) do
    {:ok, %{case: cse, snapshot: snapshot}} =
      Cases.open_case(finding.id, owner: "alpha", environment: "prod-cluster-1")

    {:ok, %{case: submitted}} =
      Cases.submit_review(cse.id, cse.revision, snapshot.id, Ecto.UUID.generate(), attrs)

    submitted
  end

  defp text(document, selector), do: document |> LazyHTML.query(selector) |> LazyHTML.text()

  test "an unassessed critical advisory appears in the intake lane", %{conn: conn} do
    finding = critical!("live-intake", "CVE-2026-7001")

    {:ok, view, html} = live(conn, ~p"/triage")
    document = LazyHTML.from_document(html)

    assert has_element?(view, "#nav-triage[aria-current='page']")
    assert has_element?(view, "#triage-lane-intake")
    refute has_element?(view, "#triage-lane-impact")
    refute has_element?(view, "#triage-lane-handled")
    assert has_element?(view, "#triage-scopes-CVE-2026-7001")

    assert text(document, "#triage-state-CVE-2026-7001") =~ "Not assessed"
    assert text(document, "#triage-coverage-CVE-2026-7001") =~ "0 of 1 scope assessed"

    # The only place a case can be opened is the finding page, so an unassessed
    # scope links there rather than pretending a case exists.
    assert document
           |> LazyHTML.query("#triage-open-#{finding.id}[href='/findings/#{finding.id}']")
           |> Enum.count() == 1
  end

  test "a current affected review moves the advisory to the impact lane and links its case",
       %{conn: conn} do
    finding = critical!("live-impact", "CVE-2026-7002")
    cse = assess!(finding, review_attrs())

    {:ok, view, html} = live(conn, ~p"/triage")
    document = LazyHTML.from_document(html)

    assert has_element?(view, "#triage-lane-impact")
    refute has_element?(view, "#triage-lane-intake")
    assert text(document, "#triage-state-CVE-2026-7002") =~ "affected"
    assert text(document, "#triage-coverage-CVE-2026-7002") =~ "1 of 1 scope assessed"
    assert text(document, "#triage-scope-count") =~ "1 of 1"

    assert document
           |> LazyHTML.query("#triage-case-#{finding.id}[href='/cases/#{cse.id}']")
           |> Enum.count() == 1
  end

  test "the handled filter is the exact complement of the active filter", %{conn: conn} do
    finding = critical!("live-handled", "CVE-2026-7003")
    attrs = Map.put(review_attrs(), "applicability", "not_affected_with_evidence")
    assess!(finding, attrs)

    {:ok, active_view, _html} = live(conn, ~p"/triage")
    assert has_element?(active_view, "#triage-empty")

    {:ok, handled_view, handled_html} = live(conn, ~p"/triage?filter=handled")
    assert has_element?(handled_view, "#triage-lane-handled")

    assert text(LazyHTML.from_document(handled_html), "#triage-state-CVE-2026-7003") =~
             "Not affected"

    {:ok, _all_view, all_html} = live(conn, ~p"/triage?filter=all")

    assert LazyHTML.from_document(all_html)
           |> LazyHTML.query("#triage-lane-handled")
           |> Enum.count() == 1
  end

  test "an invalid filter is a visible error, never a silent default", %{conn: conn} do
    critical!("live-invalid", "CVE-2026-7004")

    {:ok, view, _html} = live(conn, ~p"/triage?filter=bogus")

    assert has_element?(view, "#triage-invalid-filter")
    refute has_element?(view, "#triage-lane-intake")
    refute has_element?(view, "#triage-empty")
    assert render(view) =~ "never assumed or swapped for a default"
  end

  test "choosing a filter patches the URL instead of reposting the page", %{conn: conn} do
    critical!("live-patch", "CVE-2026-7005")

    {:ok, view, _html} = live(conn, ~p"/triage")

    view
    |> form("#triage-filter-form", %{"filter" => "handled"})
    |> render_change()

    assert_patch(view, ~p"/triage?filter=handled")
    assert has_element?(view, "#triage-lane-handled") == false
  end
end
