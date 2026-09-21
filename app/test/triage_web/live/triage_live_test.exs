defmodule TriageWeb.TriageLiveTest do
  @moduledoc """
  End-to-end tests for the Triage page: lanes, per-scope work items, the exact
  filter complement, and the visible invalid-filter state.
  """
  use TriageWeb.LegacyUICase, async: false

  import Ecto.Query
  import Phoenix.LiveViewTest
  import Triage.Fixtures

  alias Triage.{Cases, Decisions, Impact}

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

  test "multiple scopes require a named choice and review navigation does not create a case", %{
    conn: conn
  } do
    image = image!("scope-choices")
    placement!(image, "alpha", "prod-cluster-1")
    placement!(image, "beta", "staging")
    finding = finding!(image, "CVE-2026-7199", severity: "CRITICAL")

    {:ok, view, html} = live(conn, ~p"/triage/history")

    assert has_element?(
             view,
             "details#triage-scopes-CVE-2026-7199 > summary",
             "Team reviews (2)"
           )

    refute has_element?(view, "details#triage-scopes-CVE-2026-7199[open]")
    links = html |> LazyHTML.from_document() |> LazyHTML.query(".triage-scope-action")
    assert Enum.count(links) == 2
    assert links |> LazyHTML.attribute("id") |> Enum.uniq() |> length() == 2

    target =
      Enum.find(
        LazyHTML.attribute(links, "href"),
        &(URI.decode_query(URI.parse(&1).query)["owner"] == "beta")
      )

    assert URI.parse(target).path == "/findings/#{finding.id}"

    assert URI.decode_query(URI.parse(target).query) == %{
             "owner" => "beta",
             "environment" => "staging"
           }

    {:ok, scoped, _} =
      view
      |> element(".triage-scope-action[href='#{target}']")
      |> render_click()
      |> follow_redirect(conn)

    assert has_element?(scoped, "#open-case-btn", "Open case for beta · staging")
    assert Triage.Repo.aggregate(Triage.Cases.ReviewCase, :count) == 0
  end

  test "the shown count leads and the unpaged total is scoped to local inventory", %{conn: conn} do
    critical!("counts-intake", "CVE-2026-7101")

    {:ok, view, html} = live(conn, ~p"/triage/history")
    document = LazyHTML.from_document(html)

    # The primary number is the work in front of the operator, named with the
    # filter that produced it.
    assert text(document, "#triage-summary") =~ "1 advisory shown"
    assert text(document, "#triage-summary") =~ "filter: active"

    # The estate-wide number is still stated, but as an explicitly unpaged total
    # on its own footnote rather than as a peer of a lane count.
    note = text(document, "#triage-counts-note")
    assert note =~ "Local inventory"
    assert note =~ "unpaged"
    assert text(document, "#triage-cve-count") =~ "1"

    # The strip is a breakdown of the shown rows, and now says so.
    assert has_element?(view, "dl[aria-label='Shown advisories by assessment state']")
  end

  test "the reading definitions sit behind a disclosure, not in front of the rows", %{conn: conn} do
    critical!("defs-intake", "CVE-2026-7102")

    {:ok, view, html} = live(conn, ~p"/triage/history")
    document = LazyHTML.from_document(html)

    # The gate that decides whether a row belongs here stays visible.
    assert text(document, "#triage-banner") =~ "Critical and active only"

    # The definitions are available on request, and the disclosure is a real
    # <details>, so it works without JavaScript and is keyboard operable.
    assert has_element?(view, "details#triage-banner-details > summary")
    assert text(document, "#triage-banner-details") =~ "opening a case is not an assessment"
  end

  test "a compacted row keeps every count as its own labelled field", %{conn: conn} do
    critical!("row-intake", "CVE-2026-7103")

    {:ok, view, _html} = live(conn, ~p"/triage/history")

    # Packing three counts onto two lines is a presentation change only: each
    # count keeps its own hook, so nothing became unaddressable.
    assert has_element?(view, "#triage-row-CVE-2026-7103 [data-field='packages']", "1 package")
    assert has_element?(view, "#triage-row-CVE-2026-7103 [data-field='images']", "1 image")

    assert has_element?(
             view,
             "#triage-row-CVE-2026-7103 [data-field='occurrences']",
             "1 occurrence"
           )

    assert has_element?(view, "#triage-row-CVE-2026-7103 [data-field='teams']", "1 team")
  end

  test "mixed lanes render each advisory exactly once across filter patches", %{conn: conn} do
    critical!("mixed-intake", "CVE-2026-7090")
    affected = critical!("mixed-affected", "CVE-2026-7091")
    assess!(affected, review_attrs())

    {:ok, view, _} = live(conn, ~p"/triage/history?filter=all")
    assert has_element?(view, "#triage-lane-intake #triage-row-CVE-2026-7090")
    assert has_element?(view, "#triage-lane-applicability #triage-row-CVE-2026-7091")
    refute has_element?(view, "#triage-lane-intake #triage-row-CVE-2026-7091")
    refute has_element?(view, "#triage-lane-applicability #triage-row-CVE-2026-7090")

    assert render(view)
           |> LazyHTML.from_document()
           |> LazyHTML.query("tr[id^='triage-row-']")
           |> Enum.count() == 2

    view |> form("#triage-filter-form", %{"filter" => "handled"}) |> render_change()
    refute has_element?(view, "tr[id^='triage-row-']")
    view |> form("#triage-filter-form", %{"filter" => "all"}) |> render_change()
    assert has_element?(view, "#triage-lane-intake #triage-row-CVE-2026-7090")
    assert has_element?(view, "#triage-lane-applicability #triage-row-CVE-2026-7091")
  end

  test "an unassessed critical advisory appears in the intake lane", %{conn: conn} do
    finding = critical!("live-intake", "CVE-2026-7001")

    {:ok, view, html} = live(conn, ~p"/triage/history")
    document = LazyHTML.from_document(html)

    assert has_element?(view, "#nav-triage[aria-current='page']")
    assert has_element?(view, "#triage-lane-intake")
    refute has_element?(view, "#triage-lane-applicability")
    refute has_element?(view, "#triage-lane-decision")
    refute has_element?(view, "#triage-lane-handled")
    assert has_element?(view, "#triage-scopes-CVE-2026-7001")

    assert text(document, "#triage-state-CVE-2026-7001") =~ "Needs review"
    refute html =~ "Not assessed"

    assert has_element?(
             view,
             "#history-triage-CVE-2026-7001[href='/triage/CVE-2026-7001']",
             "Triage issue"
           )

    assert has_element?(
             view,
             ".review-history-table .review-coverage-details > summary",
             "Review progress"
           )

    refute has_element?(view, ".review-coverage-details[open]")
    refute has_element?(view, ".triage-scope-evidence[open]")
    assert text(document, "#triage-coverage-CVE-2026-7001") =~ "0 of 1 scope assessed"

    # The only place a case can be opened is the finding page, so an unassessed
    # scope links there rather than pretending a case exists.
    action = LazyHTML.query(document, ".triage-scope-action[data-finding-id='#{finding.id}']")

    [href] = LazyHTML.attribute(action, "href")
    assert URI.parse(href).path == "/findings/#{finding.id}"

    assert URI.decode_query(URI.parse(href).query) == %{
             "owner" => "alpha",
             "environment" => "prod-cluster-1"
           }

    assert LazyHTML.text(action) =~ "Review scope"
    assert [label] = LazyHTML.attribute(action, "aria-label")
    assert String.starts_with?(label, "Review scope for alpha / prod-cluster-1")
    assert has_element?(view, "div#triage-scopes-CVE-2026-7001 .triage-scope-action")
    refute has_element?(view, "details#triage-scopes-CVE-2026-7001")

    # The CVE id is itself the link to the detail page; a second "Deep dive"
    # link beside it named a destination that was already named.
    assert document
           |> LazyHTML.query("#triage-cve-CVE-2026-7001[href='/cves/CVE-2026-7001']")
           |> Enum.count() == 1

    assert document |> LazyHTML.query("#triage-cve-CVE-2026-7001 a") |> Enum.count() == 0

    # An assessment state is a workflow state, so it never borrows the severity
    # ramp's dashes and fill.
    assert document
           |> LazyHTML.query("#triage-state-CVE-2026-7001 .status-badge-state")
           |> Enum.count() == 1
  end

  test "a current affected review moves the advisory to the applicability lane and links its case",
       %{conn: conn} do
    finding = critical!("live-impact", "CVE-2026-7002")
    cse = assess!(finding, review_attrs())

    {:ok, view, html} = live(conn, ~p"/triage/history")
    document = LazyHTML.from_document(html)

    assert has_element?(view, "#triage-lane-applicability")
    refute has_element?(view, "#triage-lane-intake")
    assert text(document, "#triage-state-CVE-2026-7002") =~ "affected"
    assert text(document, "#triage-coverage-CVE-2026-7002") =~ "1 of 1 scope assessed"
    assert text(document, "#triage-scope-count") =~ "1 of 1"

    action = LazyHTML.query(document, ".triage-scope-action[data-finding-id='#{finding.id}']")

    [href] = LazyHTML.attribute(action, "href")
    assert URI.parse(href).path == "/cases/#{cse.id}"

    assert URI.decode_query(URI.parse(href).query) == %{
             "owner" => "alpha",
             "environment" => "prod-cluster-1"
           }

    assert LazyHTML.text(action) =~ "Review case"
  end

  test "the handled filter is the exact complement of the active filter", %{conn: conn} do
    finding = critical!("live-handled", "CVE-2026-7003")
    attrs = Map.put(review_attrs(), "applicability", "not_affected_with_evidence")
    assess!(finding, attrs)

    {:ok, active_view, _html} = live(conn, ~p"/triage/history")
    assert has_element?(active_view, "#triage-empty", "Nothing to review — all done!")
    assert has_element?(active_view, "#triage-empty img[src='/images/review-complete.svg'][alt]")

    assert has_element?(
             active_view,
             "#triage-empty",
             "does not mean your inventory has no vulnerabilities"
           )

    {:ok, handled_view, handled_html} = live(conn, ~p"/triage/history?filter=handled")
    assert has_element?(handled_view, "#triage-lane-handled")

    assert text(LazyHTML.from_document(handled_html), "#triage-state-CVE-2026-7003") =~
             "Not affected"

    {:ok, _all_view, all_html} = live(conn, ~p"/triage/history?filter=all")

    assert LazyHTML.from_document(all_html)
           |> LazyHTML.query("#triage-lane-handled")
           |> Enum.count() == 1
  end

  test "an invalid filter is a visible error, never a silent default", %{conn: conn} do
    critical!("live-invalid", "CVE-2026-7004")

    {:ok, view, _html} = live(conn, ~p"/triage/history?filter=bogus")

    assert has_element?(view, "#triage-invalid-filter")
    refute has_element?(view, "#triage-lane-intake")
    refute has_element?(view, "#triage-empty")
    assert render(view) =~ "never assumed or swapped for a default"
  end

  test "choosing a filter patches the URL instead of reposting the page", %{conn: conn} do
    critical!("live-patch", "CVE-2026-7005")

    {:ok, view, _html} = live(conn, ~p"/triage/history")

    view
    |> form("#triage-filter-form", %{"filter" => "handled"})
    |> render_change()

    assert_patch(view, ~p"/triage/history?filter=handled")
    assert has_element?(view, "#triage-lane-handled") == false
  end

  test "recording a decision through the form moves the advisory into the decision lane", %{
    conn: conn
  } do
    critical!("live-decision", "CVE-2026-7006")

    {:ok, view, _html} = live(conn, ~p"/triage/history")
    assert has_element?(view, "#triage-lane-intake")
    assert has_element?(view, "#triage-decision-form")

    view
    |> form("#triage-decision-form",
      record: %{
        "cve" => "CVE-2026-7006",
        "decision" => "accepted_risk",
        "reason" => "Synthetic live acceptance with an end date.",
        "expires_on" => Date.to_iso8601(Date.add(Date.utc_today(), 30)),
        "actor" => "live-operator"
      }
    )
    |> render_submit()

    # The advisory leaves the active work list, so the default filter no longer
    # shows it at all — and the flash says where it went instead of leaving the
    # operator to guess.
    refute has_element?(view, "#triage-lane-intake")
    refute has_element?(view, "#triage-lane-decision")
    assert render(view) =~ "Whitelisted recorded for CVE-2026-7006"

    {:ok, whitelisted_view, _html} = live(conn, ~p"/triage/history?filter=whitelisted")
    assert has_element?(whitelisted_view, "#triage-lane-decision")
    whitelisted = LazyHTML.from_document(render(whitelisted_view))

    assert text(whitelisted, "#triage-state-CVE-2026-7006") =~ "Covered by a decision"
    assert text(whitelisted, "#triage-decision-count") =~ "1"
    assert text(whitelisted, "#triage-decision-CVE-2026-7006") =~ "Whitelisted"
    assert text(whitelisted, "#triage-decision-CVE-2026-7006") =~ "live-operator"
    assert text(whitelisted, "#triage-decision-CVE-2026-7006") =~ "active"

    # A decision removes the advisory from the work list, never from the
    # inventory: the all-critical view still shows it, in the decision lane.
    {:ok, all_view, _html} = live(conn, ~p"/triage/history?filter=all")
    assert has_element?(all_view, "#triage-lane-decision")

    # The finding itself is untouched: only this work list changed.
    assert [row] = Decisions.history_for_cve("CVE-2026-7006")
    assert row.actor == "live-operator"
  end

  test "a refused decision explains itself and records nothing", %{conn: conn} do
    critical!("live-decision-refused", "CVE-2026-7007")

    {:ok, view, _html} = live(conn, ~p"/triage/history")

    view
    |> form("#triage-decision-form",
      record: %{
        "cve" => "CVE-2026-7007",
        "decision" => "accepted_risk",
        "reason" => "No end date on purpose.",
        "expires_on" => "",
        "actor" => "live-operator"
      }
    )
    |> render_submit()

    assert has_element?(view, "#triage-decision-errors")
    assert render(view) =~ "is required for accepted risk"
    # Still open work, and nothing was written.
    assert has_element?(view, "#triage-lane-intake")
    assert Decisions.history_for_cve("CVE-2026-7007") == []
  end

  test "an unparseable expiry is refused instead of recorded as no expiry", %{conn: conn} do
    critical!("live-decision-bad-date", "CVE-2026-7008")

    {:ok, view, _html} = live(conn, ~p"/triage/history")

    view
    |> form("#triage-decision-form",
      record: %{
        "cve" => "CVE-2026-7008",
        "decision" => "accepted_risk",
        "reason" => "Synthetic decision with a broken date.",
        "expires_on" => "next tuesday",
        "actor" => "live-operator"
      }
    )
    |> render_submit()

    assert render(view) =~ "Nothing was recorded"
    assert Decisions.history_for_cve("CVE-2026-7008") == []
  end

  test "a decision for an absent advisory is refused visibly", %{conn: conn} do
    critical!("live-decision-unknown", "CVE-2026-7009")

    {:ok, view, _html} = live(conn, ~p"/triage/history")

    view
    |> form("#triage-decision-form",
      record: %{
        "cve" => "CVE-1999-0001",
        "decision" => "not_affected",
        "reason" => "Synthetic decision for an advisory nothing recorded.",
        "expires_on" => "",
        "actor" => "live-operator"
      }
    )
    |> render_submit()

    assert render(view) =~ "no finding in this inventory carries that CVE"
    assert Decisions.history_for_cve("CVE-1999-0001") == []
  end

  test "impact evidence for a placement is shown on its work item", %{conn: conn} do
    finding = critical!("live-impact-evidence", "CVE-2026-7010")

    placement =
      Triage.Repo.one(
        from(p in Triage.Inventory.ImagePlacement, where: p.image_id == ^finding.image_id)
      )

    assert {:ok, _} =
             Impact.record(placement.id, "high", "live:operator declared", DateTime.utc_now())

    {:ok, view, html} = live(conn, ~p"/triage/history")
    document = LazyHTML.from_document(html)

    assert has_element?(view, ".triage-scope-impact[data-finding-id='#{finding.id}']")

    assert text(document, ".triage-scope-impact[data-finding-id='#{finding.id}']") =~
             "impact: High"

    assert text(document, ".triage-scope-impact[data-finding-id='#{finding.id}']") =~
             "live:operator declared"

    assert text(document, "#triage-impact-count") =~ "1"
  end

  test "a placement with no impact evidence says so rather than implying none", %{conn: conn} do
    finding = critical!("live-no-impact-evidence", "CVE-2026-7011")

    {:ok, view, html} = live(conn, ~p"/triage/history")
    document = LazyHTML.from_document(html)

    refute has_element?(view, ".triage-scope-impact[data-finding-id='#{finding.id}']")

    assert text(document, "#triage-scope-CVE-2026-7011-alpha-prod-cluster-1-#{finding.id}") =~
             "Impact not recorded"
  end
end
