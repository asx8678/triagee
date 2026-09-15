defmodule TriageWeb.TriageLiveTest do
  @moduledoc """
  End-to-end tests for the Triage page: lanes, per-scope work items, the exact
  filter complement, and the visible invalid-filter state.
  """
  use TriageWeb.ConnCase, async: false

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

  test "the shown count leads and the unpaged total is scoped to local inventory", %{conn: conn} do
    critical!("counts-intake", "CVE-2026-7101")

    {:ok, view, html} = live(conn, ~p"/triage")
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

    {:ok, view, html} = live(conn, ~p"/triage")
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

    {:ok, view, _html} = live(conn, ~p"/triage")

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

    {:ok, view, _} = live(conn, ~p"/triage?filter=all")
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

    {:ok, view, html} = live(conn, ~p"/triage")
    document = LazyHTML.from_document(html)

    assert has_element?(view, "#nav-triage[aria-current='page']")
    assert has_element?(view, "#triage-lane-intake")
    refute has_element?(view, "#triage-lane-applicability")
    refute has_element?(view, "#triage-lane-decision")
    refute has_element?(view, "#triage-lane-handled")
    assert has_element?(view, "#triage-scopes-CVE-2026-7001")

    assert text(document, "#triage-state-CVE-2026-7001") =~ "Not assessed"
    assert text(document, "#triage-coverage-CVE-2026-7001") =~ "0 of 1 scope assessed"

    # The only place a case can be opened is the finding page, so an unassessed
    # scope links there rather than pretending a case exists.
    assert document
           |> LazyHTML.query("#triage-open-#{finding.id}[href='/findings/#{finding.id}']")
           |> Enum.count() == 1

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

    {:ok, view, html} = live(conn, ~p"/triage")
    document = LazyHTML.from_document(html)

    assert has_element?(view, "#triage-lane-applicability")
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

  test "recording a decision through the form moves the advisory into the decision lane", %{
    conn: conn
  } do
    critical!("live-decision", "CVE-2026-7006")

    {:ok, view, _html} = live(conn, ~p"/triage")
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
    assert render(view) =~ "Accepted risk recorded for CVE-2026-7006"

    {:ok, whitelisted_view, _html} = live(conn, ~p"/triage?filter=whitelisted")
    assert has_element?(whitelisted_view, "#triage-lane-decision")
    whitelisted = LazyHTML.from_document(render(whitelisted_view))

    assert text(whitelisted, "#triage-state-CVE-2026-7006") =~ "Covered by a decision"
    assert text(whitelisted, "#triage-decision-count") =~ "1"
    assert text(whitelisted, "#triage-decision-CVE-2026-7006") =~ "Accepted risk"
    assert text(whitelisted, "#triage-decision-CVE-2026-7006") =~ "live-operator"
    assert text(whitelisted, "#triage-decision-CVE-2026-7006") =~ "active"

    # A decision removes the advisory from the work list, never from the
    # inventory: the all-critical view still shows it, in the decision lane.
    {:ok, all_view, _html} = live(conn, ~p"/triage?filter=all")
    assert has_element?(all_view, "#triage-lane-decision")

    # The finding itself is untouched: only this work list changed.
    assert [row] = Decisions.history_for_cve("CVE-2026-7006")
    assert row.actor == "live-operator"
  end

  test "a refused decision explains itself and records nothing", %{conn: conn} do
    critical!("live-decision-refused", "CVE-2026-7007")

    {:ok, view, _html} = live(conn, ~p"/triage")

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

    {:ok, view, _html} = live(conn, ~p"/triage")

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

    {:ok, view, _html} = live(conn, ~p"/triage")

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

    {:ok, view, html} = live(conn, ~p"/triage")
    document = LazyHTML.from_document(html)

    assert has_element?(view, "#triage-impact-#{finding.id}")
    assert text(document, "#triage-impact-#{finding.id}") =~ "impact: High"
    assert text(document, "#triage-impact-#{finding.id}") =~ "live:operator declared"
    assert text(document, "#triage-impact-count") =~ "1"
  end

  test "a placement with no impact evidence says so rather than implying none", %{conn: conn} do
    finding = critical!("live-no-impact-evidence", "CVE-2026-7011")

    {:ok, view, html} = live(conn, ~p"/triage")
    document = LazyHTML.from_document(html)

    refute has_element?(view, "#triage-impact-#{finding.id}")

    assert text(document, "#triage-scope-CVE-2026-7011-alpha-prod-cluster-1-#{finding.id}") =~
             "Impact not recorded"
  end
end
