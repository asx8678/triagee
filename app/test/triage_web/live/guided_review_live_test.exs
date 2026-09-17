defmodule TriageWeb.GuidedReviewLiveTest do
  use TriageWeb.ConnCase, async: false
  import Phoenix.LiveViewTest
  import Triage.Fixtures
  alias Triage.{GuidedReview, Repo}

  setup do
    Triage.DataCase.reset_inventory!()
    Repo.delete_all(GuidedReview.Request)
    image = image!("guided")
    placement!(image, "alpha", "prod")

    finding =
      finding!(image, "CVE-2024-3094",
        severity: "HIGH",
        description: "Malicious code in xz releases."
      )

    %{finding: finding}
  end

  test "action-only queue uses full-width compact rows and guided CTA for noncritical CVEs", %{
    conn: conn
  } do
    {:ok, view, _} = live(conn, "/triage")
    assert has_element?(view, "h1", "Action required")
    assert has_element?(view, "#action-CVE-2024-3094", "Malicious code")
    refute has_element?(view, "#action-queue table")
    refute has_element?(view, "#action-queue .review-card")
    assert has_element?(view, ".review-queue-compact > #action-CVE-2024-3094.review-queue-row")
    assert has_element?(view, "#action-CVE-2024-3094 .review-row-teams", "alpha")
    assert has_element?(view, "#action-CVE-2024-3094 .review-row-libraries", "libssl")
    assert has_element?(view, "#triage-issue-CVE-2024-3094[href='/triage/CVE-2024-3094']")
  end

  test "review polish labels the queue and guides each next step", %{conn: conn} do
    {:ok, queue, _} = live(conn, "/triage")
    assert has_element?(queue, "h2", "1 CVE needs action")
    assert has_element?(queue, ".review-queue-heading", "Libraries")
    assert has_element?(queue, ".review-row-priority.review-priority-high", "HIGH")
    assert has_element?(queue, ".review-row-teams[data-label='Teams']", "alpha")

    {:ok, view, _} = live(conn, "/triage/CVE-2024-3094")
    assert has_element?(view, "#review-progress", "Step 1 of 4")
    assert has_element?(view, "#review-next", "Next: teams & exposure")
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#review-progress", "Step 2 of 4")
    assert has_element?(view, ".review-steps .is-previous", "Understand CVE")
    assert has_element?(view, ".review-steps [aria-current='step']", "Teams & exposure")
    assert has_element?(view, "#review-next", "Next: risk & AI advice")
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#review-next", "Next: take action")
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#review-progress", "Step 4 of 4")
    refute has_element?(view, "#review-next")
    assert Repo.aggregate(GuidedReview.Request, :count) == 0
  end

  test "timeline CVE links open guided review only while action is required", %{
    conn: conn,
    finding: finding
  } do
    event!(finding, "appeared", at(3))
    {:ok, timeline, _} = live(conn, "/timeline?cve=CVE-2024-3094")

    for selector <- ["#tl-chart", "#tl-lanes-table", "#tl-bands", "#tl-drawer-title"] do
      assert has_element?(
               timeline,
               "#{selector} a[href='/triage/CVE-2024-3094']",
               "CVE-2024-3094"
             )
    end

    assert {:error, {:live_redirect, %{to: "/triage/CVE-2024-3094"}}} =
             timeline
             |> element("#tl-lane-CVE-2024-3094 a[href='/triage/CVE-2024-3094']")
             |> render_click()

    {:ok, review, _} = live(conn, "/triage/CVE-2024-3094")
    assert has_element?(review, "#review-step-1", "Malicious code")

    expiry = Date.utc_today() |> Date.add(5) |> Date.to_iso8601()
    assert {:ok, _} = GuidedReview.whitelist(finding.cve, "Temporary accepted risk", expiry)
    {:ok, covered, _} = live(conn, "/timeline?cve=CVE-2024-3094")

    for selector <- ["#tl-chart", "#tl-lanes-table", "#tl-bands", "#tl-drawer-title"] do
      refute has_element?(covered, "#{selector} a[href='/triage/CVE-2024-3094']")
      assert has_element?(covered, "#{selector} a[href='/cves/CVE-2024-3094']", "CVE-2024-3094")
    end
  end

  test "four steps, unknown exposure, unavailable integrations and local fix plan", %{conn: conn} do
    {:ok, view, _} = live(conn, "/triage/CVE-2024-3094")
    assert has_element?(view, "#review-step-1", "Malicious code")
    render_click(view, "plan_fix")
    assert Repo.aggregate(GuidedReview.Request, :count) == 0
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#review-step-2", "alpha")
    assert has_element?(view, "#review-step-2", "Exposure unknown")
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#ai-unconfigured")
    assert has_element?(view, "#review-step-3", "not a CVSS score")
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#azure-unconfigured")
    assert has_element?(view, "#confirm-team-tickets[disabled]")
    view |> element("#mark-for-fix") |> render_click()
    assert has_element?(view, "#team-ticket-results", "planned")
    assert Repo.aggregate(GuidedReview.Request, :count) == 1
  end

  test "whitelist requires reason and expiry and leaves actionable queue", %{conn: conn} do
    {:ok, view, _} = live(conn, "/triage/CVE-2024-3094")
    for _ <- 1..3, do: render_click(view, "next")

    view
    |> form("#guided-whitelist-form", decision: %{reason: "", expires_on: ""})
    |> render_submit()

    assert has_element?(view, "#guided-error")
    expiry = Date.utc_today() |> Date.add(5) |> Date.to_iso8601()

    view
    |> form("#guided-whitelist-form",
      decision: %{reason: "Temporary accepted risk", expires_on: expiry}
    )
    |> render_submit()

    assert_redirect(view, "/triage")
    assert GuidedReview.queue() == []
  end
end
