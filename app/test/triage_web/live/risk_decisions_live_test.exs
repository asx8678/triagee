defmodule TriageWeb.RiskDecisionsLiveTest do
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :viewer
  import Phoenix.LiveViewTest
  import Triage.Fixtures
  alias Triage.{Decisions, Repo}

  setup do
    Triage.DataCase.reset_inventory!()
    image = image!("risk-register")
    prod = placement!(image, "alpha", "prod")
    stage = placement!(image, "alpha", "staging")
    beta = placement!(image, "beta", "prod")
    a = finding!(image, "CVE-2099-7777")
    b = finding!(image, "CVE-2099-7778")
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    first = approval!(a.cve, prod, now, 30, "shared-approval")
    second = approval!(a.cve, stage, now, 30, "shared-approval")
    expired = approval!(b.cve, beta, now, -2, "expired-approval")
    %{cve: a.cve, other: b.cve, first: first, second: second, expired: expired}
  end

  test "grouped cards keep complete reasons, exact deployment records and expiry meaning", c do
    {:ok, view, _} = live(c.conn, "/?page=exceptions")
    assert has_element?(view, "#exceptions-count", "2 decisions")
    assert has_element?(view, "#exceptions-count", "3 underlying records")
    assert has_element?(view, "#risk-decision-list > li:nth-child(2)")
    refute has_element?(view, "#risk-decision-list > li:nth-child(3)")
    assert has_element?(view, "#exception-#{c.first.id}", "2 deployments")
    assert has_element?(view, "#risk-record-#{c.first.id}", "alpha · prod")
    assert has_element?(view, "#risk-record-#{c.second.id}", "alpha · staging")

    assert has_element?(
             view,
             "#risk-details-#{c.first.id} .risk-full-reason",
             "<script>not markup</script>"
           )

    refute has_element?(view, "#exceptions-register script")
    assert has_element?(view, ".risk-status-expired")
    assert has_element?(view, "#risk-decisions-expiry-help", "Older decisions are retained")
    assert Repo.aggregate(Decisions.Decision, :count) == 3
  end

  test "expiry cards, search and clear controls update results without writing decisions", c do
    {:ok, view, _} = live(c.conn, "/?page=exceptions")
    view |> element("#risk-status-expired") |> render_click()
    assert has_element?(view, "#risk-status-expired[aria-current=true]")
    assert has_element?(view, "#exception-#{c.expired.id}")
    refute has_element?(view, "#exception-#{c.first.id}")

    view
    |> form("#risk-decision-filters", risk_filters: %{risk_q: "cannot-match-any-record"})
    |> render_change()

    assert has_element?(view, "#exceptions-empty", "No decisions match")
    view |> element("#risk-clear-filters") |> render_click()
    assert has_element?(view, "#risk-status-all[aria-current=true]")
    assert has_element?(view, "#exception-#{c.first.id}")
    assert Repo.aggregate(Decisions.Decision, :count) == 3
  end

  test "filters persist in URLs and Review receives only the explicitly selected risk scope", c do
    {:ok, view, _} = live(c.conn, "/?page=exceptions&team=hidden-old-scope")

    view
    |> form("#risk-decision-filters",
      risk_filters: %{risk_team: "alpha", risk_environment: "staging"}
    )
    |> render_change()

    assert has_element?(view, "#exception-#{c.second.id}", "1 deployment")
    assert has_element?(view, "#workspace-history-scope", "alpha · staging")
    refute has_element?(view, "#exception-#{c.expired.id}")
    view |> element("#risk-review-#{c.second.id}") |> render_click()
    assert_patch(view, "/?environment=staging&item=#{c.cve}&page=review&team=alpha")
    assert has_element?(view, ".review-heading h2", c.cve)
    assert Repo.aggregate(Decisions.Decision, :count) == 3
  end

  test "global history links never accidentally inherit an unrelated previous Review scope", c do
    {:ok, view, _} = live(c.conn, "/?page=exceptions&team=hidden-old-scope&environment=dev")
    view |> element("#risk-review-#{c.first.id}") |> render_click()
    assert_patch(view, "/?item=#{c.cve}&page=review")
    assert has_element?(view, ".review-heading h2", c.cve)
  end

  test "unknown URL scopes remain visible and do not widen the result set", c do
    {:ok, view, _} = live(c.conn, "/?page=exceptions&risk_team=missing-team")
    assert has_element?(view, "#risk_filters_risk_team option[value=missing-team][selected]")
    assert has_element?(view, "#exceptions-empty")
    refute has_element?(view, "#risk-decision-list")
  end

  test "malformed filter events do not crash the page or widen its scope", c do
    {:ok, view, _} = live(c.conn, "/?page=exceptions&risk_team=alpha")
    render_hook(view, "risk-filter", %{"risk_filters" => %{"risk_team" => ["beta"]}})
    render_hook(view, "risk-filter", %{"risk_filters" => []})
    assert has_element?(view, "#risk_filters_risk_team option[value=alpha][selected]")
    assert has_element?(view, "#exception-#{c.first.id}")
    refute has_element?(view, "#exception-#{c.expired.id}")
  end

  defp approval!(cve, placement, now, expiry_days, operation) do
    {:ok, decision} =
      Decisions.record(%{
        cve: cve,
        placement_id: placement.id,
        decision: "accepted_risk",
        actor: "reviewer@example.test",
        reason: "Scheduled patch rollout. <script>not markup</script>",
        decided_at: DateTime.add(now, -10, :day),
        expires_at: DateTime.add(now, expiry_days, :day),
        operation_id: operation,
        metadata: %{
          "expiry_boundary" => "exclusive",
          "target" => %{
            "team" => placement.owner,
            "environment" => placement.environment,
            "namespace" => placement.namespace
          }
        }
      })

    decision
  end
end
