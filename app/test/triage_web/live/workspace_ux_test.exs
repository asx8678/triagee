defmodule TriageWeb.WorkspaceUXTest do
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :reviewer
  import Triage.Fixtures
  alias Triage.{Decisions, Repo}

  setup do
    Triage.DataCase.reset_inventory!()
    image = image!("workspace-ux")
    prod = placement!(image, "alpha", "prod")
    staging = placement!(image, "alpha", "staging")
    first = finding!(image, "CVE-2099-7711", severity: "CRITICAL", fix: "2.17.1")
    second = finding!(image, "CVE-2099-7712", severity: "HIGH")
    %{prod: prod, staging: staging, first: first, second: second}
  end

  test "search submits without reloading and clearing filters keeps deployment scope", c do
    {:ok, view, _} = live(c.conn, "/?page=inventory&team=alpha&environment=prod")

    view
    |> form("#workspace-search", search: %{q: c.first.cve, severity: "CRITICAL", sort: "age"})
    |> render_submit()

    query = view |> assert_patch() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["team"] == "alpha"
    assert query["environment"] == "prod"
    assert query["q"] == c.first.cve
    assert has_element?(view, "#inventory-#{c.first.cve}")
    refute has_element?(view, "#inventory-#{c.second.cve}")
    view |> element("#clear-inventory-filters") |> render_click()
    query = view |> assert_patch() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["team"] == "alpha"
    assert query["environment"] == "prod"
    refute Map.has_key?(query, "q")
    refute Map.has_key?(query, "severity")
    assert has_element?(view, "#inventory-#{c.second.cve}")
    refute has_element?(view, "#clear-inventory-filters")
  end

  test "row density exposes its current state", c do
    {:ok, view, _} = live(c.conn, "/?page=inventory")
    assert has_element?(view, "#inventory-density[aria-pressed=false]", "Compact rows")
    view |> element("#inventory-density") |> render_click()
    assert has_element?(view, "#shell.compact")
    assert has_element?(view, "#inventory-density[aria-pressed=true]", "Comfortable rows")
    view |> element("#inventory-density") |> render_click()
    refute has_element?(view, "#shell.compact")
  end

  test "no targets disables submission and explains how to continue", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.first.cve}")

    # Fresh draft: no action and no write targets selected (I05).
    assert has_element?(view, "#save-decision[disabled]", "Select an action")
    assert has_element?(view, "#decision-no-targets", "Select deployments to continue")
    assert has_element?(view, "#cancel-decision[disabled]")

    # Targets alone are not enough: the action must also be chosen explicitly.
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    assert has_element?(view, "#save-decision[disabled]")
    view |> form("#workspace-decision", decision: %{action: "fixed"}) |> render_change()
    assert has_element?(view, "#save-decision:not([disabled])")
    assert has_element?(view, "#cancel-decision:not([disabled])")

    # Deselecting every target disables submission again.
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    assert has_element?(view, "#decision-no-targets", "Select deployments to continue")
    assert has_element?(view, "#save-decision[disabled]")
    view |> element("#cancel-decision") |> render_click()
    assert has_element?(view, "#decision-no-targets")
    assert has_element?(view, "#save-decision[disabled]")
    assert has_element?(view, "#cancel-decision[disabled]")
    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "selection guidance is neutral and counts use deployment grammar", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.first.cve}")

    assert has_element?(
             view,
             "#decision-no-targets.decision-guidance",
             "Select deployments to continue"
           )

    refute has_element?(view, "#decision-no-targets.form-error")
    refute has_element?(view, "#workspace-decision [aria-invalid=true]")
    assert has_element?(view, ".decision-head", "0 deployments selected")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    assert has_element?(view, ".decision-head", "1 deployment selected")
    refute has_element?(view, "#decision-no-targets")
    view |> element("#scope-target-#{c.staging.id}") |> render_click()
    assert has_element?(view, ".decision-head", "2 deployments selected")

    assert has_element?(
             view,
             "#scope-target-#{c.prod.id}[aria-label='Select alpha prod deployment #{c.prod.id}']"
           )
  end

  test "server validation exposes field errors and requests keyboard recovery", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.first.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> form("#workspace-decision", decision: %{action: "accepted_risk"}) |> render_change()
    assert has_element?(view, "#workspace-decision[phx-hook=WorkspaceValidation]")
    assert has_element?(view, "#decision_reason[required]")
    view |> form("#workspace-decision", decision: %{reason: "   "}) |> render_submit()

    assert has_element?(
             view,
             "#decision_reason[aria-invalid=true][aria-errormessage=decision_reason-errors]"
           )

    assert has_element?(view, "#decision-error[role=alert]", "highlighted fields")
    assert_push_event(view, "workspace-validation-failed", %{})
    refute has_element?(view, "#risk-confirmation")
    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "risk acceptance copy and exclusive UTC expiry agree across review and history", c do
    through = Date.add(Date.utc_today(), 30)
    expires_on = Date.add(through, 1)
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.first.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> form("#workspace-decision", decision: %{action: "accepted_risk"}) |> render_change()

    assert has_element?(
             view,
             "#decision_action option[value=accepted_risk]",
             "Accept risk temporarily"
           )

    assert has_element?(
             view,
             "#whitelist-expiry-help",
             "expires at 00:00 UTC on the following day"
           )

    view
    |> form("#workspace-decision",
      decision: %{reason: "Patch rollout scheduled", due_on: Date.to_iso8601(through)}
    )
    |> render_submit()

    assert has_element?(
             view,
             "#risk-confirmation[data-return-focus=save-decision]",
             "1 deployment"
           )

    assert has_element?(view, "#risk-title", "Accept risk temporarily?")
    assert has_element?(view, "#risk-confirmation", "Accepted through #{through} (UTC)")
    assert has_element?(view, "#risk-confirmation", "Expires at 00:00 UTC on the following day")
    view |> element("#confirm-risk") |> render_click()
    assert has_element?(view, ".action-toast", "risk accepted for selected deployments")
    assert has_element?(view, ".scope-table", "Needs decision")
    [decision] = Decisions.history_for_cve(c.first.cve)
    assert decision.expires_at == DateTime.new!(expires_on, ~T[00:00:00])
    view |> element("#workspace-nav-exceptions") |> render_click()
    assert has_element?(view, "#exceptions-count", "1 decision")
    assert has_element?(view, "#exceptions-count", "1 underlying record")
    refute has_element?(view, "#exceptions-count", "1 underlying records")
    assert has_element?(view, ".risk-action-tag", "Temporary risk acceptance")
    assert has_element?(view, ".risk-entry-expiry", "Expires at")

    assert has_element?(
             view,
             ".risk-entry-expiry time",
             Calendar.strftime(expires_on, "%d %b %Y") <> ", 00:00 UTC"
           )

    view |> element("#workspace-nav-daily") |> render_click()
    assert has_element?(view, ".timeline-event-heading", "Risk accepted")
    assert has_element?(view, ".timeline-event-expiry", "Risk acceptance expires at")
  end

  test "review displays actual scanner fix data, not placeholder evidence", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.first.cve}")
    assert has_element?(view, ".reported-fix dd", "2.17.1")
    assert has_element?(view, ".evidence-column .form-note", "not proof it has been deployed")
    refute has_element?(view, ".policy-strip")
    refute has_element?(view, ".fact-grid")
  end

  test "timeline reuses global scope and window changes never widen it", c do
    {:ok, view, _} = live(c.conn, "/timeline?owner=alpha&environment=prod&weeks=4")
    assert has_element?(view, "#workspace-scope #scope_team option[value=alpha][selected]")
    refute has_element?(view, "#timeline-form select[name=owner]")
    refute has_element?(view, "#timeline-form select[name=environment]")
    assert has_element?(view, "#timeline-form input[type=hidden][name=owner][value=alpha]")
    assert has_element?(view, "#timeline-form input[type=hidden][name=environment][value=prod]")
    view |> form("#timeline-form", %{weeks: "8", scale: "detail"}) |> render_change()
    query = view |> assert_patch() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["owner"] == "alpha"
    assert query["environment"] == "prod"
    assert query["weeks"] == "8"
    assert query["scale"] == "detail"
    view |> element("#timeline-reset") |> render_click()
    query = view |> assert_patch() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["owner"] == "alpha"
    assert query["environment"] == "prod"
    refute Map.has_key?(query, "weeks")
    assert has_element?(view, "#scope_team option[value=alpha][selected]")
  end

  test "recovering an invalid timeline window keeps the displayed global scope", c do
    for recovery <- [:change, :reset] do
      {:ok, view, _} = live(c.conn, "/timeline?owner=alpha&environment=prod&weeks=99")
      assert has_element?(view, "#timeline-error")
      assert has_element?(view, "#scope_team option[value=alpha][selected]")
      assert has_element?(view, "#timeline-form input[name=owner][value=alpha]")
      assert has_element?(view, "#timeline-form input[name=environment][value=prod]")

      case recovery do
        :change -> view |> form("#timeline-form", %{weeks: "4", scale: "fit"}) |> render_change()
        :reset -> view |> element("#timeline-reset") |> render_click()
      end

      query = view |> assert_patch() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
      assert query["owner"] == "alpha"
      assert query["environment"] == "prod"
      refute has_element?(view, "#timeline-error")
    end
  end

  test "help describes real capabilities and account remains accessible", c do
    {:ok, view, _} = live(c.conn, "/")
    assert has_element?(view, "#workspace-account summary", "Account")
    assert has_element?(view, "#workspace-account #verified-identity")
    assert has_element?(view, "#workspace-account #logout-button")
    view |> element("#workspace-settings") |> render_click()
    assert has_element?(view, "#settings-title", "Data & help")
    assert has_element?(view, ".data-help dt", "Your work is saved to your account")
    assert has_element?(view, ".data-help dd", "not editable here")
  end

  test "overview drilldown remains scoped and reference caveats stay available", c do
    {:ok, view, _} = live(c.conn, "/?page=overview&team=alpha&environment=prod")
    assert has_element?(view, "#overview-data-note", "Scan coverage is unverified")
    assert has_element?(view, "#metric-unknown .sub", "Affected deployments, counted per CVE")
    view |> element("#start-review") |> render_click()
    query = view |> assert_patch() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
    assert query["page"] == "review"
    assert query["team"] == "alpha"
    assert query["environment"] == "prod"
  end
end
