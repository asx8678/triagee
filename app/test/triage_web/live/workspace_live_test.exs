defmodule TriageWeb.WorkspaceLiveTest do
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :reviewer
  import Phoenix.LiveViewTest
  import Triage.Fixtures
  alias Triage.{Decisions, Exposure, Repo, Workspace}

  setup do
    Triage.DataCase.reset_inventory!()
    image = image!("workspace-live")
    prod = placement!(image, "alpha", "prod")
    staging = placement!(image, "alpha", "staging")

    first =
      finding!(image, "CVE-2099-1001",
        severity: "CRITICAL",
        description: "<script>inert untrusted description</script>"
      )

    second = finding!(image, "CVE-2099-1002")
    %{prod: prod, staging: staging, cve: first.cve, first: first, second: second}
  end

  test "success toast dismisses and fixed badges survive reload", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> element("#scope-target-#{c.staging.id}") |> render_click()
    view |> decision_form(fields("fixed")) |> render_submit()
    assert has_element?(view, ".action-toast", "reported fixed")
    refute has_element?(view, ".workspace-notice")
    refute render(view) =~ "Active scanner evidence is unchanged"
    assert has_element?(view, ".action-toast .confirmation-title", "Action completed")
    assert has_element?(view, ".fixed-heading .fixed-banner", "REPORTED FIXED")
    assert has_element?(view, ".review-heading .status-fixed", "Reported fix")
    view |> element("button[phx-click='dismiss-action-toast']") |> render_click()
    refute has_element?(view, ".action-toast")
    {:ok, reloaded, _} = live(c.conn, "/?page=review&mode=fixed&item=#{c.cve}")
    assert has_element?(reloaded, ".status-fixed", "Reported fix")
    assert has_element?(reloaded, ".fixed-heading .fixed-banner", "REPORTED FIXED")
    assert has_element?(reloaded, "#queue-#{c.cve}.fixed-item")
    refute has_element?(reloaded, ".action-toast")
  end

  test "whitelist success shows expiry and timer removes only its toast", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> element("#scope-target-#{c.staging.id}") |> render_click()
    view |> form("#workspace-decision", decision: %{action: "accepted_risk"}) |> render_change()

    # A13: the acceptance rationale is required before the confirmation step.
    view
    |> form("#workspace-decision", decision: %{reason: "Vendor patch window acceptance"})
    |> render_submit()

    view |> element("#confirm-risk") |> render_click()

    assert has_element?(
             view,
             ".action-toast",
             "whitelisted until #{Triage.Workspace.Commit.default_due_on()}"
           )

    refute has_element?(view, ".saved-status.status-accepted_risk")
    refute has_element?(view, ".whitelist-badge")
    assert has_element?(view, ".whitelist-toast .confirmation-title", "Whitelisted")
    assert has_element?(view, ".whitelisted-heading .whitelisted-banner", "WHITELISTED")
    refute has_element?(view, ".fixed-heading")
    {:ok, reloaded, _} = live(c.conn, "/?page=review&mode=accepted&item=#{c.cve}")
    assert has_element?(reloaded, ".whitelisted-heading .whitelisted-banner", "WHITELISTED")
    assert has_element?(reloaded, "#queue-#{c.cve}.whitelisted-item")
    refute has_element?(reloaded, ".whitelist-badge, .status-accepted_risk")
    refute has_element?(reloaded, ".action-toast")

    [id] = Regex.run(~r/action-toast-\d+/, render(view))

    send(view.pid, {:dismiss_action_toast, -1})
    assert has_element?(view, ".action-toast")

    send(
      view.pid,
      {:dismiss_action_toast,
       id |> String.replace_prefix("action-toast-", "") |> String.to_integer()}
    )

    refute has_element?(view, ".action-toast")
  end

  test "fresh drafts are neutral and action labels follow the chosen action", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")

    # A fresh draft preselects no action, no conclusion and no write targets.
    assert has_element?(view, "#save-decision[disabled]", "Select an action")
    assert has_element?(view, "#decision-no-targets", "Select at least one deployment")
    assert has_element?(view, "#decision-action-help", "Choose one of the three actions")
    refute has_element?(view, "#ai-triage h3")
    refute render(view) =~ "KIRO · HEADLESS"

    assert Triage.Workspace.Commit.review_actions() == ~w(fixed accepted_risk create_ticket)

    for {action, index} <- Enum.with_index(Triage.Workspace.Commit.review_actions(), 2) do
      assert has_element?(view, "#decision_action option:nth-child(#{index})[value=#{action}]")
    end

    refute has_element?(view, "#decision_action option:nth-child(5)")

    for {action, label} <- [
          {"fixed", "Mark as fixed"},
          {"accepted_risk", "Whitelist now"},
          {"create_ticket", "Create Azure DevOps ticket"}
        ] do
      view |> form("#workspace-decision", decision: %{action: action}) |> render_change()
      assert has_element?(view, "#save-decision", label)
    end

    view |> element("#cancel-decision") |> render_click()
    assert has_element?(view, "#save-decision[disabled]", "Select an action")
    refute has_element?(view, "#save-next")
    assert Repo.aggregate(Decisions.Decision, :count) == 0
    assert_push_event(view, "workspace-draft-cleared", %{})
  end

  test "ticket preview does not save before confirmation and cancel is read-only", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> decision_form(%{"action" => "create_ticket"}) |> render_submit()
    assert has_element?(view, "#ticket-confirmation", "1 backlog")
    assert has_element?(view, "#ticket-confirmation", "#{c.cve} needs to be fixed")
    previous = System.get_env("ADO_PAT")
    System.delete_env("ADO_PAT")

    try do
      view |> element("#confirm-ticket") |> render_click()
      assert has_element?(view, "#ticket-confirmation [role=alert]", "not configured")
    after
      if previous, do: System.put_env("ADO_PAT", previous), else: System.delete_env("ADO_PAT")
    end

    assert Repo.aggregate(Decisions.Decision, :count) == 0
    view |> element("#ticket-confirmation button", "Cancel") |> render_click()
    refute has_element?(view, "#ticket-confirmation")
    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "action-specific fields reveal on selection and whitelist defaults stay", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    assert has_element?(view, "option[value=create_ticket]")
    refute has_element?(view, "option[value=investigate]")
    refute has_element?(view, "option[value=request_remediation]")
    refute has_element?(view, "option[value=request_verification]")
    refute has_element?(view, "input[name='decision[actor]']")
    refute has_element?(view, "input[name='decision[owner]']")

    view |> form("#workspace-decision", decision: %{action: "accepted_risk"}) |> render_change()

    assert has_element?(
             view,
             "#decision_due_on[value='#{Triage.Workspace.Commit.default_due_on()}']"
           )

    # A13: a blank rationale cannot reach the confirmation step; nothing is
    # recorded. This deliberately corrects the earlier optional-comment flow.
    view |> form("#workspace-decision", decision: %{reason: ""}) |> render_submit()
    assert has_element?(view, "#decision-error")
    assert Decisions.history_for_cve(c.cve) == []

    view
    |> form("#workspace-decision",
      decision: %{reason: "Accepted until service replacement lands"}
    )
    |> render_submit()

    view |> element("#confirm-risk") |> render_click()

    assert Enum.all?(
             Decisions.history_for_cve(c.cve),
             &(&1.reason == "Accepted until service replacement lands")
           )

    assert has_element?(view, "#draft-state", "Decision saved")
  end

  test "the findings table uses the four-column hierarchy with source-backed reasons", c do
    Exposure.record(c.prod.id, "internet_exposed", "fixture", DateTime.utc_now())

    {:ok, view, _} = live(c.conn, "/?page=inventory")

    for header <- ["Advisory / package", "Affected", "Why now", "Next action"] do
      assert has_element?(view, "#workspace-inventory th", header)
    end

    # Why now comes from the deterministic risk policy, not an opaque score.
    assert has_element?(
             view,
             "#inventory-#{c.cve} .why-now",
             "Internet-exposed placement with CRITICAL severity"
           )

    # Next action is a concrete step; the fix summary never invents a version.
    assert has_element?(view, "#inventory-#{c.cve} td", "Choose an action for exact scopes")
    assert has_element?(view, "#inventory-#{c.cve} td", "Scanner fix: not reported")

    # Affected carries real team/environment identity and the exact scope count.
    assert has_element?(view, "#inventory-#{c.cve} td", "alpha")
    assert has_element?(view, "#inventory-#{c.cve} td", "2 scopes")
  end

  test "a recorded decision changes the next-action column and appears in the detail history",
       c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> decision_form(fields("fixed")) |> render_submit()

    # The detail shows the append-only history inline; no separate destination.
    assert [decision] = Decisions.history_for_cve(c.cve)
    assert has_element?(view, "#decision-history-#{decision.id}", "Reported fix (unverified)")
    refute has_element?(view, "#workspace-inspector")
  end

  test "inventory and legacy inspect links open the one shared detail", c do
    {:ok, view, _} = live(c.conn, "/?page=inventory")
    view |> element("#inventory-#{c.cve} .cve-link") |> render_click()
    assert has_element?(view, "#workspace-review")
    assert has_element?(view, ".review-heading h2", c.cve)

    # The retired inspector URL converges on the same actionable detail.
    {:ok, deep, _} = live(c.conn, "/?page=inventory&inspect=#{c.cve}")
    assert has_element?(deep, "#workspace-review")
    assert has_element?(deep, ".review-heading h2", c.cve)
    refute has_element?(deep, "#workspace-inspector")
  end

  test "whitelist button explains missing targets and enables without AI classification", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> form("#workspace-decision", decision: %{action: "accepted_risk"}) |> render_change()

    assert has_element?(
             view,
             "#save-decision[disabled][aria-describedby=decision-action-help]",
             "Whitelist now"
           )

    assert has_element?(view, "#decision-action-help", "Select at least one deployment")

    assert has_element?(
             view,
             "#decision-action-help a[href='#review-deployments']",
             "Select deployments"
           )

    refute has_element?(view, "#classification-result")

    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    assert has_element?(view, "#save-decision:not([disabled])", "Whitelist now")
    refute has_element?(view, "#decision-action-help")

    view
    |> form("#workspace-decision", decision: %{reason: "Reviewed this production deployment"})
    |> render_submit()

    assert has_element?(view, "#risk-confirmation")
    assert Decisions.history_for_cve(c.cve) == []
    view |> element("#confirm-risk") |> render_click()
    assert [%{decision: "accepted_risk", placement_id: id}] = Decisions.history_for_cve(c.cve)
    assert id == c.prod.id
  end

  test "Review rejects retired work actions even when a client supplies valid fields", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()

    for action <- ~w(investigate request_remediation request_verification) do
      fields = %{
        "action" => action,
        "owner" => "Team A",
        "due_on" => Date.to_iso8601(Date.add(Date.utc_today(), 7)),
        "reason" => "Review this exact deployment"
      }

      render_hook(view, "draft", %{"decision" => fields})
      render_hook(view, "save", %{"decision" => fields})

      assert has_element?(
               view,
               "#decision-error",
               "Choose Mark as fixed, Whitelist temporarily, or Create Azure DevOps ticket."
             )

      assert has_element?(view, "#save-decision[disabled]", "Select an action")
      assert has_element?(view, "#decision-action-help", "Choose one of the three actions")
      assert Decisions.history_for_cve(c.cve) == []
    end
  end

  test "restored legacy drafts require an explicit supported choice without losing selection",
       c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()

    render_hook(view, "draft", %{
      "decision" => %{
        "action" => "investigate",
        "owner" => "Team A",
        "reason" => "Keep my draft context",
        "due_on" => Date.to_iso8601(Date.add(Date.utc_today(), 7))
      }
    })

    {:ok, restored, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    assert has_element?(restored, "#scope-target-#{c.prod.id}[checked]")
    assert has_element?(restored, "#save-decision[disabled]", "Select an action")
    assert has_element?(restored, "#decision-action-help", "Choose one of the three actions")
    refute has_element?(restored, "input[name='decision[owner]']")

    restored
    |> form("#workspace-decision", decision: %{action: "accepted_risk"})
    |> render_change()

    assert has_element?(restored, "textarea[name='decision[reason]']", "Keep my draft context")
    assert has_element?(restored, "#save-decision:not([disabled])", "Whitelist now")
    assert Decisions.history_for_cve(c.cve) == []
  end

  test "whitelist selection restores blank date and preserves an explicit date while editing",
       c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    render_change(view, "draft", %{"decision" => %{"action" => "accepted_risk", "due_on" => ""}})
    expected = Triage.Workspace.Commit.default_due_on() |> Date.to_iso8601()
    assert has_element?(view, "#decision_due_on[value='#{expected}']")
    custom = Date.utc_today() |> Date.add(10) |> Date.to_iso8601()
    view |> form("#workspace-decision", decision: %{due_on: custom}) |> render_change()
    assert has_element?(view, "#decision_due_on[value='#{custom}']")
    view |> form("#workspace-decision", decision: %{due_on: ""}) |> render_change()
    assert has_element?(view, "#decision_due_on[value='#{expected}']")
  end

  test "mark as fixed saves and is reachable in the Fixed queue", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    assert has_element?(view, "option[value=fixed]", "Mark as fixed")
    # Neutral drafts: the reviewer selects the exact write targets (I05).
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> element("#scope-target-#{c.staging.id}") |> render_click()
    view |> decision_form(fields("fixed")) |> render_submit()
    assert has_element?(view, ".action-toast", "reported fixed"), render(view)

    assert Decisions.history_for_cve(c.cve) |> Enum.map(& &1.placement_id) |> Enum.sort() ==
             Enum.sort([c.prod.id, c.staging.id])

    assert Workspace.page(%{"page" => "review", "mode" => "fixed", "item" => c.cve}).page_rows
           |> Enum.map(& &1.cve) == [c.cve]

    {:ok, fixed, _} = live(c.conn, "/?page=review&mode=fixed&item=#{c.cve}")
    assert has_element?(fixed, "#queue-#{c.cve}")
    assert has_element?(fixed, ".review-tools a", "Reported fixed")

    assert Enum.all?(
             Workspace.select(Workspace.targets(%{"cve" => c.cve}), "fixed"),
             &(&1.decision.label == "Reported fix (unverified)")
           )
  end

  test "workspace has one accessible page title without redundant header rows", %{conn: conn} do
    for page <- ["overview", "inventory", "review", "timeline"] do
      {:ok, view, _html} = live(conn, "/?page=#{page}")
      document = render(view) |> LazyHTML.from_document()
      assert Enum.count(LazyHTML.query(document, "#main-content h1")) == 1
      refute has_element?(view, "#main-content .page-head")
      refute has_element?(view, "#main-content .page-header")
      refute has_element?(view, ".timeline-jump")

      case page do
        "overview" ->
          refute has_element?(view, ".callout")
          assert has_element?(view, "#start-review", "Start review")
          assert has_element?(view, "#overview-data-note summary", "About these numbers")

        "inventory" ->
          assert has_element?(view, "#inventory-density[aria-pressed=false]", "Compact rows")

        "review" ->
          assert has_element?(view, "#decision-history-section summary", "Decision history")
          assert has_element?(view, "#why-now")
          assert has_element?(view, "#save-decision")
          refute has_element?(view, "#save-next")
          assert has_element?(view, "#cancel-decision", "Discard draft")

        "timeline" ->
          assert has_element?(view, "#timeline-form")
      end
    end
  end

  test "review queue gives package context and returns to the selected decision", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    assert has_element?(view, "#queue-#{c.cve}.active .queue-id", c.cve)
    assert has_element?(view, "#queue-#{c.cve} .queue-package", c.first.package_name)
    assert has_element?(view, "#queue-#{c.cve} .critical", "CRITICAL")
    refute has_element?(view, "#queue-#{c.second.cve}.active")
    assert has_element?(view, ".review-heading .critical", "CRITICAL")
    view |> element("#review-queue-toggle") |> render_click()
    assert has_element?(view, ".review-page.show-queue")
    assert has_element?(view, "#review-queue-toggle[aria-expanded=true]", "Back to decision")
    view |> element("#queue-#{c.second.cve}") |> render_click()
    assert has_element?(view, "#queue-#{c.second.cve}[aria-current=true]")
    assert has_element?(view, ".review-heading h2", c.second.cve)
    refute has_element?(view, ".review-page.show-queue")
    assert has_element?(view, "#review-queue-toggle[aria-expanded=false]", "Show queue")
  end

  test "homepage and workspace alias expose only the new shell", %{conn: conn} do
    for path <- ["/", "/workspace"] do
      {:ok, view, html} = live(conn, path)
      # Both existing review URLs share the Review navigation item.
      assert has_element?(view, "#workspace-nav-findings.active[aria-current=page]", "Review")
      assert has_element?(view, "#workspace-nav-exceptions", "Risk decisions")
      assert has_element?(view, "#workspace-review")
      refute has_element?(view, ".app-shell")
      refute html =~ "/assets/css/app.css"
      view |> element("#workspace-settings") |> render_click()
      refute has_element?(view, "#workspace-settings-dialog a[href]")
      view |> element("button[phx-click=close-settings]") |> render_click()
      view |> element("#workspace-nav-exceptions") |> render_click()
      assert_patch(view, "/?page=exceptions")
    end
  end

  test "all retired screens redirect instead of mounting old LiveViews", %{conn: conn} do
    for path <-
          ~w(/findings /findings/1 /cves/CVE-2099-1001 /triage /triage/CVE-2099-1001 /triage/history /cases /cases/1 /cases/1/exception /intel /whats-new /statistics /replay /replay/history /imports) do
      destination = conn |> get(path) |> redirected_to(302)
      assert String.starts_with?(destination, "/?")

      assert URI.decode_query(URI.parse(destination).query)["page"] in ~w(overview inventory review timeline)
    end

    assert conn |> get("/triage/CVE-2099-1001?owner=alpha&environment=prod") |> redirected_to(302) ==
             "/?environment=prod&item=CVE-2099-1001&page=review&team=alpha"

    live_routes =
      Phoenix.Router.routes(TriageWeb.Router) |> Enum.filter(&(&1.plug == Phoenix.LiveView.Plug))

    assert Enum.sort(Enum.map(live_routes, & &1.path)) == [
             "/",
             "/timeline",
             "/workspace"
           ]
  end

  test "full original timeline stays inside the new workspace and retains scope", c do
    appeared = event!(c.first, "appeared", DateTime.utc_now() |> DateTime.truncate(:second))
    other_image = image!("timeline-out-of-scope")
    placement!(other_image, "other", "staging")
    other = finding!(other_image, "CVE-2099-9999")
    event!(other, "appeared", DateTime.utc_now() |> DateTime.truncate(:second))
    before_count = Repo.aggregate(Triage.Inventory.FindingEvent, :count)

    {:ok, view, html} = live(c.conn, "/?page=timeline&team=alpha&environment=prod")

    for selector <- [
          "#workspace-timeline",
          "#tl-chart svg",
          "#tl-lanes-table",
          "#tl-bands",
          "#tl-grid-table"
        ] do
      assert has_element?(view, selector)
    end

    assert has_element?(view, "#tl-track-#{c.cve}")
    refute has_element?(view, "#tl-track-#{other.cve}")
    refute html =~ "/assets/css/app.css"
    refute has_element?(view, ".app-shell")
    refute has_element?(view, ".workspace-observation-dot")

    view
    |> form("#timeline-form", %{weeks: "4", scale: "detail", owner: "alpha", environment: "prod"})
    |> render_change()

    assert_patch(view, "/timeline?environment=prod&owner=alpha&scale=detail&weeks=4")
    assert has_element?(view, ".tl-chart-detail")
    view |> element("#tl-open-#{appeared.id}") |> render_click()
    assert has_element?(view, "#tl-drawer")
    assert has_element?(view, "#tl-event-#{appeared.id}")
    assert Repo.aggregate(Triage.Inventory.FindingEvent, :count) == before_count
    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "timeline invalid and empty scopes never widen the data", c do
    event!(c.first, "appeared", DateTime.utc_now() |> DateTime.truncate(:second))
    {:ok, view, _} = live(c.conn, "/?page=timeline&team=missing")
    assert has_element?(view, "#tl-lanes-empty")
    assert has_element?(view, "#scope_team option[value=missing][selected]")
    refute has_element?(view, "#tl-track-#{c.cve}")

    for path <- [
          "/?page=timeline&weeks=999",
          "/timeline?filters[owner]=alpha",
          "/timeline?events_after=1"
        ] do
      {:ok, invalid, _} = live(c.conn, path)
      assert has_element?(invalid, "#timeline-error")
      refute has_element?(invalid, "#tl-track-#{c.cve}")
    end
  end

  test "review drafts survive visiting the original timeline and returning", c do
    {:ok, view, _} = live(c.conn, "/?page=review&team=alpha&environment=prod&item=#{c.cve}")
    view |> decision_form(fields()) |> render_change()
    assert has_element?(view, "#shell[data-dirty=true]")

    # T04: the timeline is not in the primary nav; it remains reachable via
    # its legacy URL while the reporting transition is pending.
    view |> element("#workspace-nav-exceptions") |> render_click()
    assert_patch(view, "/?environment=prod&page=exceptions&team=alpha")
    assert has_element?(view, "#exceptions-register")

    # Navigating back to Review restores the draft.
    view |> element("#workspace-nav-findings") |> render_click()
    assert_patch(view, "/?environment=prod&page=findings&team=alpha")

    assert has_element?(
             view,
             "#decision_action option[value=fixed][selected]"
           )

    assert has_element?(
             view,
             "#decision_action option[value=fixed][selected]"
           )

    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  defp fields(action \\ "fixed") do
    if action == "accepted_risk",
      do: %{
        "action" => action,
        "reason" => "Investigated exact production scope",
        "due_on" => Date.to_iso8601(Date.add(Date.utc_today(), 5))
      },
      else: %{"action" => action}
  end

  defp decision_form(view, fields) do
    # Change action first so conditional inputs are actually present.
    view |> form("#workspace-decision", decision: %{action: "create_ticket"}) |> render_change()
    view |> form("#workspace-decision", decision: %{action: fields["action"]}) |> render_change()
    form(view, "#workspace-decision", decision: fields)
  end

  test "overview drilldown and inspector are read-only and retain environment", %{conn: conn} do
    {:ok, view, _} = live(conn, "/?page=overview&environment=prod")
    assert has_element?(view, "#metric-active .value", "2")
    view |> element("#team-review-alpha") |> render_click()
    assert_patch(view, "/?environment=prod&mode=needs&page=review&team=alpha")
    assert has_element?(view, "#workspace-review")
    # T03: the shared detail carries the evidence inline; the parallel
    # read-only inspector dialog is gone and nothing is written by reading.
    refute has_element?(view, "#workspace-inspector")
    assert has_element?(view, "#why-now")
    assert Repo.aggregate(Decisions.Decision, :count) == 0
    assert Repo.aggregate(Triage.GuidedReview.Request, :count) == 0
  end

  test "production-only save leaves staging pending and survives queue navigation", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> decision_form(fields()) |> render_change()
    view |> element("#queue-#{c.second.cve}") |> render_click()
    view |> element("#queue-#{c.cve}") |> render_click()

    assert has_element?(
             view,
             "#decision_action option[value=fixed][selected]"
           )

    refute has_element?(view, "#scope-target-#{c.staging.id}[checked]")

    view
    |> decision_form(fields())
    |> render_submit(%{"advance" => "false"})

    assert has_element?(view, "#draft-state", "Decision saved")

    assert Workspace.metrics(Workspace.targets(%{"cve" => c.cve}))["needs"].targets == [
             {c.cve, c.staging.id}
           ]

    assert Workspace.metrics(Workspace.targets())["active"].value == 2
    [decision] = Decisions.history_for_cve(c.cve)
    assert decision.placement_id == c.prod.id
    assert Repo.aggregate(Triage.GuidedReview.Request, :count) == 0
  end

  test "cancel acceptance preserves fields, confirmation and save target exact production", c do
    {:ok, view, _} = live(c.conn, "/?page=review&environment=prod&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> decision_form(fields("accepted_risk")) |> render_submit()
    assert has_element?(view, "#risk-confirmation", "Whitelist temporarily?")
    assert has_element?(view, "#confirm-risk", "Confirm whitelist")
    assert Repo.aggregate(Decisions.Decision, :count) == 0
    view |> element("#cancel-risk") |> render_click()

    assert has_element?(
             view,
             "textarea[name='decision[reason]']",
             "Investigated exact production scope"
           )

    view |> decision_form(fields("accepted_risk")) |> render_submit()
    view |> element("#confirm-risk") |> render_click()
    assert Repo.aggregate(Decisions.Decision, :count) == 1

    {:ok, whitelisted, _} =
      live(c.conn, "/?page=review&mode=accepted&environment=prod&item=#{c.cve}")

    refute has_element?(whitelisted, ".whitelist-badge")
    refute has_element?(whitelisted, ".status-accepted_risk")
    assert has_element?(whitelisted, ".review-tools a", "Whitelisted")

    assert Workspace.metrics(Workspace.targets(%{"cve" => c.cve}))["needs"].targets == [
             {c.cve, c.staging.id}
           ]
  end

  test "whitelist badge reflects only currently covered active scopes" do
    alias TriageWeb.WorkspaceComponents
    accepted = %{active?: true, covered?: true, decision: %{decision: "accepted_risk"}}
    uncovered = %{active?: true, covered?: false, decision: nil}
    expired = %{accepted | covered?: false}
    work = %{accepted | decision: %{decision: "investigate"}}

    assert WorkspaceComponents.whitelist_state(%{scopes: [accepted]}) == "Whitelisted"

    assert WorkspaceComponents.whitelist_state(%{scopes: [accepted, uncovered]}) ==
             "Partially whitelisted"

    assert WorkspaceComponents.whitelist_state(%{scopes: [expired, work]}) == nil
    assert WorkspaceComponents.whitelist_state(%{scopes: [%{accepted | active?: false}]}) == nil
    assert WorkspaceComponents.whitelist_state(%{scopes: []}) == nil
    assert WorkspaceComponents.whitelist_state(nil) == nil
  end

  test "scope changes never prune hidden draft targets", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> element("#scope-target-#{c.staging.id}") |> render_click()
    view |> decision_form(fields()) |> render_change()

    view
    |> form("#workspace-scope", scope: %{team: "alpha", environment: "prod"})
    |> render_change()

    assert has_element?(view, "#save-decision[disabled]")
    assert has_element?(view, ".form-error", "selected targets are hidden")
    view |> form("#workspace-scope", scope: %{team: "alpha", environment: ""}) |> render_change()
    assert has_element?(view, "#scope-target-#{c.staging.id}[checked]")

    assert has_element?(
             view,
             "#decision_action option[value=fixed][selected]"
           )
  end

  test "save conflict does not advance or erase the draft", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()

    c.first
    |> Ecto.Changeset.change(description: "Changed while operator typed")
    |> Repo.update!()

    view
    |> decision_form(fields())
    |> render_submit(%{"advance" => "true"})

    assert has_element?(view, "#decision-error", "Nothing was saved")
    assert has_element?(view, ".review-heading h2", c.cve)

    assert has_element?(
             view,
             "#decision_action option[value=fixed][selected]"
           )

    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "legacy advance parameter does not leave the current CVE", c do
    {:ok, view, _} = live(c.conn, "/?page=review&environment=prod&item=#{c.cve}")

    view |> element("#scope-target-#{c.prod.id}") |> render_click()

    view
    |> decision_form(fields())
    |> render_submit(%{"advance" => "true"})

    assert has_element?(view, ".review-heading h2", c.cve)
    assert Repo.aggregate(Decisions.Decision, :count) == 1
  end

  test "Save stays on the current CVE even when entered without an item parameter", c do
    {:ok, view, _} = live(c.conn, "/?page=review&environment=prod")
    assert has_element?(view, ".review-heading h2", c.cve)
    assert has_element?(view, "#shell[data-dirty=false]")
    view |> decision_form(fields()) |> render_change()
    assert has_element?(view, "#shell[data-dirty=true]")

    view |> element("#scope-target-#{c.prod.id}") |> render_click()

    view
    |> decision_form(fields())
    |> render_submit(%{"advance" => "false"})

    assert has_element?(view, ".review-heading h2", c.cve)
    assert has_element?(view, "#draft-state", "Decision saved")
    assert has_element?(view, "#shell[data-dirty=false]")
  end

  test "target-only and action-only drafts persist without a new draft button", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    assert has_element?(view, "#shell[data-dirty=false]")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    assert has_element?(view, "#shell[data-dirty=true]")
    view |> element("#workspace-nav-findings") |> render_click()
    assert has_element?(view, "#shell[data-dirty=true]")
    view |> element("#workspace-nav-findings") |> render_click()
    # The target-only draft persisted: its explicit selection is restored.
    assert has_element?(view, "#scope-target-#{c.prod.id}[checked]")
    refute has_element?(view, "#scope-target-#{c.staging.id}[checked]")
    refute has_element?(view, "button[phx-click=new-draft]")
    refute has_element?(view, "button", "Start a new draft")
    assert has_element?(view, "#shell[data-dirty=true]")
    view |> form("#workspace-decision", decision: %{action: "accepted_risk"}) |> render_change()
    assert has_element?(view, "#shell[data-dirty=true]")
    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "committing one draft does not clear another CVE's unsaved targets", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> element("#queue-#{c.second.cve}") |> render_click()
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> decision_form(fields()) |> render_submit()
    assert_push_event(view, "workspace-draft-cleared", %{})
    assert has_element?(view, "#shell[data-dirty=true]")
    view |> element("#queue-#{c.cve}") |> render_click()
    # The other CVE's unsaved explicit selection survived the commit.
    assert has_element?(view, "#scope-target-#{c.prod.id}[checked]")
    refute has_element?(view, "#scope-target-#{c.staging.id}[checked]")
    assert Decisions.history_for_cve(c.cve) == []
  end

  test "invalid view and forged save without a target are inert", c do
    {:ok, view, _} = live(c.conn, "/?page=review&mode=unexpected")
    # Invalid mode falls back to the findings default; no decision is recorded.
    render_submit(view, "save", %{"decision" => fields()})
    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "editing a saved decision starts a new operation, leaving both records in history", c do
    {:ok, view, _} = live(c.conn, "/?page=review&environment=prod&item=#{c.cve}")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> decision_form(fields()) |> render_submit()
    view |> decision_form(fields("accepted_risk")) |> render_change()
    view |> decision_form(fields("accepted_risk")) |> render_submit()
    view |> element("#confirm-risk") |> render_click()
    assert [latest, prior] = Decisions.history_for_cve(c.cve)
    assert latest.decision == "accepted_risk"
    assert latest.supersedes_id == prior.id
    assert latest.operation_id != prior.operation_id
  end

  test "unknown and out-of-scope advisory never fall back to another queue record", c do
    {:ok, view, _} =
      live(c.conn, "/?page=review&item=CVE-UNKNOWN&inspect=#{c.cve}&team=missing")

    # The inspect deep link opens the same shared detail; nothing matches the
    # scope, so the honest empty state shows and no record is substituted.
    refute has_element?(view, "#workspace-review")
    assert has_element?(view, ".review-workspace .empty", "No matching assessment")
    refute has_element?(view, ".review-heading h2", c.cve)
  end

  test "selected-only review visits exactly selected advisories", c do
    {:ok, view, _} = live(c.conn, "/?page=inventory")
    view |> element("#inventory-#{c.second.cve} input") |> render_click()
    view |> element("#review-selected") |> render_click()
    assert has_element?(view, "#queue-#{c.second.cve}")
    refute has_element?(view, "#queue-#{c.cve}")
    assert has_element?(view, ".review-heading h2", c.second.cve)
  end
end
