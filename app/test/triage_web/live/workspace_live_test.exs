defmodule TriageWeb.WorkspaceLiveTest do
  use TriageWeb.ConnCase, async: false
  import Phoenix.LiveViewTest
  import Triage.Fixtures
  alias Triage.{Decisions, Repo, Workspace}

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

  defp fields(action \\ "request_remediation") do
    %{
      "action" => action,
      "owner" => "Owner",
      "actor" => "Reviewer",
      "reason" => "Investigated exact production scope",
      "due_on" => Date.utc_today() |> Date.add(5) |> Date.to_iso8601()
    }
  end

  test "overview drilldown and inspector are read-only and retain environment", %{conn: conn} do
    {:ok, view, _} = live(conn, "/workspace?environment=prod")
    assert has_element?(view, "#metric-active .value", "2")
    view |> element("#team-review-alpha") |> render_click()
    assert_patch(view, "/workspace?environment=prod&mode=needs&page=review&team=alpha")
    assert has_element?(view, "#workspace-review")
    view |> element(".review-heading a", "Full evidence") |> render_click()
    assert has_element?(view, "#workspace-inspector")
    refute has_element?(view, ".inspector-body script")
    assert Repo.aggregate(Decisions.Decision, :count) == 0
    assert Repo.aggregate(Triage.GuidedReview.Request, :count) == 0
  end

  test "production-only save leaves staging pending and survives queue navigation", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.staging.id}") |> render_click()
    view |> form("#workspace-decision", decision: fields()) |> render_change()
    view |> element("#queue-#{c.second.cve}") |> render_click()
    view |> element("#queue-#{c.cve}") |> render_click()

    assert has_element?(
             view,
             "textarea[name='decision[reason]']",
             "Investigated exact production scope"
           )

    refute has_element?(view, "#scope-target-#{c.staging.id}[checked]")

    view
    |> form("#workspace-decision", decision: fields())
    |> render_submit(%{"advance" => "false"})

    assert has_element?(view, "#draft-state", "Decision committed locally")

    assert Workspace.metrics(Workspace.targets(%{"cve" => c.cve}))["needs"].targets == [
             {c.cve, c.staging.id}
           ]

    assert Workspace.metrics(Workspace.targets())["active"].value == 2
    [decision] = Decisions.history_for_cve(c.cve)
    assert decision.placement_id == c.prod.id
    assert Repo.aggregate(Triage.GuidedReview.Request, :count) == 0
  end

  test "cancel acceptance preserves fields, confirmation and save target exact production", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=review&environment=prod&item=#{c.cve}")
    view |> form("#workspace-decision", decision: fields("accepted_risk")) |> render_submit()
    assert has_element?(view, "#risk-confirmation")
    assert Repo.aggregate(Decisions.Decision, :count) == 0
    view |> element("#cancel-risk") |> render_click()

    assert has_element?(
             view,
             "textarea[name='decision[reason]']",
             "Investigated exact production scope"
           )

    view |> form("#workspace-decision", decision: fields("accepted_risk")) |> render_submit()
    view |> element("#confirm-risk") |> render_click()
    assert Repo.aggregate(Decisions.Decision, :count) == 1

    assert Workspace.metrics(Workspace.targets(%{"cve" => c.cve}))["needs"].targets == [
             {c.cve, c.staging.id}
           ]
  end

  test "scope changes never prune hidden draft targets", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=review&item=#{c.cve}")
    view |> form("#workspace-decision", decision: fields()) |> render_change()

    view
    |> form("#workspace-scope", scope: %{team: "alpha", environment: "prod"})
    |> render_change()

    assert has_element?(view, "#save-decision[disabled]")
    assert has_element?(view, ".form-error", "selected targets are hidden")
    view |> form("#workspace-scope", scope: %{team: "alpha", environment: ""}) |> render_change()
    assert has_element?(view, "#scope-target-#{c.staging.id}[checked]")

    assert has_element?(
             view,
             "textarea[name='decision[reason]']",
             "Investigated exact production scope"
           )
  end

  test "save conflict does not advance or erase the draft", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=review&item=#{c.cve}")

    c.first
    |> Ecto.Changeset.change(description: "Changed while operator typed")
    |> Repo.update!()

    view
    |> form("#workspace-decision", decision: fields())
    |> render_submit(%{"advance" => "true"})

    assert has_element?(view, "#decision-error", "Nothing was saved")
    assert has_element?(view, ".review-heading h2", c.cve)

    assert has_element?(
             view,
             "textarea[name='decision[reason]']",
             "Investigated exact production scope"
           )

    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "save and next advances only after a durable decision", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=review&environment=prod&item=#{c.cve}")

    view
    |> form("#workspace-decision", decision: fields())
    |> render_submit(%{"advance" => "true"})

    assert has_element?(view, ".review-heading h2", c.second.cve)
    assert Repo.aggregate(Decisions.Decision, :count) == 1
  end

  test "Save stays on the current CVE even when entered without an item parameter", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=review&environment=prod")
    assert has_element?(view, ".review-heading h2", c.cve)
    assert has_element?(view, "#shell[data-dirty=false]")
    view |> form("#workspace-decision", decision: fields()) |> render_change()
    assert has_element?(view, "#shell[data-dirty=true]")

    view
    |> form("#workspace-decision", decision: fields())
    |> render_submit(%{"advance" => "false"})

    assert has_element?(view, ".review-heading h2", c.cve)
    assert has_element?(view, "#draft-state", "Decision committed locally")
    assert has_element?(view, "#shell[data-dirty=false]")
    view |> element(".review-heading a", "Full evidence") |> render_click()
    view |> element("#close-inspector") |> render_click()
    assert has_element?(view, ".review-heading h2", c.cve)
  end

  test "target-only and action-only drafts are dirty until explicit discard", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=review&item=#{c.cve}")
    assert has_element?(view, "#shell[data-dirty=false]")
    view |> element("#scope-target-#{c.staging.id}") |> render_click()
    assert has_element?(view, "#shell[data-dirty=true]")
    view |> element("#workspace-nav-overview") |> render_click()
    assert has_element?(view, "#shell[data-dirty=true]")
    view |> element("#workspace-nav-review") |> render_click()
    refute has_element?(view, "#scope-target-#{c.staging.id}[checked]")
    view |> element("button[phx-click=new-draft]") |> render_click()
    assert_push_event(view, "workspace-draft-cleared", %{})
    assert has_element?(view, "#shell[data-dirty=false]")
    assert has_element?(view, "#scope-target-#{c.staging.id}[checked]")
    view |> form("#workspace-decision", decision: %{action: "investigate"}) |> render_change()
    assert has_element?(view, "#shell[data-dirty=true]")
    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "committing one draft does not clear another CVE's unsaved targets", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=review&item=#{c.cve}")
    view |> element("#scope-target-#{c.staging.id}") |> render_click()
    view |> element("#queue-#{c.second.cve}") |> render_click()
    view |> form("#workspace-decision", decision: fields()) |> render_submit()
    assert_push_event(view, "workspace-draft-cleared", %{})
    assert has_element?(view, "#shell[data-dirty=true]")
    view |> element("#queue-#{c.cve}") |> render_click()
    refute has_element?(view, "#scope-target-#{c.staging.id}[checked]")
    assert Decisions.history_for_cve(c.cve) == []
  end

  test "invalid view and forged save without a target are inert", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=review&mode=unexpected")
    refute has_element?(view, "#workspace-review")
    render_submit(view, "save", %{"decision" => fields()})
    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  test "editing a saved decision starts a new operation, leaving both records in history", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=review&environment=prod&item=#{c.cve}")
    view |> form("#workspace-decision", decision: fields()) |> render_submit()
    view |> form("#workspace-decision", decision: fields("investigate")) |> render_change()
    view |> form("#workspace-decision", decision: fields("investigate")) |> render_submit()
    assert [latest, prior] = Decisions.history_for_cve(c.cve)
    assert latest.decision == "investigate"
    assert latest.supersedes_id == prior.id
    assert latest.operation_id != prior.operation_id
  end

  test "unknown and out-of-scope advisory never fall back to another queue record", c do
    {:ok, view, _} =
      live(c.conn, "/workspace?page=review&item=CVE-UNKNOWN&inspect=#{c.cve}&team=missing")

    refute has_element?(view, "#workspace-review")
    refute has_element?(view, "#inspector-review")
    assert has_element?(view, ".inspector-body", "No matching scopes")
  end

  test "selected-only review visits exactly selected advisories", c do
    {:ok, view, _} = live(c.conn, "/workspace?page=inventory")
    view |> element("#inventory-#{c.second.cve} input") |> render_click()
    view |> element("#review-selected") |> render_click()
    assert has_element?(view, "#queue-#{c.second.cve}")
    refute has_element?(view, "#queue-#{c.cve}")
    assert has_element?(view, ".review-heading h2", c.second.cve)
  end
end
