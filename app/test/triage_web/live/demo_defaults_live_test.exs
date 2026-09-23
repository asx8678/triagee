defmodule TriageWeb.DemoDefaultsLiveTest do
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :reviewer
  import Phoenix.LiveViewTest
  import Triage.Fixtures
  alias Triage.{Decisions, Repo}

  setup do
    previous = Application.get_env(:triage, :demo_mode, false)
    Application.put_env(:triage, :demo_mode, true)
    on_exit(fn -> Application.put_env(:triage, :demo_mode, previous) end)
    Triage.DataCase.reset_inventory!()
    image = image!("demo-defaults")
    prod = placement!(image, "demo-test", "prod")
    staging = placement!(image, "demo-test", "staging")
    retired = placement!(image, "demo-test", "dev")
    Repo.update!(Ecto.Changeset.change(retired, active: false))
    finding = finding!(image, "CVE-2099-9950")
    %{prod: prod, staging: staging, retired: retired, cve: finding.cve}
  end

  test "fresh demo opens with whitelist enabled for active visible deployments only", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}&environment=prod")
    assert has_element?(view, "#demo-mode")
    assert has_element?(view, "#decision_action option[value=accepted_risk][selected]")
    assert has_element?(view, "#scope-target-#{c.prod.id}[checked]")
    refute has_element?(view, "#scope-target-#{c.staging.id}")
    assert has_element?(view, "#save-decision:not([disabled])", "Whitelist now")
    assert has_element?(view, "#draft-state", "No unsaved changes")
    assert Decisions.history_for_cve(c.cve) == []
    refute has_element?(view, "#risk-confirmation")

    view |> form("#workspace-decision", decision: %{reason: ""}) |> render_submit()
    assert has_element?(view, "#decision-error")
    assert Decisions.history_for_cve(c.cve) == []

    view
    |> form("#workspace-decision", decision: %{reason: "Demo: approved temporary patch window"})
    |> render_submit()

    assert has_element?(view, "#risk-confirmation")
    assert Decisions.history_for_cve(c.cve) == []
    view |> element("#confirm-risk") |> render_click()
    assert [%{decision: "accepted_risk", placement_id: id}] = Decisions.history_for_cve(c.cve)
    assert id == c.prod.id
  end

  test "explicit deselection survives reconnect and is never silently reversed", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    refute has_element?(view, "#scope-target-#{c.retired.id}[checked]")
    view |> element("#scope-target-#{c.prod.id}") |> render_click()
    view |> element("#scope-target-#{c.staging.id}") |> render_click()
    assert has_element?(view, "#save-decision[disabled]")
    {:ok, restored, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    refute has_element?(restored, "#scope-target-#{c.prod.id}[checked]")
    refute has_element?(restored, "#scope-target-#{c.staging.id}[checked]")
    assert has_element?(restored, "#save-decision[disabled]")
    assert Decisions.history_for_cve(c.cve) == []
  end

  test "untouched defaults follow scope but user-edited targets stay frozen", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    view |> form("#workspace-scope", scope: %{environment: "prod"}) |> render_change()
    assert has_element?(view, "#scope-target-#{c.prod.id}[checked]")
    assert has_element?(view, "#save-decision:not([disabled])")

    view
    |> form("#workspace-decision", decision: %{reason: "Keep the chosen production scope"})
    |> render_change()

    view |> form("#workspace-scope", scope: %{environment: "staging"}) |> render_change()
    refute has_element?(view, "#scope-target-#{c.staging.id}[checked]")
    assert has_element?(view, "#save-decision[disabled]")
    assert has_element?(view, "#decision-action-help", "Selected deployments are hidden")
  end

  test "turning demo mode off restores neutral defaults", c do
    Application.put_env(:triage, :demo_mode, false)
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    refute has_element?(view, "#demo-mode")
    refute has_element?(view, "#scope-target-#{c.prod.id}[checked]")
    assert has_element?(view, "#decision_action option[value=''][selected]")
    assert has_element?(view, "#save-decision[disabled]", "Select an action")
  end

  @tag authenticated: :viewer
  test "demo defaults never grant reviewer permission", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    refute has_element?(view, "#scope-target-#{c.prod.id}[checked]")
    assert has_element?(view, "#save-decision[disabled]")
    assert has_element?(view, "#viewer-read-only")
    assert Decisions.history_for_cve(c.cve) == []
  end
end
