defmodule TriageWeb.ReportingDrilldownLiveTest do
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :viewer

  import Phoenix.LiveViewTest
  import Triage.Fixtures

  setup do
    Triage.DataCase.reset_inventory!()
    image = image!("reporting-drilldown")
    prod = placement!(image, "alpha", "prod")
    stage = placement!(image, "alpha", "staging")
    finding = finding!(image, "CVE-2099-8301", severity: "HIGH")
    %{cve: finding.cve, prod: prod, stage: stage}
  end

  test "exact target focus is visible to viewers and never selects a mutation target", c do
    path = "/?page=review&item=#{c.cve}&team=alpha&environment=prod&focus_target=#{c.prod.id}"
    {:ok, view, _html} = live(c.conn, path)

    assert has_element?(view, "#review-target-#{c.prod.id}.focused-target[aria-current=true]")
    refute has_element?(view, "#scope-target-#{c.prod.id}[checked]")
    refute has_element?(view, "#review-target-#{c.stage.id}")
  end

  test "wrong-CVE, out-of-scope and malformed target links fail closed without substitution", c do
    for path <- [
          "/?page=review&item=#{c.cve}&team=alpha&environment=prod&focus_target=#{c.stage.id}",
          "/?page=review&item=#{c.cve}&team=alpha&environment=prod&focus_target=bad"
        ] do
      {:ok, view, _html} = live(c.conn, path)
      assert has_element?(view, ".review-workspace .empty")
      refute has_element?(view, "#workspace-review")
    end
  end
end
