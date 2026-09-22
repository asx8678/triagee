defmodule TriageWeb.WorkspaceDraftConcurrencyTest do
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :reviewer
  import Triage.Fixtures
  alias Triage.Workspace.Drafts

  setup c do
    Triage.DataCase.reset_inventory!()
    image = image!("draft-cas")
    placement = placement!(image, "team-cas", "prod")
    finding = finding!(image, "CVE-2099-7770")
    Map.merge(c, %{cve: finding.cve, placement: placement})
  end

  test "a stale tab is told to reload instead of overwriting a saved draft", c do
    {:ok, a, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    {:ok, b, _} = live(c.conn, "/?page=review&item=#{c.cve}")

    render_change(a, "draft", %{"decision" => %{"action" => "fixed", "reason" => "Tab A saves"}})

    # B never observed the stored revision A created, so its change conflicts.
    render_change(b, "draft", %{"decision" => %{"reason" => "B overwrite attempt"}})

    assert has_element?(
             b,
             "#decision-error",
             "Draft was changed in another tab or device."
           )

    assert {:ok, stored} = Drafts.get(c.principal, c.cve)
    assert stored.fields["reason"] == "Tab A saves"
    assert stored.revision == 0
  end

  test "discarding in one tab keeps a newer draft another tab saved", c do
    {:ok, a, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    render_change(a, "draft", %{"decision" => %{"action" => "fixed", "reason" => "Tab A saves"}})

    # A later tab loads the stored draft and saves a newer revision of it.
    {:ok, b, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    render_change(b, "draft", %{"decision" => %{"reason" => "Newer tab B"}})
    assert {:ok, stored} = Drafts.get(c.principal, c.cve)
    assert stored.fields["reason"] == "Newer tab B"
    assert stored.revision == 1

    # The older tab discards only the revision it knew about.
    render_click(a, "cancel-decision", %{})

    assert {:ok, kept} = Drafts.get(c.principal, c.cve)
    assert kept.fields["reason"] == "Newer tab B"
    assert kept.revision == 1
  end

  test "commit cleanup keeps a newer draft another tab saved", c do
    {:ok, a, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    render_change(a, "draft", %{"decision" => %{"action" => "fixed", "reason" => "Tab A saves"}})

    {:ok, b, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    render_change(b, "draft", %{"decision" => %{"reason" => "Newer tab B"}})

    render_change(a, "target", %{"id" => to_string(c.placement.id)})
    render_submit(a, "save", %{"decision" => %{"action" => "fixed"}})

    assert [%{decision: "fixed"}] = Triage.Decisions.history_for_cve(c.cve)

    # A's commit cleaned up only its own revision; B's newer draft survives.
    assert {:ok, kept} = Drafts.get(c.principal, c.cve)
    assert kept.fields["reason"] == "Newer tab B"
    assert kept.revision == 1
  end
end
