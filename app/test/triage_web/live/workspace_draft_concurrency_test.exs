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
    Map.merge(c, %{cve: finding.cve, placement: placement, image: image})
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

  test "a conflict stays with its CVE when another draft is saved", c do
    other = finding!(c.image, "CVE-2099-7771")
    path = "/?page=review&item=#{c.cve}"
    other_path = "/?page=review&item=#{other.cve}"
    {:ok, a, _} = live(c.conn, path)
    {:ok, b, _} = live(c.conn, path)

    render_change(a, "draft", %{
      "decision" => %{"action" => "accepted_risk", "reason" => "Saved in tab A"}
    })

    render_change(b, "draft", %{
      "decision" => %{"action" => "accepted_risk", "reason" => "Unsaved in tab B"}
    })

    assert has_element?(b, "#draft-state", "Draft NOT saved")
    assert has_element?(b, "#decision-error", "another tab or device")
    assert {:ok, original} = Drafts.get(c.principal, c.cve)

    render_patch(b, other_path)
    refute has_element?(b, "#decision-error")
    assert has_element?(b, "#draft-state", "No unsaved changes")

    render_change(b, "draft", %{
      "decision" => %{"action" => "accepted_risk", "reason" => "Other CVE saved"}
    })

    assert has_element?(b, "#draft-state", "Draft saved to your account")
    render_patch(b, path)
    assert has_element?(b, "#decision_reason", "Unsaved in tab B")
    assert has_element?(b, "#draft-state", "Draft NOT saved")
    assert has_element?(b, "#decision-error", "another tab or device")
    assert has_element?(b, "#save-decision[disabled]")
    assert {:ok, ^original} = Drafts.get(c.principal, c.cve)

    {:ok, restored, _} = live(c.conn, path)
    assert has_element?(restored, "#decision_reason", "Saved in tab A")
    assert has_element?(restored, "#draft-state", "Draft saved to your account")
  end

  test "nonpersisting invalid submissions preserve an existing conflict", c do
    path = "/?page=review&item=#{c.cve}"
    {:ok, a, _} = live(c.conn, path)
    {:ok, b, _} = live(c.conn, path)
    render_change(a, "draft", %{"decision" => %{"action" => "fixed"}})
    render_change(b, "draft", %{"decision" => %{"action" => "accepted_risk"}})
    assert {:ok, original} = Drafts.get(c.principal, c.cve)

    render_submit(b, "save", %{"decision" => %{"reason" => ""}})
    assert has_element?(b, "#draft-state", "Draft NOT saved")
    assert has_element?(b, "#decision-action-help", "draft could not be saved")
    render_patch(b, "/?page=inventory")
    render_patch(b, path)
    assert has_element?(b, "#draft-state", "Draft NOT saved")
    assert {:ok, ^original} = Drafts.get(c.principal, c.cve)
    assert Triage.Decisions.history_for_cve(c.cve) == []
  end

  test "submit-only edits are not acknowledged until they are actually stored", c do
    path = "/?page=review&item=#{c.cve}"
    {:ok, view, _} = live(c.conn, path)
    render_click(view, "target", %{"id" => to_string(c.placement.id)})

    render_change(view, "draft", %{
      "decision" => %{"action" => "accepted_risk", "reason" => "Stored reason"}
    })

    assert {:ok, original} = Drafts.get(c.principal, c.cve)
    assert has_element?(view, "#draft-state", "Draft saved to your account")

    # Submitting unchanged content is not a new acknowledgement, but retains
    # the previous one. Cancelling confirmation must not alter storage.
    render_submit(view, "save", %{"decision" => %{"reason" => "Stored reason"}})
    assert has_element?(view, "#risk-confirmation")
    render_click(view, "cancel-risk", %{})
    assert has_element?(view, "#draft-state", "Draft saved to your account")

    # A submission can carry newer fields without an autosave acknowledgement.
    render_submit(view, "save", %{"decision" => %{"reason" => "Submit-only reason"}})
    assert has_element?(view, "#risk-confirmation")
    render_click(view, "cancel-risk", %{})
    assert has_element?(view, "#decision_reason", "Submit-only reason")
    assert has_element?(view, "#draft-state", "Draft NOT saved")
    assert {:ok, ^original} = Drafts.get(c.principal, c.cve)
    assert Triage.Decisions.history_for_cve(c.cve) == []

    render_patch(view, "/?page=inventory")
    render_patch(view, path)
    assert has_element?(view, "#draft-state", "Draft NOT saved")

    render_change(view, "draft", %{"decision" => %{"reason" => "Submit-only reason"}})
    assert has_element?(view, "#draft-state", "Draft saved to your account")
    assert {:ok, stored} = Drafts.get(c.principal, c.cve)
    assert stored.fields["reason"] == "Submit-only reason"
    assert stored.revision == original.revision + 1
  end

  test "validation failure cannot acknowledge submit-only fields", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    render_click(view, "target", %{"id" => to_string(c.placement.id)})

    render_change(view, "draft", %{
      "decision" => %{"action" => "accepted_risk", "reason" => "Stored valid reason"}
    })

    assert {:ok, original} = Drafts.get(c.principal, c.cve)
    render_submit(view, "save", %{"decision" => %{"reason" => " "}})
    assert has_element?(view, "#decision-error", "Your draft is unchanged.")
    assert has_element?(view, "#draft-state", "Draft NOT saved")
    refute has_element?(view, "#risk-confirmation")
    assert {:ok, ^original} = Drafts.get(c.principal, c.cve)
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
