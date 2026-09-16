defmodule TriageWeb.CaseReadabilityTest do
  use TriageWeb.ConnCase, async: true

  import Ecto.Query
  alias Triage.{Cases, Repo, Seeds}
  alias Triage.Inventory.Finding

  @scope [owner: "alpha", environment: "prod"]

  setup do
    :ok = Seeds.seed()

    finding =
      Repo.one!(
        from f in Finding, where: f.cve == "CVE-2025-1001" and f.package_name == "busybox"
      )

    {:ok, %{case: review_case}} = Cases.open_case(finding.id, @scope)
    %{review_case: review_case, finding: finding}
  end

  defp draft(rationale \\ "Reviewing the captured package and image evidence") do
    %{
      "applicability" => "unknown",
      "priority" => "insufficient_context",
      "next_action" => "investigation",
      "rationale" => rationale
    }
  end

  defp value(view, name) do
    [value] =
      view
      |> element("#review-form input[name='meta[#{name}]']")
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.attribute("value")

    value
  end

  defp draft_binding(view) do
    Map.new(
      ~w(case_id expected_revision expected_snapshot_id idempotency_token),
      &{&1, value(view, &1)}
    )
  end

  defp edit_draft(view, params) do
    view |> form("#review-form", %{"review" => params}) |> render_change()
  end

  defp submit(view, meta, params) do
    render_submit(view, "save", %{"review" => params, "meta" => meta})
  end

  defp externally_review(review_case, rationale \\ "Another operator's recorded assessment") do
    {:ok, data} = Cases.get_case(review_case.id)

    {:ok, _} =
      Cases.submit_review(
        review_case.id,
        data.case.revision,
        data.case.current_snapshot_id,
        Ecto.UUID.generate(),
        draft(rationale)
      )
  end

  defp change_source(finding) do
    Repo.update_all(from(f in Finding, where: f.id == ^finding.id), set: [fix: "99.0-reported"])
  end

  test "summary/form/details DOM order, snapshot identity and local restrictions stay prominent",
       %{conn: conn, review_case: review_case} do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")

    assert has_element?(
             view,
             "#case-workspace > .case-summary + .assessment-panel + .case-details"
           )

    assert has_element?(view, "#evidence-snapshot", "busybox")
    assert has_element?(view, "#evidence-snapshot", "Reported fixed version")
    assert has_element?(view, "#evidence-snapshot time[datetime][title]")
    assert has_element?(view, "#case-scope", "alpha")
    assert has_element?(view, "#case-banner", "does not approve an exception")

    assert has_element?(
             view,
             "#review-form[phx-hook='DirtyDraft'][data-dirty='false'][phx-auto-recover='recover_draft']"
           )

    assert has_element?(
             view,
             "#save-review-btn[data-confirm][phx-disable-with]",
             "Save local assessment"
           )

    assert has_element?(view, "#case-details details#technical-metadata:not([open])")
    assert has_element?(view, "#case-details details#case-history:not([open])")
    refute has_element?(view, "#evidence-snapshot table")

    refute has_element?(
             view,
             "#review-form select option[value='not_affected_with_evidence'][selected]"
           )
  end

  test "dirty reload and same-case patch keep all fields and the exact binding, without writes",
       %{conn: conn, review_case: review_case} do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    meta = draft_binding(view)
    edit_draft(view, draft())
    view |> element("#reload-case") |> render_click()
    render_patch(view, ~p"/cases/#{review_case.id}?owner=beta")
    assert draft_binding(view) == meta
    assert has_element?(view, "#review-form[data-dirty='true']")
    assert has_element?(view, "#review-form textarea", draft()["rationale"])

    assert has_element?(
             view,
             "#review-form select[name='review[applicability]'] option[value='unknown'][selected]"
           )

    assert has_element?(view, "#scope-mismatch")
    {:ok, data} = Cases.get_case(review_case.id)
    assert data.reviews == []
    assert length(data.events) == 1
    assert length(data.snapshots) == 1
  end

  test "conflict reload does not rebind; explicit confirmation does, without overwriting history",
       %{conn: conn, review_case: review_case} do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    meta = draft_binding(view)
    edit_draft(view, draft())
    externally_review(review_case)
    submit(view, meta, draft())
    assert has_element?(view, "#case-conflict")
    assert draft_binding(view) == meta
    view |> element("#reload-case") |> render_click()
    assert draft_binding(view) == meta
    assert has_element?(view, "#draft-binding-conflict")
    assert has_element?(view, "#save-review-btn[disabled]")
    assert has_element?(view, "#case-timeline", "Another operator's recorded assessment")
    view |> element("#rebind-draft-btn") |> render_click()
    view |> element("#rebind-cancel-btn") |> render_click()
    assert draft_binding(view) == meta
    view |> element("#rebind-draft-btn") |> render_click()
    view |> element("#rebind-confirm-btn") |> render_click()
    current = draft_binding(view)
    assert current["expected_revision"] == "2"
    assert current["expected_snapshot_id"] == meta["expected_snapshot_id"]
    refute current["idempotency_token"] == meta["idempotency_token"]
    assert has_element?(view, "#review-form[data-dirty='true']")
    submit(view, current, draft())
    assert has_element?(view, "#review-form[data-dirty='false']")
    {:ok, data} = Cases.get_case(review_case.id)
    assert length(data.reviews) == 2
    assert Enum.any?(data.reviews, &(&1.rationale == "Another operator's recorded assessment"))
  end

  test "changed recapture keeps draft's OLD snapshot until explicit rebind and marks older assessments",
       %{conn: conn, review_case: review_case, finding: finding} do
    externally_review(review_case)
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    meta = draft_binding(view)
    edit_draft(view, draft())
    change_source(finding)
    view |> element("#refresh-evidence-btn") |> render_click()
    view |> element("#refresh-evidence-confirm-btn") |> render_click()
    assert draft_binding(view) == meta
    assert has_element?(view, "#review-form textarea", draft()["rationale"])
    assert has_element?(view, "#evidence-snapshot", "99.0-reported")
    assert has_element?(view, "#evidence-refreshed")
    assert has_element?(view, "#save-review-btn[disabled]")
    assert has_element?(view, "#case-timeline", "saved against older evidence")
    {:ok, data} = Cases.get_case(review_case.id)
    assert length(data.snapshots) == 2
    assert length(data.reviews) == 1
    view |> element("#rebind-draft-btn") |> render_click()
    view |> element("#rebind-confirm-btn") |> render_click()
    assert value(view, "expected_snapshot_id") == to_string(data.case.current_snapshot_id)
    assert has_element?(view, "#review-form[data-dirty='true']")
  end

  test "unconfirmed and cancelled refresh/discard/rebind events never mutate or drop drafts", %{
    conn: conn,
    review_case: review_case,
    finding: finding
  } do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    meta = draft_binding(view)
    edit_draft(view, draft())
    change_source(finding)

    for event <- ~w(refresh_evidence_confirmed discard_confirmed rebind_confirmed),
        do: render_click(view, event)

    assert draft_binding(view) == meta
    assert has_element?(view, "#review-form textarea", draft()["rationale"])
    view |> element("#refresh-evidence-btn") |> render_click()
    view |> element("#refresh-evidence-cancel-btn") |> render_click()
    render_click(view, "refresh_evidence_confirmed")
    view |> element("#discard-draft-btn") |> render_click()
    view |> element("#discard-cancel-btn") |> render_click()
    render_click(view, "discard_confirmed")
    assert draft_binding(view) == meta
    assert has_element?(view, "#review-form[data-dirty='true']")
    {:ok, data} = Cases.get_case(review_case.id)
    assert data.reviews == []
    assert length(data.snapshots) == 1
    assert length(data.events) == 1
  end

  test "rebind confirmation detects another intervening revision instead of guessing", %{
    conn: conn,
    review_case: review_case
  } do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    meta = draft_binding(view)
    edit_draft(view, draft())
    externally_review(review_case)
    view |> element("#reload-case") |> render_click()
    view |> element("#rebind-draft-btn") |> render_click()
    externally_review(review_case, "A still newer saved review")
    view |> element("#rebind-confirm-btn") |> render_click()
    assert draft_binding(view) == meta
    assert has_element?(view, "#case-conflict")
    assert has_element?(view, "#review-form[data-dirty='true']")
    refute has_element?(view, "#rebind-draft-confirm")
  end

  test "late exact retry preserves a newer draft and its token; save clears only the saved draft",
       %{conn: conn, review_case: review_case} do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    original = draft_binding(view)
    edit_draft(view, draft())
    submit(view, original, draft())
    assert has_element?(view, "#review-form[data-dirty='false']")
    next_binding = draft_binding(view)
    next_draft = draft("New draft typed after the first save")
    edit_draft(view, next_draft)
    submit(view, original, draft())
    assert draft_binding(view) == next_binding
    assert has_element?(view, "#review-form textarea", next_draft["rationale"])
    assert has_element?(view, "#review-form[data-dirty='true']")
    assert has_element?(view, "[data-flash]", "Duplicate submission")
    {:ok, data} = Cases.get_case(review_case.id)
    assert length(data.reviews) == 1
    assert length(data.events) == 2
  end

  test "reconnect restores original binding rather than attaching recovered text to latest revision",
       %{conn: conn, review_case: review_case} do
    {:ok, old_view, _} = live(conn, ~p"/cases/#{review_case.id}")
    meta = draft_binding(old_view)
    externally_review(review_case)
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    render_change(view, "recover_draft", %{"review" => draft(), "meta" => meta})
    assert draft_binding(view) == meta
    assert has_element?(view, "#draft-recovered")
    assert has_element?(view, "#draft-binding-conflict")
    assert has_element?(view, "#save-review-btn[disabled]")
    assert has_element?(view, "#review-form textarea", draft()["rationale"])
    submit(view, draft_binding(view), draft())
    {:ok, data} = Cases.get_case(review_case.id)
    assert length(data.reviews) == 1
  end

  test "invalid recovery keeps text but blocks forged fresh-binding save", %{
    conn: conn,
    review_case: review_case
  } do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    meta = Map.put(draft_binding(view), "expected_snapshot_id", "999999999")
    render_change(view, "recover_draft", %{"review" => draft(), "meta" => meta})
    assert has_element?(view, "#draft-recovery-failed")
    assert has_element?(view, "#review-form textarea", draft()["rationale"])
    submit(view, draft_binding(view), draft())
    {:ok, data} = Cases.get_case(review_case.id)
    assert data.reviews == []
  end

  test "invalid route detaches the draft, blocks queued writes, and return restores its exact identity",
       %{conn: conn, review_case: review_case} do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    meta = draft_binding(view)
    edit_draft(view, draft())
    render_patch(view, "/cases/not-an-id")
    assert has_element?(view, "#retained-draft", "case ##{review_case.id}")
    refute has_element?(view, "#review-form")
    submit(view, meta, draft())
    view |> element("#return-to-draft") |> render_click()
    assert draft_binding(view) == meta
    assert has_element?(view, "#review-form textarea", draft()["rationale"])
    assert has_element?(view, "#review-form[data-dirty='true']")
    refute has_element?(view, "#retained-draft")
    {:ok, data} = Cases.get_case(review_case.id)
    assert data.reviews == []
  end

  test "explicit discard resets fields and token but never changes saved history", %{
    conn: conn,
    review_case: review_case
  } do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    original = draft_binding(view)
    edit_draft(view, draft())
    view |> element("#discard-draft-btn") |> render_click()
    view |> element("#discard-confirm-btn") |> render_click()
    assert has_element?(view, "#review-form[data-dirty='false']")
    refute has_element?(view, "#review-form textarea", draft()["rationale"])
    refute value(view, "idempotency_token") == original["idempotency_token"]
    {:ok, data} = Cases.get_case(review_case.id)
    assert data.reviews == []
    assert length(data.events) == 1
  end

  test "queue uses shared headings, neutral evidence state, page count and exact return cursor",
       %{conn: conn, review_case: review_case} do
    before = review_case.id + 1
    {:ok, queue, _} = live(conn, ~p"/cases?#{%{owner: "alpha", before: before}}")
    assert has_element?(queue, ".table-region[role='region'][tabindex='0'] #queue-table")
    assert has_element?(queue, "#queue-table thead th[scope='col']", "Assessment")

    assert has_element?(
             queue,
             "tbody#case-queue[phx-update='stream'] > tr#case-#{review_case.id}"
           )

    assert has_element?(
             queue,
             "#evidence-status-#{review_case.id} .status-badge-neutral",
             "Local evidence match"
           )

    assert has_element?(queue, "#review-status-#{review_case.id}", "No assessment recorded")
    assert has_element?(queue, "#queue-pagination", "1 saved cases on this page")

    assert {:error, {:live_redirect, %{to: to}}} =
             queue |> element("#case-link-#{review_case.id}") |> render_click()

    {:ok, detail, _} = live(conn, to)
    assert has_element?(detail, "#case-scope", "prod")

    assert {:error, {:live_redirect, %{to: back}}} =
             detail |> element("#back-to-cases") |> render_click()

    assert URI.parse(back).path == "/cases"

    assert URI.decode_query(URI.parse(back).query) == %{
             "owner" => "alpha",
             "before" => to_string(before)
           }
  end

  test "malformed queue return context cannot relabel the case or construct an arbitrary return URL",
       %{conn: conn, review_case: review_case} do
    for queue <- [
          %{from: "queue", owner: "beta", before: "bad"},
          %{from: "queue", owner: %{nested: "bad"}},
          "https://example.invalid"
        ] do
      {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}?#{%{queue: queue}}")
      assert has_element?(view, "#case-scope", "alpha")

      assert {:error, {:live_redirect, %{to: back}}} =
               view |> element("#back-to-cases") |> render_click()

      assert URI.parse(back).path == "/cases"

      assert URI.decode_query(URI.parse(back).query) == %{
               "owner" => "alpha",
               "environment" => "prod"
             }
    end
  end

  test "out-of-scope source stays readable but raw save and confirmed refresh cannot write", %{
    conn: conn,
    review_case: review_case,
    finding: finding
  } do
    Repo.update_all(
      from(p in Triage.Inventory.ImagePlacement,
        where: p.image_id == ^finding.image_id and p.owner == "alpha"
      ),
      set: [active: false]
    )

    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    assert has_element?(view, "#source-out-of-scope")
    assert has_element?(view, "#save-review-btn[disabled]")
    submit(view, draft_binding(view), draft())
    view |> element("#refresh-evidence-btn") |> render_click()
    view |> element("#refresh-evidence-confirm-btn") |> render_click()
    {:ok, data} = Cases.get_case(review_case.id)
    assert data.reviews == []
    assert length(data.snapshots) == 1
    assert length(data.events) == 1
  end

  test "detaching an unverified recovered draft cannot remove its explicit-rebind requirement", %{
    conn: conn,
    review_case: review_case
  } do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    bad_meta = Map.put(draft_binding(view), "expected_snapshot_id", "bad")
    render_change(view, "recover_draft", %{"review" => draft(), "meta" => bad_meta})
    render_patch(view, "/cases/not-an-id")
    view |> element("#return-to-draft") |> render_click()
    assert has_element?(view, "#draft-binding-conflict")
    assert has_element?(view, "#save-review-btn[disabled]")
    submit(view, draft_binding(view), draft())
    {:ok, data} = Cases.get_case(review_case.id)
    assert data.reviews == []
  end

  test "untrusted long values remain escaped and exactly available for copy", %{
    conn: conn,
    review_case: review_case,
    finding: finding
  } do
    hostile = "<script>alert(1)</script>" <> String.duplicate("long-image", 60)

    Repo.update_all(from(f in Finding, where: f.id == ^finding.id),
      set: [description: hostile, fix: nil]
    )

    Repo.update_all(from(i in Triage.Inventory.Image, where: i.id == ^finding.image_id),
      set: [repository: hostile, tag: "long-tag"]
    )

    {:ok, _} =
      Cases.refresh_evidence(
        review_case.id,
        review_case.revision,
        review_case.current_snapshot_id
      )

    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")
    assert has_element?(view, "#evidence-details", hostile)
    refute has_element?(view, "script")
    assert has_element?(view, "#evidence-snapshot", "Not reported")
    {:ok, data} = Cases.get_case(review_case.id)

    [copy] =
      view
      |> element("#case-image-digest-copy")
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.attribute("data-copy-value")

    assert copy == data.snapshot.payload["image"]["digest"]

    [image_copy] =
      view
      |> element("#case-image-reference-copy")
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.attribute("data-copy-value")

    assert image_copy == hostile <> ":long-tag"

    ids =
      view
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.query("[id]")
      |> LazyHTML.attribute("id")

    assert ids == Enum.uniq(ids)
  end

  test "evidence limitations consolidate caveats while snapshot identity stays visible", %{
    conn: conn,
    review_case: review_case
  } do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")

    assert has_element?(view, "#evidence-limitations", "Evidence limitations")
    assert has_element?(view, "#evidence-limitations", "Frozen local snapshot")
    assert has_element?(view, "#evidence-limitations-details", "not a verified fix")

    assert has_element?(view, "#evidence-snapshot", "Package · installed version")
    assert has_element?(view, "#evidence-snapshot", "Reported fixed version")
    assert has_element?(view, "#case-assessment-state", "No assessment recorded")
  end

  test "assessment fields mark required and the save action bar is one labelled region", %{
    conn: conn,
    review_case: review_case
  } do
    {:ok, view, _} = live(conn, ~p"/cases/#{review_case.id}")

    for field <- ~w(applicability priority next_action rationale) do
      assert has_element?(view, "#review-form #review_#{field}[required]")
    end

    assert has_element?(view, "#review-form label", "Applicability *")
    assert has_element?(view, "#review-form label", "Priority *")
    assert has_element?(view, "#review-form label", "Next action *")
    assert has_element?(view, "#review-form label", "Rationale *")
    assert has_element?(view, "#review-form legend", "All four fields are required")
    assert has_element?(view, "#assessment-actions #save-review-btn")
  end

  test "queue image column renders the shared technical value component", %{
    conn: conn,
    review_case: review_case
  } do
    before = review_case.id + 1
    {:ok, queue, _} = live(conn, ~p"/cases?#{%{owner: "alpha", before: before}}")

    assert has_element?(
             queue,
             "tbody#case-queue > tr#case-#{review_case.id} #queue-image-#{review_case.id}",
             "Image reference"
           )
  end
end
