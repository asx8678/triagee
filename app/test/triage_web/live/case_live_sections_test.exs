defmodule TriageWeb.CaseLive.SectionsTest do
  @moduledoc """
  Per-section regressions for the review case detail's components: each section
  renders on its own with the assigns it declares, so a section's content and
  its blocking conditions are asserted without driving a whole LiveView.

  These are pure renders over frozen payloads; nothing here loads or writes a
  case.
  """

  use ExUnit.Case, async: true

  import Phoenix.Component, only: [to_form: 2]
  import Phoenix.LiveViewTest

  alias TriageWeb.CaseLive.Format
  alias TriageWeb.CaseLive.Sections

  @captured_at ~U[2026-09-10 12:00:00Z]

  defp evidence do
    %{
      schema_version: "v1",
      source: "synthetic_local_inventory",
      scope_owner: "alpha",
      scope_environment: "prod-cluster-1",
      finding: %{
        cve: "CVE-2025-1001",
        package_name: "busybox",
        package_version: "1.37",
        severity: "HIGH",
        fix: "1.38",
        first_seen: @captured_at,
        last_seen: @captured_at,
        suppressed: false,
        resolved_at: nil
      },
      image: %{digest: "sha256:" <> String.duplicate("a", 64), repository: "reg/app", tag: "1.0"},
      placements: [],
      events: [],
      coverage: "complete"
    }
  end

  defp case_row do
    %{id: 7, revision: 2, owner: "alpha", environment: "prod-cluster-1", current_snapshot_id: 3}
  end

  defp snapshot do
    %{
      id: 3,
      version: 2,
      is_current: true,
      captured_at: @captured_at,
      payload_hash: "sha256:" <> String.duplicate("b", 64),
      evidence: evidence()
    }
  end

  defp evidence_assigns do
    %{
      evidence: evidence(),
      evidence_status: :current,
      snapshot: snapshot(),
      latest_review: nil,
      case: case_row(),
      retained_draft: nil,
      notice: nil,
      refresh_confirm?: false
    }
  end

  defp review_assigns do
    %{
      case: case_row(),
      expected_revision: 2,
      expected_snapshot_id: 3,
      dirty?: false,
      notice: nil,
      rebind_required?: false,
      rebind_confirm?: false,
      review_form: to_form(%{"applicability" => "unknown"}, as: :review),
      idempotency_token: "00000000-0000-0000-0000-000000000000",
      applicability_options: Format.applicability_options(),
      priority_options: Format.priority_options(),
      next_action_options: Format.next_action_options(),
      evidence_status: :current,
      snapshot: snapshot(),
      retained_draft: nil
    }
  end

  test "the retained-draft notice names the case and offers return or discard" do
    html = render_component(&Sections.retained_draft_notice/1, %{retained_draft: %{case_id: 7}})

    assert html =~ ~s(id="retained-draft")
    assert html =~ ~s(id="return-to-draft")
    assert html =~ ~s(id="retained-discard-btn")
    assert html =~ "Unsaved draft retained for case #7"
  end

  test "the discard confirmation points focus back at what opened it" do
    with_draft =
      render_component(&Sections.discard_confirm/1, %{
        discard_confirm?: true,
        retained_draft: %{case_id: 7}
      })

    without_draft =
      render_component(&Sections.discard_confirm/1, %{
        discard_confirm?: false,
        retained_draft: nil
      })

    assert with_draft =~ ~s(id="discard-confirm-btn")
    assert with_draft =~ ~s(data-return-focus="retained-discard-btn")

    refute without_draft =~ ~s(id="discard-confirm-btn")
    refute without_draft =~ ~s(data-return-focus="retained-discard-btn")
  end

  test "the evidence section states what it captured and which limitations apply" do
    html = render_component(&Sections.evidence_snapshot/1, evidence_assigns())

    assert html =~ ~s(id="evidence-snapshot")
    assert html =~ "Captured evidence"
    assert html =~ "Snapshot v2"
    assert html =~ "Local evidence match"

    # Every blocking state is its own visible notice, never a silent no-op.
    stale =
      render_component(&Sections.evidence_snapshot/1, %{
        evidence_assigns()
        | evidence_status: :changed
      })

    assert stale =~ "evidence-stale"

    out_of_scope =
      render_component(&Sections.evidence_snapshot/1, %{
        evidence_assigns()
        | evidence_status: :source_out_of_scope
      })

    assert out_of_scope =~ "source-out-of-scope"

    missing =
      render_component(&Sections.evidence_snapshot/1, %{
        evidence_assigns()
        | evidence_status: :source_missing
      })

    assert missing =~ "source-missing"
  end

  test "the evidence section refuses to invent a snapshot" do
    html = render_component(&Sections.evidence_snapshot/1, %{evidence_assigns() | snapshot: nil})

    assert html =~ "No evidence snapshot is available"
    assert html =~ "Do not assess missing evidence"
  end

  test "a retained draft locks the other assessment forms" do
    html =
      render_component(
        &Sections.evidence_snapshot/1,
        %{evidence_assigns() | retained_draft: %{case_id: 9}}
      )

    assert html =~ ~s(id="refresh-evidence-btn")
    assert html =~ "disabled"
  end

  test "the review section offers the shared choices and its save conditions" do
    html = render_component(&Sections.review_section/1, review_assigns())

    assert html =~ ~s(id="review-form")
    assert html =~ ~s(id="save-review-btn")

    for {label, key} <- Format.applicability_options() do
      assert html =~ key, "applicability option #{label} is missing"
    end

    for {label, key} <- Format.next_action_options() do
      assert html =~ key, "next-action option #{label} is missing"
    end

    # Saving is blocked whenever the draft is not bound to current evidence.
    for blocked <- [
          %{review_assigns() | rebind_required?: true},
          %{review_assigns() | evidence_status: :changed},
          %{review_assigns() | snapshot: nil}
        ] do
      assert render_component(&Sections.review_section/1, blocked) =~ "disabled"
    end
  end

  test "the review section surfaces a conflicting binding" do
    html = render_component(&Sections.review_section/1, %{review_assigns() | notice: :conflict})

    assert html =~ ~s(id="case-conflict")
    assert html =~ "Use reviewed evidence for draft"
  end

  test "the details section renders history and superseded snapshots from the streams" do
    timeline = [
      {"review-1",
       %{
         type: :review,
         applicability: "unknown",
         priority: "normal_review",
         next_action: "investigation",
         rationale: "Recorded reasoning",
         at: @captured_at,
         actor: "local-operator",
         snapshot_version: 2,
         is_stale: false,
         detail_pairs: []
       }},
      {"event-1",
       %{
         type: :event,
         kind: "review_saved",
         at: @captured_at,
         case_revision: 2,
         actor: "local-operator",
         snapshot_id: 3,
         review_id: 1,
         detail_pairs: []
       }}
    ]

    snapshots = [
      {"snapshot-3",
       %{
         id: 3,
         version: 2,
         is_current: true,
         captured_at: @captured_at,
         payload_hash: "sha256:x",
         evidence: evidence()
       }},
      {"snapshot-1",
       %{
         id: 1,
         version: 1,
         is_current: false,
         captured_at: @captured_at,
         payload_hash: "sha256:y",
         evidence: evidence()
       }}
    ]

    assigns = %{
      evidence: evidence(),
      snapshot: snapshot(),
      case: case_row(),
      streams: %{timeline: timeline, snapshots: snapshots}
    }

    html = render_component(&Sections.case_details/1, assigns)

    assert html =~ ~s(id="case-history")
    assert html =~ "Manual assessment"
    assert html =~ "Recorded reasoning"
    assert html =~ "Assessment saved"
    assert html =~ "Case revision 2"
    assert html =~ ~s(id="snapshots-section")
    assert html =~ "superseded"
    assert html =~ "historical-evidence-1"
  end

  test "the evidence facts component degrades to placeholders, never a crash" do
    html = render_component(&Sections.evidence_facts/1, %{evidence: evidence(), id: "facts"})

    assert html =~ "CVE-2025-1001"
    assert html =~ "facts"

    empty =
      render_component(&Sections.evidence_facts/1, %{
        evidence: Format.empty_evidence(),
        id: "facts"
      })

    assert empty =~ "Not reported"
  end
end
