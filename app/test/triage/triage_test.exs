defmodule Triage.TriageTest do
  @moduledoc """
  Unit tests for the Triage read model: admission, lanes and per-scope work items.

  Fixtures are dated relative to today and every test starts from an empty
  inventory, so a count assertion can only be satisfied by rows the test itself
  created.
  """
  use Triage.DataCase, async: false

  import Triage.Fixtures

  alias Triage.Cases
  alias Triage.Repo

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  defp board(filter \\ nil) do
    opts = if filter, do: [filter: filter], else: []
    {:ok, page} = Triage.Triage.list_critical(opts)
    page
  end

  defp row!(cve, filter \\ nil) do
    board(filter).rows
    |> Enum.find(&(&1.cve == cve))
    |> case do
      nil -> flunk("no triage row for #{cve}")
      row -> row
    end
  end

  defp not_affected_attrs,
    do: Map.put(review_attrs(), "applicability", "not_affected_with_evidence")

  # The idempotency token is server-generated in the product, so the test
  # produces a real UUID rather than a readable placeholder the API rejects.
  defp assess!(finding, owner, environment, attrs) do
    {:ok, %{case: cse, snapshot: snapshot}} =
      Cases.open_case(finding.id, owner: owner, environment: environment)

    # The saved review bumps the case revision, so the current revision comes
    # from the submit result rather than the pre-review read.
    {:ok, %{case: submitted}} =
      Cases.submit_review(cse.id, cse.revision, snapshot.id, Ecto.UUID.generate(), attrs)

    {submitted, snapshot}
  end

  test "an unassessed critical advisory is open work with one active scope" do
    image = image!("triage-intake")
    placement!(image, "alpha", "prod-cluster-1")
    finding!(image, "CVE-2026-1001", severity: "CRITICAL")

    page = board()
    assert page.total == 1
    assert page.truncated? == false
    assert [row] = page.rows
    assert row.state == :awaiting_assessment
    assert row.scopes_total == 1
    assert row.scopes_assessed == 0
    assert row.scopes_reviewed == 0
    assert row.scopes_impacted == 0
    # The row carries the group metrics the page renders, so a template can
    # never reach for a field the read model does not publish.
    assert row.reopened == 0
    assert row.fixable == 0
    assert row.images == 1
    assert row.occurrences == 1

    assert [item] = row.work_items
    assert item.owner == "alpha"
    assert item.environment == "prod-cluster-1"
    assert item.case_id == nil
    assert item.assessment == :awaiting_assessment
  end

  test "a current affected review is the only thing that confirms impact" do
    image = image!("triage-impact")
    placement!(image, "alpha", "prod-cluster-1")
    finding = finding!(image, "CVE-2026-1002", severity: "CRITICAL")

    {cse, _snapshot} = assess!(finding, "alpha", "prod-cluster-1", review_attrs())

    row = row!("CVE-2026-1002")
    assert row.state == :impact_confirmed
    assert row.scopes_assessed == 1
    assert row.scopes_reviewed == 1
    assert row.scopes_impacted == 1

    assert [item] = row.work_items
    assert item.assessment == :assessed
    assert item.applicability == "affected"
    assert item.priority == "normal_review"
    assert item.next_action == "investigation"
    assert item.case_id == cse.id
    assert item.reviewed_at != nil
  end

  test "an assessment superseded by a recapture is recorded but never counted as assessed" do
    image = image!("triage-superseded")
    placement!(image, "alpha", "prod-cluster-1")
    finding = finding!(image, "CVE-2026-1003", severity: "CRITICAL")

    {cse, snapshot} = assess!(finding, "alpha", "prod-cluster-1", review_attrs())

    # The source gains a lifecycle event, then a human recaptures evidence: the
    # review now judges a snapshot that is no longer the case's current one.
    event!(finding, "reopened", at(0))
    assert {:ok, %{changed?: true}} = Cases.refresh_evidence(cse.id, cse.revision, snapshot.id)

    row = row!("CVE-2026-1003")
    assert row.state == :awaiting_assessment
    assert row.scopes_reviewed == 1
    assert row.scopes_assessed == 0
    assert row.scopes_impacted == 0

    assert [item] = row.work_items
    assert item.assessment == :assessment_superseded
    assert item.applicability == "affected"
  end

  test "scope is per owner and environment, and partial coverage is reported honestly" do
    image = image!("triage-scopes")
    placement!(image, "alpha", "prod-cluster-1")
    placement!(image, "beta", "prod-cluster-2")
    finding = finding!(image, "CVE-2026-1004", severity: "CRITICAL")

    assert row!("CVE-2026-1004").scopes_total == 2

    assess!(finding, "alpha", "prod-cluster-1", review_attrs())

    row = row!("CVE-2026-1004")
    assert row.scopes_total == 2
    assert row.scopes_assessed == 1
    assert row.scopes_reviewed == 1
    assert row.scopes_impacted == 1
    # One confirmed scope is enough to place the advisory in the impact lane; it
    # still reports partial coverage, and the unjudged beta scope keeps it out of
    # the handled filter entirely.
    assert row.state == :impact_confirmed
    assert board("handled").rows == []
    assert Enum.map(row.work_items, & &1.owner) == ["alpha", "beta"]
    assert Enum.map(row.work_items, & &1.assessment) == [:assessed, :awaiting_assessment]
  end

  test "only critical, active, unsuppressed advisories are admitted" do
    image = image!("triage-admission")
    placement!(image, "alpha", "prod-cluster-1")
    finding!(image, "CVE-2026-2001", severity: "HIGH")
    finding!(image, "CVE-2026-2002", severity: "CRITICAL", suppressed: true)
    finding!(image, "CVE-2026-2003", severity: "CRITICAL", resolved_at: at(1))

    retired = image!("triage-retired")
    placement!(retired, "alpha", "prod-cluster-1", false)
    finding!(retired, "CVE-2026-2004", severity: "CRITICAL")
    retired_finding = finding!(retired, "CVE-2026-2005", severity: "CRITICAL")
    assert retired_finding.id

    page = board("all")
    assert page.total == 0
    assert page.rows == []
  end

  test "handled and active are complements and all covers both" do
    handled_image = image!("triage-handled")
    placement!(handled_image, "alpha", "prod-cluster-1")
    handled = finding!(handled_image, "CVE-2026-3001", severity: "CRITICAL")

    open_image = image!("triage-open")
    placement!(open_image, "alpha", "prod-cluster-1")
    finding!(open_image, "CVE-2026-3002", severity: "CRITICAL")

    assess!(handled, "alpha", "prod-cluster-1", not_affected_attrs())

    assert row!("CVE-2026-3001", "handled").state == :assessed_no_impact
    assert Enum.map(board("active").rows, & &1.cve) == ["CVE-2026-3002"]
    assert Enum.map(board("handled").rows, & &1.cve) == ["CVE-2026-3001"]

    assert board("all").rows |> Enum.map(& &1.cve) |> Enum.sort() ==
             ["CVE-2026-3001", "CVE-2026-3002"]

    summary = Triage.Triage.summarize(board("all").rows)
    assert summary.awaiting_assessment == 1
    assert summary.assessed_no_impact == 1
    assert summary.scopes_total == 2
    assert summary.scopes_assessed == 1
  end

  test "an unknown filter is rejected instead of silently defaulting" do
    assert {:error, :invalid_filter} = Triage.Triage.list_critical(filter: "bogus")
    assert {:error, :invalid_filter} = Triage.Triage.list_critical(filter: 7)
    assert {:ok, %{filter: "active"}} = Triage.Triage.list_critical([])
    assert {:ok, %{filter: "active"}} = Triage.Triage.list_critical(filter: "  ")
  end

  test "a suppressed advisory that a review judged is still not admitted" do
    image = image!("triage-suppressed")
    placement!(image, "alpha", "prod-cluster-1")
    finding = finding!(image, "CVE-2026-4001", severity: "CRITICAL")

    assess!(finding, "alpha", "prod-cluster-1", review_attrs())
    Repo.update!(Ecto.Changeset.change(finding, suppressed: true))

    assert board("all").rows == []
  end
end
