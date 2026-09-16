defmodule Triage.ExceptionDecisionTest do
  use ExUnit.Case, async: true
  alias Triage.Exceptions
  alias Triage.Exceptions.Decision

  defp attrs do
    %{
      "kind" => "accepted_risk",
      "reason" => "Risk accepted during scheduled upgrade",
      "review_by" => Date.to_iso8601(Date.add(Date.utc_today(), 30))
    }
  end

  test "requires bounded nonblank safe text and a valid decision" do
    assert Exceptions.change(attrs()).valid?

    for reason <- [
          nil,
          "",
          "   ",
          "bad\0reason",
          "bad\a",
          <<255>>,
          String.duplicate("x", 2001),
          %{}
        ] do
      refute Exceptions.change(Map.put(attrs(), "reason", reason)).valid?
    end

    for kind <- [nil, "safe", "suppressed", %{}] do
      refute Exceptions.change(Map.put(attrs(), "kind", kind)).valid?
    end

    for malformed <- [
          nil,
          [],
          "bad",
          %{kind: "accepted_risk"},
          %{"reason" => "text", kind: "accepted_risk"}
        ] do
      refute Exceptions.change(malformed).valid?
    end
  end

  test "review date is mandatory, future, bounded and parsed strictly" do
    for date <- [
          nil,
          "",
          "tomorrow",
          "2026-02-30",
          %{},
          Date.to_iso8601(Date.utc_today()),
          Date.to_iso8601(Date.add(Date.utc_today(), -1)),
          Date.to_iso8601(Date.add(Date.utc_today(), 91))
        ] do
      refute Exceptions.change(Map.put(attrs(), "review_by", date)).valid?
    end

    assert Exceptions.change(Map.put(attrs(), "review_by", Date.add(Date.utc_today(), 90))).valid?
  end

  test "not affected requires evidence; reopen requires reason but no date" do
    evidence_attrs = Map.put(attrs(), "kind", "not_affected")

    for evidence <- [nil, "", "  ", "bad\0", String.duplicate("x", 2001)] do
      refute Exceptions.change(Map.put(evidence_attrs, "evidence", evidence)).valid?
    end

    assert Exceptions.change(
             Map.put(
               evidence_attrs,
               "evidence",
               "Vulnerable feature excluded; build manifest ABC"
             )
           ).valid?

    reopened = Exceptions.change(%{"kind" => "reopened", "reason" => "Evidence no longer holds"})
    assert reopened.valid?
    assert Ecto.Changeset.get_field(reopened, :review_by) == nil
  end

  test "client identity and bindings cannot be mass assigned" do
    attrs =
      Map.merge(attrs(), %{
        "actor" => "admin",
        "case_id" => 99,
        "snapshot_id" => 99,
        "expected_revision" => 99,
        "idempotency_token" => "forged",
        "request_hash" => "forged"
      })

    row = Ecto.Changeset.apply_changes(Exceptions.change(attrs))
    assert row.actor == nil and row.case_id == nil and row.snapshot_id == nil

    assert row.expected_revision == nil and row.idempotency_token == nil and
             row.request_hash == nil
  end

  test "expiry starts at UTC review date; changes and later assessments invalidate exceptions" do
    today = ~D[2026-09-16]

    row = %Decision{
      kind: "accepted_risk",
      review_by: Date.add(today, 1),
      snapshot_id: 5,
      expected_revision: 2
    }

    binding = %{evidence_status: :current, current_snapshot_id: 5, revision: 3}
    assert Exceptions.status(row, binding, today) == :accepted_risk
    assert Exceptions.status(%{row | kind: "not_affected"}, binding, today) == :not_affected
    assert Exceptions.status(row, binding, Date.add(today, 1)) == :expired
    assert Exceptions.status(row, %{binding | revision: 4}, today) == :needs_review
    assert Exceptions.status(row, %{binding | current_snapshot_id: 6}, today) == :needs_review

    for status <- [:changed, :source_out_of_scope, :source_missing] do
      assert Exceptions.status(row, %{binding | evidence_status: status}, today) == :needs_review
    end

    assert Exceptions.status(nil, binding, today) == :action_required
    assert Exceptions.status(%{row | kind: "reopened"}, binding, today) == :reopened
  end
end
