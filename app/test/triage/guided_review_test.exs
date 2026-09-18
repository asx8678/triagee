defmodule Triage.GuidedReviewTest do
  use Triage.DataCase, async: true

  import Triage.Fixtures
  alias Triage.{Decisions, Exposure, GuidedReview, Intel}

  setup do
    reset_inventory!()
    image = image!("risk-acceptance")
    placement = placement!(image, "alpha", "prod")
    finding = finding!(image, "CVE-2090-8765", description: "Reviewed evidence")
    row = GuidedReview.get(finding.cve)

    %{
      image: image,
      placement: placement,
      finding: finding,
      fingerprint: GuidedReview.review_fingerprint(row),
      expiry: Date.utc_today() |> Date.add(5) |> Date.to_iso8601()
    }
  end

  test "unchanged evidence can be accepted without ticket configuration or inventory mutation",
       context do
    assert {:ok, decision} = accept(context)
    assert decision.reason == "Reviewed risk"

    assert decision.expires_at ==
             DateTime.new!(Date.from_iso8601!(context.expiry), ~T[23:59:59], "Etc/UTC")

    assert GuidedReview.get(context.finding.cve) == nil
    finding = Repo.reload!(context.finding)
    assert finding.resolved_at == nil
    refute finding.suppressed
  end

  test "missing or incorrect confirmation cannot accept risk", context do
    for fingerprint <- [nil, "", "incorrect"] do
      assert_stale(%{context | fingerprint: fingerprint})
    end
  end

  test "invalid reason and expiry fail without writing a decision", context do
    for {reason, expiry} <- [
          {"", context.expiry},
          {"  ", context.expiry},
          {nil, context.expiry},
          {"Reviewed risk", nil},
          {"Reviewed risk", []},
          {"Reviewed risk", "invalid"},
          {"Reviewed risk", Date.utc_today() |> Date.add(-1) |> Date.to_iso8601()}
        ] do
      assert {:error, :invalid_whitelist} =
               GuidedReview.whitelist(
                 context.finding.cve,
                 reason,
                 expiry,
                 context.fingerprint
               )
    end

    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end

  for {field, value} <- [description: "Changed evidence", severity: "CRITICAL", fix: "2.0.0"] do
    test "changed #{field} invalidates risk acceptance", context do
      context.finding
      |> Ecto.Changeset.change([{unquote(field), unquote(value)}])
      |> Repo.update!()

      assert_stale(context)
    end
  end

  test "newly affected teams invalidate whole-advisory acceptance", context do
    placement!(context.image, "beta", "prod")
    assert_stale(context)
  end

  test "changed exposure invalidates acceptance", context do
    assert {:ok, _} =
             Exposure.record(context.placement.id, "internet_exposed", "test", DateTime.utc_now())

    assert_stale(context)
  end

  test "new KEV evidence invalidates acceptance even if the priority stays critical", context do
    context.finding |> Ecto.Changeset.change(severity: "CRITICAL") |> Repo.update!()
    row = GuidedReview.get(context.finding.cve)
    context = %{context | fingerprint: GuidedReview.review_fingerprint(row)}

    Repo.insert!(%Intel.Advisory{
      source: "kev",
      external_id: context.finding.cve,
      fetched_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })

    assert GuidedReview.get(context.finding.cve).risk.priority == row.risk.priority
    assert_stale(context)
  end

  test "risk confirmation covers evidence for already ticketed teams too", context do
    beta = placement!(context.image, "beta", "prod")
    assert {:ok, requests} = GuidedReview.mark_for_fix(context.finding.cve)
    request = Enum.find(requests, &(&1.owner == "beta"))
    request |> Ecto.Changeset.change(status: "created") |> Repo.update!()
    row = GuidedReview.get(context.finding.cve)
    assert Enum.map(row.pending, & &1.owner) == ["alpha"]
    context = %{context | fingerprint: GuidedReview.review_fingerprint(row)}

    assert {:ok, _} = Exposure.record(beta.id, "internal", "test", DateTime.utc_now())
    assert_stale(context)
  end

  test "planning tickets and refreshing observation timestamps do not change reviewed evidence",
       context do
    assert {:ok, _} = GuidedReview.mark_for_fix(context.finding.cve)
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    context.finding |> Ecto.Changeset.change(last_seen: now) |> Repo.update!()
    context.placement |> Ecto.Changeset.change(last_seen: now) |> Repo.update!()
    row = GuidedReview.get(context.finding.cve)
    assert GuidedReview.review_fingerprint(row) == context.fingerprint
    assert {:ok, _} = accept(context)
  end

  test "resolved evidence cannot be accepted from an old review", context do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    context.finding |> Ecto.Changeset.change(resolved_at: now) |> Repo.update!()
    assert_stale(context)
  end

  defp accept(context) do
    GuidedReview.whitelist(
      context.finding.cve,
      "  Reviewed risk  ",
      context.expiry,
      context.fingerprint
    )
  end

  defp assert_stale(context) do
    assert {:error, :review_changed} = accept(context)
    assert Repo.aggregate(Decisions.Decision, :count) == 0
  end
end
