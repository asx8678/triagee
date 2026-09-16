defmodule Triage.ExceptionsTest do
  use Triage.DataCase, async: true
  import Triage.Fixtures
  alias Triage.{Cases, Exceptions, Inventory, Repo}
  alias Triage.Cases.ReviewCase
  alias Triage.Exceptions.Decision

  setup do
    :ok = seed()
    finding = Repo.get_by!(Inventory.Finding, cve: "CVE-2025-1001", package_name: "busybox")

    {:ok, %{case: cse}} =
      Cases.open_case(finding.id, owner: "alpha", environment: "prod-cluster-1")

    %{cse: cse, finding: finding}
  end

  defp attrs(kind \\ "accepted_risk") do
    %{
      "kind" => kind,
      "reason" => "Temporary exception while the dependency upgrade is tested",
      "evidence" => "Build manifest and reachability review SEC-123",
      "review_by" => Date.to_iso8601(Date.add(Date.utc_today(), 30))
    }
  end

  defp save(cse, attrs, token \\ Ecto.UUID.generate()),
    do: Exceptions.submit(cse.id, cse.revision, cse.current_snapshot_id, token, attrs)

  defp status(cse) do
    {:ok, data} = Cases.get_case(cse.id)
    Exceptions.status(List.first(Exceptions.history(cse.id)), Exceptions.binding(data))
  end

  test "persists a local risk exception, keeps source intact and binds its exact scope", %{
    cse: cse,
    finding: finding
  } do
    before = Repo.get!(Inventory.Finding, finding.id)

    {:ok, %{decision: decision}} =
      save(cse, Map.merge(attrs(), %{"actor" => "admin", "case_id" => 9}))

    assert decision.actor == "local-operator"
    assert decision.case_id == cse.id
    assert decision.snapshot_id == cse.current_snapshot_id
    assert decision.expected_revision == cse.revision
    assert Repo.get!(ReviewCase, cse.id).revision == cse.revision + 1
    assert Repo.get!(Inventory.Finding, finding.id) == before
    assert status(cse) == :accepted_risk

    {:ok, %{case: beta}} =
      Cases.open_case(finding.id, owner: "beta", environment: "prod-cluster-1")

    assert status(beta) == :action_required
    statuses = Exceptions.finding_statuses([finding.id])
    assert statuses[{finding.id, "alpha", "prod-cluster-1"}] == :accepted_risk
    assert statuses[{finding.id, "beta", "prod-cluster-1"}] == :action_required
  end

  test "not affected is an evidenced operator decision and reopen retains both records", %{
    cse: cse
  } do
    assert {:error, %Ecto.Changeset{}} = save(cse, Map.delete(attrs("not_affected"), "evidence"))
    assert {:ok, _} = save(cse, attrs("not_affected"))
    assert status(cse) == :not_affected
    fresh = Repo.get!(ReviewCase, cse.id)

    assert {:ok, _} =
             save(fresh, %{"kind" => "reopened", "reason" => "New applicability evidence"})

    assert status(cse) == :reopened
    assert [%{kind: "reopened"}, %{kind: "not_affected"}] = Exceptions.history(cse.id)
  end

  test "exact retries replay; reused tokens and stale tabs cannot overwrite", %{cse: cse} do
    token = Ecto.UUID.generate()
    assert {:ok, %{decision: original, replayed?: false}} = save(cse, attrs(), token)
    assert {:ok, %{decision: ^original, replayed?: true}} = save(cse, attrs(), token)
    assert {:error, :token_reuse} = save(cse, Map.put(attrs(), "reason", "Different"), token)
    assert {:error, :conflict} = save(cse, attrs())
    assert length(Exceptions.history(cse.id)) == 1
  end

  test "malformed bindings fail without writes", %{cse: cse} do
    for bad <- [nil, 0, -1, 9_223_372_036_854_775_808, "1", %{}] do
      assert {:error, :invalid_request} =
               Exceptions.submit(bad, 1, 1, Ecto.UUID.generate(), attrs())
    end

    assert {:error, :invalid_request} = save(cse, attrs(), "not-a-token")

    assert {:error, :conflict} =
             Exceptions.submit(
               cse.id,
               cse.revision,
               cse.current_snapshot_id + 999,
               Ecto.UUID.generate(),
               attrs()
             )

    assert Exceptions.history(cse.id) == []
  end

  test "source drift invalidates a decision and blocks another exception until reviewed", %{
    cse: cse,
    finding: finding
  } do
    assert {:ok, _} = save(cse, attrs())
    Repo.update!(Inventory.Finding.changeset(finding, %{description: "new evidence"}))
    assert status(cse) == :needs_review
    fresh = Repo.get!(ReviewCase, cse.id)
    assert {:error, :evidence_stale} = save(fresh, attrs())

    assert {:ok, _} =
             save(fresh, %{"kind" => "reopened", "reason" => "Investigate changed evidence"})

    assert status(cse) == :reopened
  end

  test "retired placement cannot acquire an exception; reopening still works", %{
    cse: cse,
    finding: finding
  } do
    assert {:ok, _} = save(cse, attrs())

    Repo.update_all(
      from(p in Inventory.ImagePlacement,
        where: p.image_id == ^finding.image_id and p.owner == "alpha"
      ),
      set: [active: false]
    )

    assert status(cse) == :needs_review
    fresh = Repo.get!(ReviewCase, cse.id)
    assert {:error, :evidence_stale} = save(fresh, attrs("not_affected"))
    assert {:ok, _} = save(fresh, %{"kind" => "reopened", "reason" => "Placement retired"})
  end

  test "a subsequent manual assessment returns local exception to needs review", %{cse: cse} do
    assert {:ok, _} = save(cse, attrs())
    fresh = Repo.get!(ReviewCase, cse.id)

    assert {:ok, _} =
             Cases.submit_review(
               fresh.id,
               fresh.revision,
               fresh.current_snapshot_id,
               Ecto.UUID.generate(),
               %{
                 "applicability" => "unknown",
                 "priority" => "expedited_review",
                 "next_action" => "investigation",
                 "rationale" => "Reconsidering applicability"
               }
             )

    assert status(cse) == :needs_review
  end

  test "refresh does not renew an old exception; re-review can create a new one", %{
    cse: cse,
    finding: finding
  } do
    assert {:ok, _} = save(cse, attrs())
    Repo.update!(Inventory.Finding.changeset(finding, %{description: "New evidence"}))
    fresh = Repo.get!(ReviewCase, cse.id)

    {:ok, %{case: refreshed}} =
      Cases.refresh_evidence(fresh.id, fresh.revision, fresh.current_snapshot_id)

    assert status(cse) == :needs_review
    assert {:ok, _} = save(refreshed, attrs("not_affected"))
    assert status(cse) == :not_affected
    assert length(Exceptions.history(cse.id)) == 2
  end

  test "expired persisted decisions return to action required without writes", %{cse: cse} do
    assert {:ok, _} = save(cse, %{"kind" => "reopened", "reason" => "Initial review"})
    old = DateTime.add(DateTime.utc_now(), -3, :day) |> DateTime.truncate(:second)

    row =
      Repo.insert!(%Decision{
        case_id: cse.id,
        snapshot_id: cse.current_snapshot_id,
        expected_revision: cse.revision,
        idempotency_token: Ecto.UUID.generate(),
        request_hash: "fixture",
        actor: "local-operator",
        kind: "accepted_risk",
        reason: "Historical test fixture",
        review_by: Date.add(Date.utc_today(), -1),
        inserted_at: old
      })

    revision = Repo.get!(ReviewCase, cse.id).revision
    assert status(cse) == :expired
    assert Exceptions.latest_index([cse.id])[cse.id].review_by == row.review_by
    assert Repo.get!(ReviewCase, cse.id).revision == revision
    assert length(Exceptions.history(cse.id)) == 2
  end

  test "same-case snapshot constraint cannot be bypassed", %{cse: cse, finding: finding} do
    {:ok, %{case: beta}} =
      Cases.open_case(finding.id, owner: "beta", environment: "prod-cluster-1")

    forged =
      Exceptions.change(attrs())
      |> Ecto.Changeset.change(
        case_id: cse.id,
        snapshot_id: beta.current_snapshot_id,
        expected_revision: cse.revision,
        idempotency_token: Ecto.UUID.generate(),
        request_hash: "fixture",
        actor: "local-operator"
      )

    assert_raise Ecto.ConstraintError, fn ->
      Repo.transaction(fn -> Repo.insert!(forged) end)
    end

    assert Exceptions.history(cse.id) == []
  end

  test "decisions are immutable at the database layer", %{cse: cse} do
    {:ok, %{decision: row}} = save(cse, attrs())

    assert_raise Postgrex.Error, fn ->
      Repo.transaction(fn ->
        Repo.update_all(from(d in Decision, where: d.id == ^row.id),
          set: [reason: "rewrite history"]
        )
      end)
    end

    assert_raise Postgrex.Error, fn ->
      Repo.transaction(fn -> Repo.delete!(row) end)
    end

    assert Exceptions.history(cse.id) == [row]
  end
end
