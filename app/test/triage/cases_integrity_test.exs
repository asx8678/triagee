defmodule Triage.CasesIntegrityTest do
  @moduledoc """
  Adversarial integration tests for the PR 2 review-case contract in `Triage.Cases`.

  These tests exercise the public contract from `app/PR2_PLAN.md` end to end:
  concurrent-open convergence, GET-path purity, database-enforced append-only
  evidence/reviews/events, refresh semantics, exact retry replay vs token
  reuse, conflict and rollback atomicity, scope separation and source-table
  immutability. Assertions use only the public `Triage.Cases` API, the schema
  modules it fixes (`Triage.Cases.ReviewCase`, `Triage.Cases.EvidenceSnapshot`,
  `Triage.Cases.Review`, `Triage.Cases.CaseEvent`) and the synthetic seed data.
  """

  use Triage.DataCase, async: false

  alias Triage.Cases
  alias Triage.Cases.{CaseEvent, EvidenceSnapshot, Review, ReviewCase}
  alias Triage.Inventory

  # From `Triage.Seeds`: image_a carries active placements for teams alpha and
  # beta in "prod-cluster-1"; its openssl finding is CRITICAL with fix "3.2.1".
  @owner "alpha"
  @other_owner "beta"
  @environment "prod-cluster-1"

  @review_attrs %{
    "applicability" => "not_affected_with_evidence",
    "priority" => "normal_review",
    "next_action" => "investigation",
    "rationale" => "Service A does not call the affected OpenSSL code paths."
  }

  setup do
    :ok = Triage.Fixtures.seed()

    finding =
      Repo.one!(
        from f in Inventory.Finding,
          where: f.cve == "CVE-2024-2002" and f.package_name == "openssl"
      )

    %{finding: finding}
  end

  defp open(finding_id, owner \\ @owner, environment \\ @environment),
    do: Cases.open_case(finding_id, owner: owner, environment: environment)

  defp submit(case_id, revision, snapshot_id, token, attrs \\ @review_attrs),
    do: Cases.submit_review(case_id, revision, snapshot_id, token, attrs)

  defp refresh(case_id, revision, snapshot_id),
    do: Cases.refresh_evidence(case_id, revision, snapshot_id)

  defp counts do
    %{
      cases: Repo.aggregate(ReviewCase, :count),
      snapshots: Repo.aggregate(EvidenceSnapshot, :count),
      reviews: Repo.aggregate(Review, :count),
      events: Repo.aggregate(CaseEvent, :count)
    }
  end

  defp case_event_kinds(case_id) do
    Repo.all(from e in CaseEvent, where: e.case_id == ^case_id, select: e.kind, order_by: e.id)
  end

  # The PR2 contract allows direct sandbox source mutations in this file when
  # no public Inventory helper exists (retirement has none).
  defp retire_scoped_placements!(image_id, owner) do
    from(p in Inventory.ImagePlacement, where: p.image_id == ^image_id and p.owner == ^owner)
    |> Repo.update_all(set: [active: false])
  end

  defp source_fingerprint do
    hash_rows = fn schema ->
      schema
      |> order_by([x], x.id)
      |> Repo.all()
      |> :erlang.term_to_binary()
      |> then(&:crypto.hash(:sha256, &1))
      |> Base.encode16()
    end

    %{
      images: hash_rows.(Inventory.Image),
      placements: hash_rows.(Inventory.ImagePlacement),
      findings: hash_rows.(Inventory.Finding),
      events: hash_rows.(Inventory.FindingEvent)
    }
  end

  describe "open_case convergence" do
    test "concurrent same-scope opens converge to one case, one snapshot and one opening event",
         %{finding: finding} do
      parent = self()

      tasks =
        for _ <- 1..2 do
          Task.async(fn ->
            send(parent, {:ready, self()})

            receive do
              :go -> :ok
            end

            open(finding.id)
          end)
        end

      assert_receive {:ready, pid_a}
      assert_receive {:ready, pid_b}
      Enum.each([pid_a, pid_b], &Ecto.Adapters.SQL.Sandbox.allow(Triage.Repo, parent, &1))
      send(pid_a, :go)
      send(pid_b, :go)

      assert [{:ok, first}, {:ok, second}] = Task.await_many(tasks, 5_000)

      assert first.case.id == second.case.id
      assert first.snapshot.id == second.snapshot.id
      assert first.created? != second.created?

      assert Repo.aggregate(ReviewCase, :count) == 1
      assert Repo.aggregate(EvidenceSnapshot, :count) == 1
      assert Repo.aggregate(CaseEvent, :count) == 1
      assert case_event_kinds(first.case.id) == ["case_opened"]

      # a sequential open of the same scope reuses the same case
      assert {:ok, %{case: again, snapshot: same_snapshot, created?: false}} = open(finding.id)
      assert again.id == first.case.id
      assert same_snapshot.id == first.snapshot.id
      assert counts() == %{cases: 1, snapshots: 1, reviews: 0, events: 1}
    end

    test "distinct team and environment scopes yield distinct cases for the same finding",
         %{finding: finding} do
      # All/absence is never a review scope
      assert {:error, :invalid_scope} = open(finding.id, nil, nil)
      assert {:error, :invalid_scope} = open(finding.id, "  ", @environment)

      assert {:ok, %{case: alpha_case, created?: true}} = open(finding.id)
      assert alpha_case.owner == @owner
      assert alpha_case.environment == @environment
      assert alpha_case.revision == 1

      assert {:ok, %{case: beta_case, created?: true}} =
               open(finding.id, @other_owner, @environment)

      assert beta_case.id != alpha_case.id
      assert beta_case.owner == @other_owner

      # a third, explicitly different environment for the same image and team
      image = Repo.get!(Inventory.Image, finding.image_id)

      {:ok, _} =
        Inventory.upsert_placement(
          image,
          %{namespace: "web", owner: @owner, environment: "staging-cluster-9"},
          ~U[2026-09-09 06:00:00Z]
        )

      assert {:ok, %{case: staging_case, created?: true}} =
               open(finding.id, @owner, "staging-cluster-9")

      assert staging_case.id != alpha_case.id
      assert staging_case.environment == "staging-cluster-9"

      # exactly one case, one initial snapshot and one opening event per scope
      assert counts() == %{cases: 3, snapshots: 3, reviews: 0, events: 3}
    end
  end

  describe "read purity" do
    test "get_case creates no rows, even after the source later changes", %{finding: finding} do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      before = counts()

      # a source change must never tempt the read path into capturing anything
      finding |> change(last_seen: ~U[2026-09-10 00:00:00Z]) |> Repo.update!()

      assert {:ok,
              %{
                snapshot: current,
                snapshots: snapshots,
                reviews: [],
                events: events,
                evidence_status: :changed
              }} = Cases.get_case(review_case.id)

      assert current.id == snapshot.id
      assert length(snapshots) == 1
      assert length(events) == 1

      assert {:ok, _} = Cases.get_case(review_case.id)
      assert {:ok, _} = Cases.get_case(review_case.id)
      assert {:ok, _} = Cases.get_case(review_case.id)
      assert counts() == before

      reloaded = Repo.get!(ReviewCase, review_case.id)
      assert reloaded.revision == 1
      assert reloaded.current_snapshot_id == snapshot.id
    end

    test "case flows never mutate source inventory rows", %{finding: finding} do
      before = source_fingerprint()

      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      token = Ecto.UUID.generate()
      assert {:ok, _} = submit(review_case.id, 1, snapshot.id, token)
      assert {:ok, %{changed?: false}} = refresh(review_case.id, 2, snapshot.id)
      assert {:ok, _} = Cases.get_case(review_case.id)

      assert source_fingerprint() == before
    end
  end

  describe "append-only evidence, reviews and events" do
    test "UPDATE and DELETE on snapshot, review and event are rejected by the database", %{
      finding: finding
    } do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      token = Ecto.UUID.generate()
      assert {:ok, %{review: review}} = submit(review_case.id, 1, snapshot.id, token)
      {:ok, %{events: events}} = Cases.get_case(review_case.id)
      [event] = Enum.take(events, 1)

      # Each refusal runs in its own savepoint so the shared sandbox
      # connection stays usable (rollback-to-savepoint) instead of being left
      # in the aborted state of the surrounding transaction.
      assert_raise Postgrex.Error, ~r/append-only/, fn ->
        Repo.transaction(fn -> snapshot |> change(version: 99) |> Repo.update!() end)
      end

      assert_raise Postgrex.Error, ~r/append-only/, fn ->
        Repo.transaction(fn ->
          review |> change(rationale: "tampered after the fact") |> Repo.update!()
        end)
      end

      assert_raise Postgrex.Error, ~r/append-only/, fn ->
        Repo.transaction(fn -> event |> change(kind: "tampered") |> Repo.update!() end)
      end

      assert_raise Postgrex.Error, ~r/append-only/, fn ->
        Repo.transaction(fn -> Repo.delete!(snapshot) end)
      end

      assert_raise Postgrex.Error, ~r/append-only/, fn ->
        Repo.transaction(fn -> Repo.delete!(review) end)
      end

      assert_raise Postgrex.Error, ~r/append-only/, fn ->
        Repo.transaction(fn -> Repo.delete!(event) end)
      end

      # nothing was mutated or removed by the refused statements
      assert counts() == %{cases: 1, snapshots: 1, reviews: 1, events: 2}
      reloaded_review = Repo.get!(Review, review.id)
      assert reloaded_review.rationale == @review_attrs["rationale"]
      reloaded_event = Repo.get!(CaseEvent, event.id)
      assert reloaded_event.kind == event.kind
    end

    test "refresh_evidence is a no-op while content is unchanged and appends when it changes", %{
      finding: finding
    } do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      before = counts()

      assert {:ok, %{changed?: false, case: unchanged_case, snapshot: unchanged_snapshot}} =
               refresh(review_case.id, 1, snapshot.id)

      assert unchanged_snapshot.id == snapshot.id
      assert unchanged_case.revision == 1
      assert unchanged_case.current_snapshot_id == snapshot.id
      assert counts() == before
      assert case_event_kinds(review_case.id) == ["case_opened"]

      finding |> change(severity: "LOW") |> Repo.update!()

      assert {:ok, %{changed?: true, case: advanced_case, snapshot: new_snapshot}} =
               refresh(review_case.id, 1, snapshot.id)

      assert advanced_case.revision == 2
      assert advanced_case.current_snapshot_id == new_snapshot.id
      assert new_snapshot.id != snapshot.id
      assert new_snapshot.version == 2
      assert new_snapshot.case_id == review_case.id
      assert new_snapshot.payload["finding"]["severity"] == "LOW"

      after_refresh = counts()

      assert after_refresh == %{
               before
               | snapshots: before.snapshots + 1,
                 events: before.events + 1
             }

      assert case_event_kinds(review_case.id) == ["case_opened", "evidence_captured"]

      # older evidence stays frozen, byte for byte
      frozen = Repo.get!(EvidenceSnapshot, snapshot.id)
      assert frozen.payload["finding"]["severity"] == "CRITICAL"
      assert frozen.payload_hash == snapshot.payload_hash
      assert frozen.version == 1

      # unchanged again: a no-op under the new binding
      assert {:ok, %{changed?: false, case: still, snapshot: same_again}} =
               refresh(review_case.id, 2, new_snapshot.id)

      assert still.revision == 2
      assert same_again.id == new_snapshot.id
      assert counts() == after_refresh
    end
  end

  describe "idempotent replay vs token reuse" do
    test "exact retry replays the original review without writes, even after later revisions", %{
      finding: finding
    } do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      token = Ecto.UUID.generate()

      assert {:ok, %{case: advanced, review: review, replayed?: false}} =
               submit(review_case.id, 1, snapshot.id, token)

      assert review.actor == "local-operator"
      assert review.case_id == review_case.id
      assert review.snapshot_id == snapshot.id
      assert advanced.revision == 2
      after_submit = counts()

      assert {:ok, %{review: replayed, replayed?: true}} =
               submit(review_case.id, 1, snapshot.id, token)

      assert replayed.id == review.id
      assert counts() == after_submit

      # a later revision must not turn the exact retry into a conflict or duplicate
      finding |> change(last_seen: ~U[2026-09-10 00:00:00Z]) |> Repo.update!()
      assert {:ok, %{changed?: true, snapshot: _newer}} = refresh(review_case.id, 2, snapshot.id)

      assert {:ok, %{review: replayed_again, replayed?: true}} =
               submit(review_case.id, 1, snapshot.id, token)

      assert replayed_again.id == review.id
      assert Repo.aggregate(Review, :count) == 1
      # only the recapture appended an event
      assert counts().events == after_submit.events + 1
    end

    test "same token with a different manual payload is rejected as token reuse", %{
      finding: finding
    } do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      token = Ecto.UUID.generate()
      assert {:ok, _} = submit(review_case.id, 1, snapshot.id, token)
      after_submit = counts()

      other_attrs = %{@review_attrs | "rationale" => "A different manual assessment."}

      assert {:error, :token_reuse} = submit(review_case.id, 1, snapshot.id, token, other_attrs)
      assert counts() == after_submit
    end

    test "same token with a different revision or snapshot binding is never silently replayed",
         %{finding: finding} do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      token = Ecto.UUID.generate()
      assert {:ok, _} = submit(review_case.id, 1, snapshot.id, token)

      finding |> change(last_seen: ~U[2026-09-10 00:00:00Z]) |> Repo.update!()
      assert {:ok, %{snapshot: newer}} = refresh(review_case.id, 2, snapshot.id)
      after_refresh = counts()

      # different revision than the original binding
      assert {:error, :token_reuse} = submit(review_case.id, 3, snapshot.id, token)
      assert counts() == after_refresh

      # different snapshot than the original binding
      assert {:error, :token_reuse} = submit(review_case.id, 1, newer.id, token)
      assert counts() == after_refresh
    end
  end

  describe "conflicts, rollback and staleness" do
    test "stale revision or snapshot bindings conflict with no writes", %{finding: finding} do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      token = Ecto.UUID.generate()
      assert {:ok, _} = submit(review_case.id, 1, snapshot.id, token)
      after_submit = counts()

      # the original binding with a fresh token is now a stale conflict
      assert {:error, :conflict} = submit(review_case.id, 1, snapshot.id, Ecto.UUID.generate())
      assert counts() == after_submit

      finding |> change(last_seen: ~U[2026-09-10 00:00:00Z]) |> Repo.update!()
      assert {:ok, %{snapshot: newer}} = refresh(review_case.id, 2, snapshot.id)
      after_refresh = counts()

      # current revision but a stale snapshot binding: the referenced evidence
      # is not the case's current snapshot, so the domain labels it stale
      # evidence rather than a plain revision conflict
      assert {:error, :evidence_stale} =
               submit(review_case.id, 3, snapshot.id, Ecto.UUID.generate())

      # current snapshot but stale revision binding
      assert {:error, :conflict} = submit(review_case.id, 2, newer.id, Ecto.UUID.generate())
      assert counts() == after_refresh
    end

    test "a forced final review_saved event failure rolls back the review and the revision", %{
      finding: finding
    } do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      before = counts()

      # sabotage only the final review_saved append, inside the sandbox transaction
      Repo.query!(
        "ALTER TABLE review_case_events ADD CONSTRAINT integrity_forced_review_saved " <>
          "CHECK (kind <> 'review_saved')"
      )

      result =
        try do
          submit(review_case.id, 1, snapshot.id, Ecto.UUID.generate())
        rescue
          e in Postgrex.Error -> {:error, {:raised, e}}
        catch
          :exit, reason -> {:error, {:exit, reason}}
        end

      refute match?({:ok, _}, result)

      # the review, the revision bump and the event are all gone
      assert counts() == before
      reloaded = Repo.get!(ReviewCase, review_case.id)
      assert reloaded.revision == 1
      assert reloaded.current_snapshot_id == snapshot.id
      assert case_event_kinds(review_case.id) == ["case_opened"]
    end

    test "a semantic source change marks evidence changed, submit stale, and the old snapshot frozen",
         %{finding: finding} do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      assert {:ok, %{evidence_status: :current}} = Cases.get_case(review_case.id)

      finding |> change(fix: "3.2.2") |> Repo.update!()

      assert {:ok, %{evidence_status: :changed}} = Cases.get_case(review_case.id)
      before = counts()

      assert {:error, :evidence_stale} =
               submit(review_case.id, 1, snapshot.id, Ecto.UUID.generate())

      assert counts() == before

      frozen = Repo.get!(EvidenceSnapshot, snapshot.id)
      assert frozen.payload["finding"]["fix"] == "3.2.1"
      assert frozen.payload_hash == snapshot.payload_hash
    end

    test "retiring every scoped placement fails refresh and submit closed but keeps history readable",
         %{finding: finding} do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      token = Ecto.UUID.generate()
      assert {:ok, _} = submit(review_case.id, 1, snapshot.id, token)
      after_submit = counts()

      {retired, _} = retire_scoped_placements!(finding.image_id, @owner)
      assert retired == 1

      assert {:error, :source_out_of_scope} = refresh(review_case.id, 2, snapshot.id)

      assert {:error, :source_out_of_scope} =
               submit(review_case.id, 2, snapshot.id, Ecto.UUID.generate())

      assert counts() == after_submit

      # the existing case's history stays readable and is labelled out of scope
      assert {:ok,
              %{
                evidence_status: :source_out_of_scope,
                snapshot: still_current,
                snapshots: [_only],
                reviews: reviews,
                events: history_events
              }} = Cases.get_case(review_case.id)

      assert still_current.id == snapshot.id
      assert length(reviews) == 1
      assert length(history_events) == 2

      # reopening the same scope cannot create an unscoped replacement case
      assert {:error, :out_of_scope} = open(finding.id)
    end
  end

  describe "cross-case pointer enforcement" do
    test "a case's current-snapshot pointer cannot be repointed at another case's snapshot (database level)",
         %{finding: finding} do
      {:ok, %{case: alpha, snapshot: alpha_snap}} = open(finding.id)
      {:ok, %{case: beta, snapshot: beta_snap}} = open(finding.id, @other_owner, @environment)

      # Astra defect: the old single-column FK only checked snapshot
      # existence, so UPDATE review_cases SET current_snapshot_id = <other
      # case's snapshot> committed and get_case then returned snapshot: nil.
      # The composite FK (current_snapshot_id, id) -> (id, case_id) must
      # reject it at the DATABASE level. Each attempt runs inside its own
      # transaction and is rolled back with the sandbox afterward.
      assert_raise Postgrex.Error, ~r/review_cases_current_snapshot_fkey/, fn ->
        Repo.transaction(fn ->
          Repo.query!("UPDATE review_cases SET current_snapshot_id = $1 WHERE id = $2", [
            beta_snap.id,
            alpha.id
          ])
        end)
      end

      assert_raise Postgrex.Error, ~r/review_cases_current_snapshot_fkey/, fn ->
        Repo.transaction(fn ->
          Repo.query!("UPDATE review_cases SET current_snapshot_id = $1 WHERE id = $2", [
            alpha_snap.id,
            beta.id
          ])
        end)
      end

      # A same-case pointer move (here: to its own only snapshot) stays legal —
      # the transactional pointer is allowed to move within its own case.
      assert {:ok, _} =
               Repo.transaction(fn ->
                 Repo.query!("UPDATE review_cases SET current_snapshot_id = $1 WHERE id = $2", [
                   alpha_snap.id,
                   alpha.id
                 ])
               end)

      # Nothing was committed: both pointers still resolve within their cases.
      assert {:ok, %{snapshot: current_alpha}} = Cases.get_case(alpha.id)
      assert current_alpha.id == alpha_snap.id
      assert {:ok, %{snapshot: current_beta}} = Cases.get_case(beta.id)
      assert current_beta.id == beta_snap.id
      assert counts() == %{cases: 2, snapshots: 2, reviews: 0, events: 2}
    end
  end

  describe "server-owned metadata" do
    test "forged metadata in review attrs cannot set actor or identity fields", %{
      finding: finding
    } do
      {:ok, %{case: review_case, snapshot: snapshot}} = open(finding.id)
      token = Ecto.UUID.generate()

      forged =
        Map.merge(@review_attrs, %{
          "actor" => "attacker",
          "idempotency_token" => Ecto.UUID.generate(),
          "case_id" => review_case.id + 1000,
          "snapshot_id" => snapshot.id + 1000,
          "request_hash" => "forged"
        })

      case submit(review_case.id, 1, snapshot.id, token, forged) do
        {:ok, %{review: review}} ->
          # ignored: the server-owned values won
          assert review.actor == "local-operator"
          assert review.idempotency_token == token
          assert review.case_id == review_case.id
          assert review.snapshot_id == snapshot.id
          assert review.request_hash != "forged"

        {:error, _reason} ->
          # rejected outright: also acceptable per the contract
          assert Repo.aggregate(Review, :count) == 0
      end
    end
  end
end
