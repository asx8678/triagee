defmodule Triage.CasesTest do
  @moduledoc """
  Targeted tests for the PR 2 domain slice: scoped case identity, frozen
  evidence, append-only enforcement and review idempotence/conflict ordering.
  Restart/migration probes on a disposable database are handled by the
  serialized integrator, not here.
  """

  use Triage.DataCase, async: true

  alias Triage.{Cases, Inventory, Repo}
  alias Triage.Cases.{CaseEvent, EvidenceSnapshot, Review, ReviewCase}

  @env "prod"
  @scope [owner: "alpha", environment: "prod"]

  @review_attrs %{
    "applicability" => "affected",
    "priority" => "normal_review",
    "next_action" => "investigation",
    "rationale" => "Confirmed load path via the synthetic fixture."
  }

  setup do
    :ok = Triage.CaseFixtures.seed()
    :ok
  end

  defp finding_id(cve, package, version \\ nil) do
    query = from(f in Inventory.Finding, where: f.cve == ^cve and f.package_name == ^package)

    query =
      if version, do: where(query, [f], f.package_version == ^version), else: query

    Repo.one!(query).id
  end

  defp counts do
    %{
      cases: Repo.aggregate(ReviewCase, :count),
      snapshots: Repo.aggregate(EvidenceSnapshot, :count),
      reviews: Repo.aggregate(Review, :count),
      events: Repo.aggregate(CaseEvent, :count)
    }
  end

  defp retire_scope(finding_id) do
    finding = Repo.get!(Inventory.Finding, finding_id)

    placement =
      Repo.get_by!(Inventory.ImagePlacement,
        image_id: finding.image_id,
        owner: "alpha",
        environment: @env
      )

    placement
    |> Inventory.ImagePlacement.changeset(%{active: false})
    |> Repo.update!()

    :ok
  end

  defp touch_source(finding_id) do
    Repo.get!(Inventory.Finding, finding_id)
    |> Inventory.Finding.changeset(%{last_seen: ~U[2026-09-10 06:00:00Z]})
    |> Repo.update!()

    :ok
  end

  test "opening creates a case with one frozen snapshot and opening event" do
    fid = finding_id("CVE-2025-1001", "busybox")

    assert {:ok, %{case: cse, snapshot: snap, created?: true}} = Cases.open_case(fid, @scope)

    assert cse.revision == 1
    assert cse.current_snapshot_id == snap.id
    assert snap.version == 1
    assert snap.captured_at

    assert snap.payload["schema_version"] == 1
    assert snap.payload["source"] == "synthetic_local_inventory"
    assert snap.payload["scope"] == %{"owner" => "alpha", "environment" => @env}

    assert snap.payload["finding"]["cve"] == "CVE-2025-1001"
    assert snap.payload["finding"]["package_name"] == "busybox"

    assert Regex.match?(
             ~r/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/,
             snap.payload["finding"]["first_seen"]
           )

    # Only scoped placements are captured, deterministically sorted.
    assert [%{"owner" => "alpha"}] = snap.payload["placements"]

    assert [%{"event" => "appeared"}] = snap.payload["events"]

    # Coverage is an explicit warning, not a completeness assertion.
    assert snap.payload["coverage"]["warning"] =~ "completeness"

    # No ORM timestamps or capture time leak into the frozen content.
    refute Map.has_key?(snap.payload["finding"], "inserted_at")
    refute Map.has_key?(snap.payload["finding"], "updated_at")
    refute Map.has_key?(snap.payload, "captured_at")

    assert Regex.match?(~r/^[0-9a-f]{64}$/, snap.payload_hash)

    assert [%CaseEvent{kind: "case_opened"}] = Repo.all(CaseEvent)
    assert %CaseEvent{} = Repo.get_by!(CaseEvent, case_id: cse.id, snapshot_id: snap.id)
  end

  test "unknown namespace and other context values are preserved, never guessed" do
    fid = finding_id("CVE-2024-4004", "zlib", "1.2.13")

    # The (unknown)-namespace image runs for alpha in the dev environment.
    assert {:ok, %{snapshot: snap}} = Cases.open_case(fid, owner: "alpha", environment: "dev")

    assert [%{"namespace" => "(unknown)", "owner" => "alpha"}] = snap.payload["placements"]
  end

  test "same finding across distinct scopes yields distinct cases" do
    fid = finding_id("CVE-2025-1001", "busybox")

    assert {:ok, %{case: alpha, created?: true}} = Cases.open_case(fid, @scope)

    assert {:ok, %{case: beta, created?: true}} =
             Cases.open_case(fid, owner: "beta", environment: @env)

    assert alpha.id != beta.id

    assert counts() == %{cases: 2, snapshots: 2, reviews: 0, events: 2}
  end

  test "invalid, blank and All scopes never create a case" do
    fid = finding_id("CVE-2025-1001", "busybox")

    for bad <- [
          "",
          "   ",
          "All",
          "ALL",
          String.duplicate("a", 121),
          "alpha\n",
          "alpha\0",
          <<0xFF>>,
          :alpha,
          5,
          ["alpha"]
        ] do
      assert {:error, :invalid_scope} = Cases.open_case(fid, owner: bad, environment: @env)
    end

    assert {:error, :invalid_scope} = Cases.open_case(fid, owner: "alpha")
    assert {:error, :invalid_scope} = Cases.open_case(fid, environment: @env)
    assert {:error, :invalid_request} = Cases.open_case(fid, nil)
    assert {:error, :invalid_request} = Cases.open_case(fid, "owner=alpha")

    # Unknown scope is not authorization: nothing unscoped is ever created.
    assert {:error, :out_of_scope} =
             Cases.open_case(fid, owner: "no-such-team", environment: @env)

    assert counts() == %{cases: 0, snapshots: 0, reviews: 0, events: 0}
  end

  test "malformed finding ids return controlled errors before any query" do
    for bad <- ["12", 0, -1, true, 1.5, Integer.pow(2, 63)] do
      assert {:error, :invalid_request} = Cases.open_case(bad, @scope)
    end

    assert {:error, :not_found} = Cases.open_case(999_999_999_999, @scope)
  end

  test "sequential opens are idempotent and never refresh evidence" do
    fid = finding_id("CVE-2025-1001", "busybox")

    assert {:ok, %{case: first, snapshot: snap, created?: true}} = Cases.open_case(fid, @scope)

    # Opt forms and map/string-key forms converge on the same case.
    assert {:ok, %{case: again, snapshot: snap_again, created?: false}} =
             Cases.open_case(fid, %{owner: " alpha ", environment: @env})

    assert again.id == first.id
    assert snap_again.id == snap.id
    assert Repo.get!(ReviewCase, first.id).owner == "alpha"

    assert counts() == %{cases: 1, snapshots: 1, reviews: 0, events: 1}
  end

  test "parallel opens converge on exactly one case, snapshot and event" do
    fid = finding_id("CVE-2025-1001", "busybox")

    # Tasks share the test's sandbox connection (serialized at the connection
    # level by DBConnection), which still exercises the unique-index
    # convergence path: exactly one insert wins, the rest join the winner.
    # Each task waits for :go so the sandbox allowance is granted before any
    # query runs.
    parent = self()

    tasks =
      for _ <- 1..4 do
        Task.async(fn ->
          send(parent, {:ready, self()})

          receive do
            :go -> :ok
          end

          Cases.open_case(fid, @scope)
        end)
      end

    Enum.each(tasks, fn task ->
      assert_receive {:ready, _pid}
      Ecto.Adapters.SQL.Sandbox.allow(Triage.Repo, self(), task.pid)
    end)

    Enum.each(tasks, fn task -> send(task.pid, :go) end)

    results = Task.await_many(tasks)

    assert Enum.all?(results, &match?({:ok, %{case: %ReviewCase{}}}, &1))
    assert Enum.count(results, fn {:ok, %{created?: created?}} -> created? end) == 1

    assert results
           |> Enum.map(fn {:ok, %{case: cse}} -> cse.id end)
           |> Enum.uniq()
           |> length() == 1

    assert counts() == %{cases: 1, snapshots: 1, reviews: 0, events: 1}
  end

  test "get_case is a pure read returning ordered history and derived status" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    before = counts()

    assert {:ok, data} = Cases.get_case(cse.id)

    assert data.evidence_status == :current
    assert data.snapshot.id == snap.id
    assert Enum.map(data.snapshots, & &1.id) == [snap.id]
    assert Enum.map(data.events, & &1.kind) == ["case_opened"]
    assert data.reviews == []
    assert data.case.id == cse.id

    # Reads never create rows.
    assert counts() == before

    assert {:error, :not_found} = Cases.get_case(cse.id + 1_000_000)
    assert {:error, :invalid_request} = Cases.get_case("7")
    assert {:error, :invalid_request} = Cases.get_case(nil)
  end

  test "retiring the scoped placement keeps history readable but fails closed" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    :ok = retire_scope(fid)

    assert {:ok, %{evidence_status: :source_out_of_scope}} = Cases.get_case(cse.id)

    assert {:error, :source_out_of_scope} =
             Cases.refresh_evidence(cse.id, cse.revision, snap.id)

    assert {:error, :source_out_of_scope} =
             Cases.submit_review(
               cse.id,
               cse.revision,
               snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    # No unscoped snapshot was taken and history is intact.
    assert counts() == %{cases: 1, snapshots: 1, reviews: 0, events: 1}
  end

  test "a source change is detected as :changed without mutating old evidence" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    :ok = touch_source(fid)

    assert {:ok, %{evidence_status: :changed}} = Cases.get_case(cse.id)

    # Detection is read-only: no snapshot was appended by the status check.
    assert counts() == %{cases: 1, snapshots: 1, reviews: 0, events: 1}
    assert Repo.get!(EvidenceSnapshot, snap.id).payload_hash == snap.payload_hash
  end

  test "refresh is a no-op on unchanged content and appends only when changed" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    assert {:ok, %{changed?: false, case: cse2, snapshot: snap2}} =
             Cases.refresh_evidence(cse.id, cse.revision, snap.id)

    assert cse2.revision == 1
    assert snap2.id == snap.id
    assert counts() == %{cases: 1, snapshots: 1, reviews: 0, events: 1}

    :ok = touch_source(fid)

    assert {:ok, %{changed?: true, case: cse3, snapshot: fresh}} =
             Cases.refresh_evidence(cse.id, cse.revision, snap.id)

    assert cse3.revision == 2
    assert fresh.version == 2
    assert fresh.id != snap.id
    assert fresh.payload["finding"]["last_seen"] == "2026-09-10T06:00:00Z"

    assert Enum.map(Repo.all(CaseEvent), & &1.kind) == ["case_opened", "evidence_captured"]

    # Older evidence is never modified.
    assert Repo.get!(EvidenceSnapshot, snap.id).payload_hash == snap.payload_hash

    # Stale bindings are refused without writes.
    assert {:error, :conflict} = Cases.refresh_evidence(cse.id, 1, snap.id)
    assert {:error, :conflict} = Cases.refresh_evidence(cse.id, 2, snap.id)
    assert {:error, :invalid_request} = Cases.refresh_evidence(cse.id, 0, fresh.id)
    assert {:error, :invalid_request} = Cases.refresh_evidence("abc", 2, fresh.id)
    assert {:error, :not_found} = Cases.refresh_evidence(cse.id + 1_000_000, 2, fresh.id)

    assert counts() == %{cases: 1, snapshots: 2, reviews: 0, events: 2}
  end

  test "submit ordering: exact retry replays, reuse is rejected, conflicts are safe" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    token = Ecto.UUID.generate()

    assert {:ok, %{case: saved_case, review: review, replayed?: false}} =
             Cases.submit_review(cse.id, 1, snap.id, token, @review_attrs)

    assert saved_case.revision == 2
    assert review.actor == "local-operator"
    assert review.snapshot_id == snap.id

    # Exact retry of the same token, payload and binding replays with no writes.
    assert {:ok, %{review: replay, replayed?: true}} =
             Cases.submit_review(cse.id, 1, snap.id, token, @review_attrs)

    assert replay.id == review.id

    # Same token, different payload: token_reuse, never a silent replay.
    assert {:error, :token_reuse} =
             Cases.submit_review(cse.id, 1, snap.id, token, %{
               @review_attrs
               | "rationale" => "Different assessment."
             })

    # Same token, different binding: still token_reuse.
    assert {:error, :token_reuse} =
             Cases.submit_review(cse.id, 2, snap.id, token, @review_attrs)

    # Stale revision with a fresh token: conflict, no writes.
    assert {:error, :conflict} =
             Cases.submit_review(cse.id, 1, snap.id, Ecto.UUID.generate(), @review_attrs)

    assert counts() == %{cases: 1, snapshots: 1, reviews: 1, events: 2}

    # After later revisions, the original submission still replays exactly.
    :ok = touch_source(fid)

    {:ok, %{case: cse3}} = Cases.refresh_evidence(cse.id, 2, snap.id)

    assert cse3.revision == 3

    assert {:ok, %{review: late_replay, replayed?: true}} =
             Cases.submit_review(cse.id, 1, snap.id, token, @review_attrs)

    assert late_replay.id == review.id

    # A review bound to an older snapshot is evidence_stale.
    assert {:error, :evidence_stale} =
             Cases.submit_review(
               cse.id,
               cse3.revision,
               snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    assert counts() == %{cases: 1, snapshots: 2, reviews: 1, events: 3}
  end

  test "submitting against evidence the source has since left behind fails closed" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    :ok = touch_source(fid)

    assert {:error, :evidence_stale} =
             Cases.submit_review(
               cse.id,
               cse.revision,
               snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    # Recapture first, then the same assessment saves cleanly.
    {:ok, %{case: cse2, snapshot: snap2}} = Cases.refresh_evidence(cse.id, cse.revision, snap.id)

    assert {:ok, %{replayed?: false}} =
             Cases.submit_review(
               cse2.id,
               cse2.revision,
               snap2.id,
               Ecto.UUID.generate(),
               @review_attrs
             )
  end

  test "malformed submissions return controlled errors" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    for {case_id, rev, snap_id, token} <- [
          {"x", 1, snap.id, Ecto.UUID.generate()},
          {0, 1, snap.id, Ecto.UUID.generate()},
          {cse.id, -1, snap.id, Ecto.UUID.generate()},
          {cse.id, 1, "x", Ecto.UUID.generate()},
          {cse.id, 1, snap.id, ""},
          {cse.id, 1, snap.id, nil},
          {cse.id, 1, snap.id, 5},
          {cse.id + 1_000_000, 1, snap.id, Ecto.UUID.generate()}
        ] do
      assert {:error, error} = Cases.submit_review(case_id, rev, snap_id, token, @review_attrs)
      assert error in [:invalid_request, :not_found]
    end

    # Malformed attrs shapes are controlled request errors, never raises.
    for attrs <- [123, nil, "a binary", [], [a: 1], [:not_a_keyword], %{rationale: "atom"}] do
      assert {:error, :invalid_request} =
               Cases.submit_review(cse.id, 1, snap.id, Ecto.UUID.generate(), attrs)
    end

    assert counts() == %{cases: 1, snapshots: 1, reviews: 0, events: 1}
  end

  test "malformed review attrs return controlled errors instead of raising" do
    # change_review keeps its documented changeset return shape, marked invalid
    # with a form-level error; submit_review rejects the same shapes outright
    # with no writes. Astra defect: lists/keyword lists/atom-keyed maps used
    # to raise Ecto.CastError or escape validation.
    for attrs <- [
          [],
          nil,
          [a: 1],
          [:not_a_keyword],
          "a binary",
          123,
          %{rationale: "atom key"},
          Map.put(@review_attrs, :forged_meta, "atom key"),
          %{"rationale" => "ok", :actor => "root"}
        ] do
      changeset = Cases.change_review(attrs)
      assert %Ecto.Changeset{} = changeset
      refute changeset.valid?, inspect(attrs)

      assert "malformed request: manual review parameters must be a string-keyed map" in errors_on(
               changeset
             ).rationale
    end

    # Valid string-keyed maps still validate normally, and an empty map is a
    # valid (blank) form shape, not a malformed one.
    assert Cases.change_review(@review_attrs).valid?
    refute Cases.change_review(%{}).valid?

    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    for attrs <- [[], nil, [a: 1], "a binary", 123, %{rationale: "atom key"}] do
      assert {:error, :invalid_request} =
               Cases.submit_review(cse.id, 1, snap.id, Ecto.UUID.generate(), attrs)
    end

    assert counts() == %{cases: 1, snapshots: 1, reviews: 0, events: 1}
  end

  test "struct attrs are rejected as malformed instead of raising" do
    # Astra defect: manual_changeset/1's `when is_map(attrs)` guard admitted
    # structs, then Enum.all?/2 raised Protocol.UndefinedError on
    # non-enumerable structs (%URI{}) and FunctionClauseError on finite
    # Enumerable structs (MapSet, Range). Every struct shape must fail closed.
    struct_attrs = [
      %URI{path: "/"},
      %Review{rationale: "forged"},
      ~D[2026-08-05],
      %Ecto.Changeset{data: %Review{}},
      MapSet.new(@review_attrs),
      1..2
    ]

    for attrs <- struct_attrs do
      changeset = Cases.change_review(attrs)
      assert %Ecto.Changeset{} = changeset
      refute changeset.valid?, inspect(attrs)

      assert "malformed request: manual review parameters must be a string-keyed map" in errors_on(
               changeset
             ).rationale
    end

    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    for attrs <- struct_attrs do
      assert {:error, :invalid_request} =
               Cases.submit_review(cse.id, 1, snap.id, Ecto.UUID.generate(), attrs)
    end

    # No review, audit event, revision bump, snapshot or source change.
    assert Repo.reload(cse).revision == 1
    assert counts() == %{cases: 1, snapshots: 1, reviews: 0, events: 1}

    # Valid plain string-keyed maps still work; the empty-map form is
    # unchanged.
    assert Cases.change_review(@review_attrs).valid?
    refute Cases.change_review(%{}).valid?

    assert {:ok, %{replayed?: false}} =
             Cases.submit_review(cse.id, 1, snap.id, Ecto.UUID.generate(), @review_attrs)

    assert counts() == %{cases: 1, snapshots: 1, reviews: 1, events: 2}
  end

  test "non-UUID idempotency tokens are rejected before any write" do
    # Astra defect: a NUL-containing token reached the insert and raised
    # Postgrex 22021. The server only ever issues Ecto.UUID.generate/0
    # tokens, so anything else is forged and must fail closed.
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    for token <- [
          "bad\0token",
          "",
          "   ",
          nil,
          5,
          "server-token",
          String.duplicate(Ecto.UUID.generate(), 2),
          String.slice(Ecto.UUID.generate(), 0, 35),
          <<0xFF>>
        ] do
      assert {:error, :invalid_request} =
               Cases.submit_review(cse.id, 1, snap.id, token, @review_attrs)
    end

    assert counts() == %{cases: 1, snapshots: 1, reviews: 0, events: 1}
  end

  test "change_review validates exactly the four manual fields" do
    assert Cases.change_review(@review_attrs).valid?

    # Ordinary textarea newline/tab content is allowed.
    assert Cases.change_review(%{@review_attrs | "rationale" => "line one\nline two\tindented"}).valid?

    for attrs <-
          [
            %{@review_attrs | "rationale" => ""},
            %{@review_attrs | "rationale" => "   "},
            %{@review_attrs | "rationale" => String.duplicate("a", 2001)},
            %{@review_attrs | "rationale" => "has\0nul"},
            %{@review_attrs | "rationale" => "has\x01control"},
            %{@review_attrs | "rationale" => "has" <> <<0x7F>>},
            %{@review_attrs | "rationale" => <<"bad", 0xFF>>},
            %{@review_attrs | "applicability" => "approved"},
            %{@review_attrs | "priority" => "urgent"},
            %{@review_attrs | "next_action" => "mitigate_now"}
          ] do
      changeset = Cases.change_review(attrs)
      refute changeset.valid?, inspect(attrs)
    end

    # Rationale is trimmed and the assessment vocabulary is exact.
    assert {:rationale, "trimmed"} in (Cases.change_review(%{
                                         @review_attrs
                                         | "rationale" => "  trimmed  "
                                       }).changes
                                       |> Enum.to_list())

    # Forged metadata keys are never cast.
    forged =
      Map.merge(@review_attrs, %{
        "actor" => "root",
        "case_id" => 99,
        "snapshot_id" => 1,
        "idempotency_token" => "forged",
        "request_hash" => "forged"
      })

    changeset = Cases.change_review(forged)

    assert changeset.valid?

    assert changeset.changes |> Map.keys() |> Enum.sort() == [
             :applicability,
             :next_action,
             :priority,
             :rationale
           ]
  end

  test "server-side metadata cannot be mass-assigned on submit" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    forged =
      Map.merge(@review_attrs, %{
        "actor" => "root",
        "case_id" => cse.id + 1_000,
        "snapshot_id" => snap.id + 1_000,
        "idempotency_token" => "forged",
        "request_hash" => "forged"
      })

    token = Ecto.UUID.generate()

    assert {:ok, %{review: review}} = Cases.submit_review(cse.id, 1, snap.id, token, forged)

    assert review.actor == "local-operator"
    assert review.idempotency_token == token
    assert review.request_hash != "forged"
    assert review.case_id == cse.id
    assert review.snapshot_id == snap.id
  end

  test "a failure in the final event insert rolls back review and revision" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    # Force the final audit append to fail inside the sandbox transaction
    # (rolled back with the test); immutability triggers are not weakened.
    Repo.query!("""
    CREATE FUNCTION triage_test_boom() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'boom';
    END;
    $$ LANGUAGE plpgsql
    """)

    Repo.query!(
      "CREATE TRIGGER review_case_events_boom BEFORE INSERT ON review_case_events FOR EACH ROW EXECUTE FUNCTION triage_test_boom()"
    )

    assert {:error, %Postgrex.Error{}} =
             Cases.submit_review(cse.id, 1, snap.id, Ecto.UUID.generate(), @review_attrs)

    # Nothing survived: no review, no revision bump, no event.
    assert Repo.aggregate(Review, :count) == 0
    assert Repo.get!(ReviewCase, cse.id).revision == 1
    assert Enum.map(Repo.all(CaseEvent), & &1.kind) == ["case_opened"]

    Repo.query!("DROP TRIGGER review_case_events_boom ON review_case_events")
    Repo.query!("DROP FUNCTION triage_test_boom()")

    # The same submission then succeeds atomically.
    assert {:ok, %{replayed?: false, case: cse2}} =
             Cases.submit_review(cse.id, 1, snap.id, Ecto.UUID.generate(), @review_attrs)

    assert cse2.revision == 2
    assert Repo.aggregate(Review, :count) == 1
  end

  test "snapshots, reviews and events reject UPDATE and DELETE" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(fid, @scope)

    {:ok, %{review: review}} =
      Cases.submit_review(cse.id, 1, snap.id, Ecto.UUID.generate(), @review_attrs)

    event = Repo.one!(from e in CaseEvent, where: e.kind == "review_saved")

    # Each attempt runs in its own transaction so a rejection leaves the
    # sandbox connection usable (savepoint rollback).
    assert_raise Postgrex.Error, ~r/append-only/, fn ->
      Repo.transaction(fn -> snap |> change(version: 99) |> Repo.update!() end)
    end

    assert_raise Postgrex.Error, ~r/append-only/, fn ->
      Repo.transaction(fn -> Repo.delete!(snap) end)
    end

    assert_raise Postgrex.Error, ~r/append-only/, fn ->
      Repo.transaction(fn -> review |> change(rationale: "tampered") |> Repo.update!() end)
    end

    assert_raise Postgrex.Error, ~r/append-only/, fn ->
      Repo.transaction(fn -> Repo.delete!(review) end)
    end

    assert_raise Postgrex.Error, ~r/append-only/, fn ->
      Repo.transaction(fn -> event |> change(kind: "forged") |> Repo.update!() end)
    end

    assert_raise Postgrex.Error, ~r/append-only/, fn ->
      Repo.transaction(fn -> Repo.delete!(event) end)
    end

    # Rows are untouched and the case pointer still resolves.
    assert Repo.get!(EvidenceSnapshot, snap.id).version == 1
    assert Repo.get!(Review, review.id).rationale == review.rationale
    assert counts() == %{cases: 1, snapshots: 1, reviews: 1, events: 2}
  end

  test "a review can never point at another case's snapshot" do
    fid = finding_id("CVE-2025-1001", "busybox")

    {:ok, %{case: _alpha, snapshot: alpha_snap}} = Cases.open_case(fid, @scope)
    {:ok, %{case: beta}} = Cases.open_case(fid, owner: "beta", environment: @env)

    # The public API refuses the cross-case binding before any insert.
    assert {:error, :evidence_stale} =
             Cases.submit_review(
               beta.id,
               beta.revision,
               alpha_snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    # The composite FK is the database-level backstop.
    forged = %Review{
      case_id: beta.id,
      snapshot_id: alpha_snap.id,
      expected_revision: 1,
      idempotency_token: Ecto.UUID.generate(),
      request_hash: "forged",
      actor: "local-operator",
      applicability: "affected",
      priority: "normal_review",
      next_action: "investigation",
      rationale: "cross-case pointer"
    }

    assert_raise Ecto.ConstraintError, fn ->
      Repo.transaction(fn -> Repo.insert!(forged) end)
    end

    assert counts() == %{cases: 2, snapshots: 2, reviews: 0, events: 2}
  end

  test "a resolved finding with an active placement can still be captured and reviewed" do
    fid = finding_id("CVE-2023-5005", "gzip")

    assert {:ok, %{snapshot: snap}} = Cases.open_case(fid, @scope)

    assert snap.payload["finding"]["resolved_at"] == "2026-08-05T06:00:00Z"
    assert [%{"event" => "appeared"}, %{"event" => "resolved"}] = snap.payload["events"]

    assert {:ok, %{replayed?: false}} =
             Cases.submit_review(snap.case_id, 1, snap.id, Ecto.UUID.generate(), @review_attrs)
  end
end
