defmodule Triage.CasesQueueTest do
  @moduledoc """
  Read-only Review Queue read-model tests (PR 3): request/scope validation
  with zero queries, AND-scope filtering, fixed 25-row keyset pagination,
  the two-axis status truth table, differential agreement with `get_case/1`,
  frozen display text, read purity and the SELECT query budget.
  """

  use Triage.DataCase, async: true

  import Ecto.Query

  alias Triage.{Cases, Inventory, Repo}
  alias Triage.Cases.{CaseEvent, EvidenceSnapshot, Review, ReviewCase}

  @env "prod"
  @scope [owner: "alpha", environment: @env]
  @max_id Integer.pow(2, 63) - 1

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

  ## Helpers (cases_test.exs patterns)

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
      events: Repo.aggregate(CaseEvent, :count),
      images: Repo.aggregate(Inventory.Image, :count),
      placements: Repo.aggregate(Inventory.ImagePlacement, :count),
      findings: Repo.aggregate(Inventory.Finding, :count),
      finding_events: Repo.aggregate(Inventory.FindingEvent, :count)
    }
  end

  defp open_case!(finding_id, opts) do
    assert {:ok, %{case: cse, snapshot: snap}} = Cases.open_case(finding_id, opts)
    {cse, snap}
  end

  defp place!(image_id, owner, environment, opts \\ []) do
    now = ~U[2026-09-09 06:00:00Z]

    %Inventory.ImagePlacement{}
    |> Inventory.ImagePlacement.changeset(%{
      image_id: image_id,
      namespace: Keyword.get(opts, :namespace, "ns-" <> owner),
      owner: owner,
      environment: environment,
      active: Keyword.get(opts, :active, true),
      first_seen: now,
      last_seen: now
    })
    |> Repo.insert!()
  end

  # Opens `count` distinct one-team-scope cases on one finding occurrence.
  # Insertion order gives ascending ids; the queue must show them id DESC.
  defp open_scope_cases(count, finding_id) do
    image_id = Repo.get!(Inventory.Finding, finding_id).image_id

    for i <- 1..count do
      owner = "team-" <> Integer.to_string(i)
      place!(image_id, owner, @env)
      {cse, _snap} = open_case!(finding_id, owner: owner, environment: @env)
      cse
    end
  end

  defp queue_row_for(case_id) do
    cse = Repo.get!(ReviewCase, case_id)

    assert {:ok, %{rows: rows}} =
             Cases.list_cases(owner: cse.owner, environment: cse.environment)

    assert row = Enum.find(rows, &(&1.id == case_id))
    row
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

  # Content fingerprints prove purity better than counts: rows and their
  # payloads, hashes and revisions must be byte-identical across reads.
  @purity_tables [
    ReviewCase,
    EvidenceSnapshot,
    Review,
    CaseEvent,
    Inventory.Image,
    Inventory.ImagePlacement,
    Inventory.Finding,
    Inventory.FindingEvent
  ]

  defp fingerprints do
    Map.new(@purity_tables, fn schema ->
      fingerprint =
        schema
        |> Repo.all()
        |> Enum.sort_by(& &1.id)
        |> Enum.map(&Map.from_struct/1)
        |> :erlang.term_to_binary()
        |> :erlang.md5()

      {schema, fingerprint}
    end)
  end

  # Counts [:triage, :repo, :query] telemetry events during one isolated
  # call, with fixture setup excluded: a direct SELECT budget check, never a
  # latency claim.
  defp count_queries(fun) do
    counter = :counters.new(1, [])
    id = "cases-queue-" <> Integer.to_string(:erlang.unique_integer([:positive, :monotonic]))

    :ok =
      :telemetry.attach(
        id,
        [:triage, :repo, :query],
        fn _event, _measurements, _metadata, _config -> :counters.add(counter, 1, 1) end,
        nil
      )

    try do
      fun.()
    after
      :ok = :telemetry.detach(id)
    end

    :counters.get(counter, 1)
  end

  # Captures the SQL of every query telemetry event during one isolated call
  # (fixture setup excluded): before/after evidence for which SELECT families
  # hydrate the queue binding.
  defp capture_queries(fun) do
    parent = self()
    id = "cases-queue-sql-" <> Integer.to_string(:erlang.unique_integer([:positive, :monotonic]))

    :ok =
      :telemetry.attach(
        id,
        [:triage, :repo, :query],
        fn _event, _measurements, metadata, _config ->
          send(parent, {:queue_sql, metadata[:query] || ""})
        end,
        nil
      )

    try do
      result = fun.()
      {drain_sql([]), result}
    after
      :ok = :telemetry.detach(id)
    end
  end

  defp drain_sql(acc) do
    receive do
      {:queue_sql, sql} -> drain_sql([sql | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp walk_queue(opts \\ [], acc \\ []) do
    assert {:ok, page} = Cases.list_cases(opts)
    acc = acc ++ page.rows

    if page.has_more? do
      walk_queue([before_id: page.next_before_id], acc)
    else
      acc
    end
  end

  ## Request and scope validation (zero queries before any database work)

  test "empty queue returns a safe empty page and empty options" do
    assert {:ok, %{rows: [], has_more?: false, next_before_id: nil}} = Cases.list_cases()

    assert {:ok, %{rows: [], has_more?: false, next_before_id: nil}} =
             Cases.list_cases(owner: "alpha", environment: @env)

    assert Cases.case_filter_options() == %{owners: [], environments: []}
  end

  test "malformed request shapes are rejected before any query" do
    for bad <- [
          nil,
          "opts",
          123,
          %{},
          %{owner: "alpha"},
          %{"owner" => "alpha"},
          %ReviewCase{},
          [1, 2],
          ["owner"],
          [{"owner", "alpha"}],
          [[:owner, "alpha"]],
          [:not_a_keyword],
          [{:owner, "alpha"} | :tail],
          [owner: "alpha", owner: "beta"],
          [owner: "alpha", q: "x"],
          [before_id: 0],
          [before_id: -1],
          [before_id: true],
          [before_id: false],
          [before_id: 1.5],
          [before_id: "7"],
          [before_id: [1]],
          [before_id: Integer.pow(2, 63)],
          [before_id: String.duplicate("9", 20)],
          [owner: "alpha", before_id: 0]
        ] do
      assert {:error, :invalid_request} = Cases.list_cases(bad), inspect(bad)
    end

    # The rejections are query-free.
    n =
      count_queries(fn ->
        for bad <- [
              nil,
              %{},
              %ReviewCase{},
              [{"owner", "alpha"}],
              [owner: "alpha", q: "x"],
              [before_id: 0],
              [before_id: true],
              [owner: "alpha", before_id: Integer.pow(2, 63)]
            ] do
          assert {:error, :invalid_request} = Cases.list_cases(bad)
        end
      end)

    assert n == 0
    assert counts().cases == 0
  end

  test "malformed scope values are rejected before any query" do
    for bad <- [
          :alpha,
          5,
          true,
          ["alpha"],
          {"alpha", "beta"},
          %Review{},
          %URI{path: "/"},
          String.duplicate("a", 121),
          "alpha\n",
          "alpha\0",
          "alpha\x01",
          <<0xFF>>,
          "  \x7F  "
        ] do
      assert {:error, :invalid_scope} = Cases.list_cases(owner: bad, environment: @env),
             inspect(bad)

      assert {:error, :invalid_scope} = Cases.list_cases(owner: "alpha", environment: bad)
    end

    n =
      count_queries(fn ->
        assert {:error, :invalid_scope} = Cases.list_cases(owner: "alpha\n", environment: @env)
        assert {:error, :invalid_scope} = Cases.list_cases(owner: "alpha", environment: 5)
        assert {:error, :invalid_scope} = Cases.list_cases(owner: String.duplicate("a", 121))
      end)

    assert n == 0
    assert counts().cases == 0
  end

  test "blank scope means unrestricted; a team literally named 'all' is ordinary" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {alpha, _snap} = open_case!(fid, @scope)

    # A team genuinely named "all" cannot exist through the write path (which
    # rejects the All token); the saved scope is inserted directly here
    # without touching any constraint or trigger.
    all_case =
      Repo.insert!(%ReviewCase{
        finding_id: fid,
        owner: "all",
        environment: @env,
        revision: 1
      })

    # Blank (the UI All choice) restricts nothing.
    for opts <- [
          [],
          [owner: nil, environment: nil],
          [owner: "", environment: "  "],
          [owner: "   "]
        ] do
      assert {:ok, %{rows: rows}} = Cases.list_cases(opts)
      assert Enum.map(rows, & &1.id) == [all_case.id, alpha.id], inspect(opts)
    end

    # "all" is a literal team name: it matches only the case saved for that
    # team, never a magic unscoping token.
    assert {:ok, %{rows: rows}} = Cases.list_cases(owner: "all", environment: @env)
    assert Enum.map(rows, & &1.id) == [all_case.id]

    assert {:ok, %{rows: rows}} = Cases.list_cases(owner: "all")
    assert Enum.map(rows, & &1.id) == [all_case.id]

    # No case-insensitive widening either.
    assert {:ok, %{rows: []}} = Cases.list_cases(owner: "ALL", environment: @env)
  end

  ## Scope filtering

  test "owner and environment filters combine with AND" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {alpha, _} = open_case!(fid, @scope)
    {beta, _} = open_case!(fid, owner: "beta", environment: @env)

    image_id = Repo.get!(Inventory.Finding, fid).image_id
    place!(image_id, "alpha", "staging")
    {staging, _} = open_case!(fid, owner: "alpha", environment: "staging")

    assert {:ok, %{rows: rows}} = Cases.list_cases(owner: "alpha")
    assert MapSet.new(Enum.map(rows, & &1.id)) == MapSet.new([alpha.id, staging.id])

    assert {:ok, %{rows: rows}} = Cases.list_cases(environment: @env)
    assert MapSet.new(Enum.map(rows, & &1.id)) == MapSet.new([alpha.id, beta.id])

    assert {:ok, %{rows: rows}} = Cases.list_cases(owner: "alpha", environment: "staging")
    assert Enum.map(rows, & &1.id) == [staging.id]

    # Trimmed values filter identically to their trimmed forms.
    assert {:ok, %{rows: rows}} = Cases.list_cases(owner: "  alpha  ", environment: " staging ")
    assert Enum.map(rows, & &1.id) == [staging.id]

    # Unknown valid values show an empty result, never a broadened scope.
    assert {:ok, %{rows: []}} = Cases.list_cases(owner: "no-such-team")
    assert {:ok, %{rows: []}} = Cases.list_cases(owner: "alpha", environment: "no-such-env")
    assert {:ok, %{rows: []}} = Cases.list_cases(owner: String.duplicate("a", 120))

    assert {:ok, %{rows: []}} =
             Cases.list_cases(
               owner: "no-such-team",
               environment: "no-such-env",
               before_id: @max_id
             )
  end

  test "retired-scope cases remain listed with an out-of-scope badge" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {alpha, _} = open_case!(fid, @scope)
    {_beta, _} = open_case!(fid, owner: "beta", environment: @env)

    :ok = retire_scope(fid)

    # The retired scope stays filterable and the case stays listed.
    assert {:ok, %{rows: rows}} = Cases.list_cases(owner: "alpha", environment: @env)
    assert [row] = rows
    assert row.id == alpha.id
    assert row.evidence_status == :source_out_of_scope
    assert row.review_status == :awaiting_review

    # Detail and queue agree on the derived evidence status.
    assert {:ok, %{evidence_status: :source_out_of_scope}} = Cases.get_case(alpha.id)

    # beta's scope is unaffected.
    assert {:ok, %{rows: rows}} = Cases.list_cases(owner: "beta", environment: @env)
    assert [%{evidence_status: :current}] = rows
  end

  test "same-CVE multi-scope rows stay per-case without cross-scope leakage" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {alpha, snap_alpha} = open_case!(fid, @scope)
    {beta, snap_beta} = open_case!(fid, owner: "beta", environment: @env)

    assert {:ok, _} =
             Cases.submit_review(
               alpha.id,
               alpha.revision,
               snap_alpha.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    beta_attrs = %{@review_attrs | "applicability" => "not_affected_with_evidence"}

    assert {:ok, _} =
             Cases.submit_review(
               beta.id,
               beta.revision,
               snap_beta.id,
               Ecto.UUID.generate(),
               beta_attrs
             )

    assert {:ok, %{rows: rows}} = Cases.list_cases()
    assert length(rows) == 2

    alpha_row = Enum.find(rows, &(&1.id == alpha.id))
    beta_row = Enum.find(rows, &(&1.id == beta.id))

    # Same frozen finding identity, distinct saved scopes and snapshots.
    assert alpha_row.finding_id == beta_row.finding_id
    assert alpha_row.finding.cve == beta_row.finding.cve
    assert alpha_row.snapshot.id != beta_row.snapshot.id

    # Placement/review batches never leak across cases: both stay :current
    # and both agree with the detail page for the same committed state.
    for {cse, row} <- [{alpha, alpha_row}, {beta, beta_row}] do
      assert row.evidence_status == :current
      assert {:ok, %{evidence_status: status}} = Cases.get_case(cse.id)
      assert status == row.evidence_status
      assert row.latest_review.snapshot_id == cse.current_snapshot_id
    end

    assert alpha_row.latest_review.applicability == "affected"
    assert beta_row.latest_review.applicability == "not_affected_with_evidence"
  end

  ## Pagination

  test "pagination walks strict id DESC pages without duplicates or skips" do
    fid = finding_id("CVE-2025-1001", "busybox")
    cases = open_scope_cases(60, fid)
    expected = cases |> Enum.map(& &1.id) |> Enum.reverse()

    assert {:ok, page} = Cases.list_cases()
    assert length(page.rows) == 25
    assert page.has_more? == true
    assert page.next_before_id == Enum.at(expected, 24)
    assert Enum.map(page.rows, & &1.id) == Enum.take(expected, 25)

    walked = walk_queue()
    assert Enum.map(walked, & &1.id) == expected
    assert length(walked) == 60

    # A scoped filter keeps the same pagination contract.
    assert {:ok, page} = Cases.list_cases(owner: "team-7")
    assert [%{owner: "team-7"}] = page.rows
    assert page.has_more? == false
    assert page.next_before_id == nil
  end

  test "the sentinel row drives has_more? exactly at 25 and 26 cases" do
    fid = finding_id("CVE-2025-1001", "busybox")

    cases_25 = open_scope_cases(25, fid)
    expected_25 = cases_25 |> Enum.map(& &1.id) |> Enum.reverse()

    assert {:ok, page} = Cases.list_cases()
    assert length(page.rows) == 25
    assert page.has_more? == false
    assert page.next_before_id == nil
    assert Enum.map(page.rows, & &1.id) == expected_25

    # One more case crosses the boundary: 25 shown, sentinel consumed.
    place!(Repo.get!(Inventory.Finding, fid).image_id, "team-26", @env)
    {c26, _} = open_case!(fid, owner: "team-26", environment: @env)

    assert {:ok, page} = Cases.list_cases()
    assert length(page.rows) == 25
    assert page.has_more? == true
    assert c26.id == hd(page.rows).id
    assert page.next_before_id == List.last(page.rows).id

    assert {:ok, page} = Cases.list_cases(before_id: page.next_before_id)
    assert Enum.map(page.rows, & &1.id) == [List.last(expected_25)]
    assert page.has_more? == false
    assert page.next_before_id == nil
  end

  test "page boundaries at one case and exhausted cursors" do
    fid = finding_id("CVE-2025-1001", "busybox")
    [one] = open_scope_cases(1, fid)

    assert {:ok, page} = Cases.list_cases()
    assert Enum.map(page.rows, & &1.id) == [one.id]
    assert page.has_more? == false
    assert page.next_before_id == nil

    # Cursor at the exact last row exhausts the queue.
    assert {:ok, page} = Cases.list_cases(before_id: one.id)
    assert page.rows == []
    assert page.has_more? == false

    # A cursor below every id is equally exhausted.
    assert {:ok, page} = Cases.list_cases(before_id: one.id - 1)
    assert page.rows == []
    assert page.has_more? == false
    assert page.next_before_id == nil
  end

  test "cursor bounds: 19-digit bigint accepted, overflow and zero rejected" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, _} = open_case!(fid, @scope)

    assert {:ok, %{rows: [row]}} = Cases.list_cases(before_id: @max_id)
    assert row.id == cse.id

    # Nonexistent in-range cursors are ordinary positions, not errors.
    assert {:ok, %{rows: [row]}} = Cases.list_cases(before_id: cse.id + 1)
    assert row.id == cse.id

    assert {:ok, %{rows: []}} = Cases.list_cases(before_id: 1)
  end

  ## Status truth table (with get_case/1 differential)

  test "truth table: fresh case with no review awaits review on current evidence" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, snap} = open_case!(fid, @scope)

    row = queue_row_for(cse.id)

    assert row.evidence_status == :current
    assert row.review_status == :awaiting_review
    assert row.latest_review == nil
    assert row.snapshot.id == snap.id
    assert row.snapshot.version == 1
    assert row.snapshot.captured_at == snap.captured_at
    assert row.revision == cse.revision
    assert row.current_snapshot_id == snap.id
    assert row.opened_at == cse.inserted_at
    assert row.owner == "alpha"
    assert row.environment == @env

    assert {:ok, %{evidence_status: :current}} = Cases.get_case(cse.id)
  end

  test "truth table: same-snapshot review on current evidence is current_review" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, snap} = open_case!(fid, @scope)

    assert {:ok, %{review: review}} =
             Cases.submit_review(
               cse.id,
               cse.revision,
               snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    row = queue_row_for(cse.id)

    assert row.evidence_status == :current
    assert row.review_status == :current_review
    assert row.latest_review.id == review.id
    assert row.latest_review.snapshot_id == snap.id
    assert row.latest_review.priority == "normal_review"
    assert row.latest_review.next_action == "investigation"

    assert {:ok, %{evidence_status: :current}} = Cases.get_case(cse.id)
  end

  test "truth table: a source change needs revalidation before recapture" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, snap} = open_case!(fid, @scope)

    assert {:ok, _} =
             Cases.submit_review(
               cse.id,
               cse.revision,
               snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    :ok = touch_source(fid)

    row = queue_row_for(cse.id)

    assert row.evidence_status == :changed
    assert row.review_status == :needs_revalidation
    assert row.latest_review.snapshot_id == snap.id

    assert {:ok, %{evidence_status: :changed}} = Cases.get_case(cse.id)
  end

  test "truth table: recapture leaves an older review needing revalidation" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, snap} = open_case!(fid, @scope)

    assert {:ok, _} =
             Cases.submit_review(
               cse.id,
               cse.revision,
               snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    cse = Repo.reload(cse)
    :ok = touch_source(fid)

    assert {:ok, %{case: cse2, snapshot: fresh}} =
             Cases.refresh_evidence(cse.id, cse.revision, snap.id)

    row = queue_row_for(cse.id)

    # Fresh evidence, but the review is still bound to the older snapshot.
    assert row.evidence_status == :current
    assert row.review_status == :needs_revalidation
    assert row.latest_review.snapshot_id == snap.id
    assert row.snapshot.id == fresh.id
    assert row.snapshot.version == 2
    assert row.revision == cse2.revision

    # A fresh review of the recaptured evidence becomes current again.
    assert {:ok, %{review: fresh_review}} =
             Cases.submit_review(
               cse2.id,
               cse2.revision,
               fresh.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    row = queue_row_for(cse.id)

    assert row.evidence_status == :current
    assert row.review_status == :current_review
    assert row.latest_review.id == fresh_review.id
    assert row.latest_review.snapshot_id == fresh.id

    assert {:ok, %{evidence_status: :current}} = Cases.get_case(cse.id)
  end

  test "truth table: retired placement outranks review recency" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, snap} = open_case!(fid, @scope)

    assert {:ok, _} =
             Cases.submit_review(
               cse.id,
               cse.revision,
               snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    :ok = retire_scope(fid)

    row = queue_row_for(cse.id)

    assert row.evidence_status == :source_out_of_scope
    assert row.review_status == :needs_revalidation
    assert row.latest_review.id

    assert {:ok, %{evidence_status: :source_out_of_scope}} = Cases.get_case(cse.id)
  end

  test "truth table: a case without a current snapshot maps to source_missing" do
    fid = finding_id("CVE-2025-1001", "busybox")

    # Not reachable after a committed open (the nil pointer lives only inside
    # the creation transaction); the state is inserted directly without
    # disabling any constraint or trigger.
    cse =
      Repo.insert!(%ReviewCase{
        finding_id: fid,
        owner: "alpha",
        environment: @env,
        revision: 1
      })

    assert {:ok, page} = Cases.list_cases()
    assert [row] = page.rows

    assert row.id == cse.id
    assert row.current_snapshot_id == nil
    assert row.snapshot == nil
    assert row.evidence_status == :source_missing
    assert row.review_status == :awaiting_review
    assert row.latest_review == nil

    # Frozen-display guard regression: with no snapshot there is no captured
    # evidence, so identity display returns explicit unknown/empty fields with
    # the same UI-safe finding/image map shape — the LIVE source is never
    # substituted as if it had been captured. The status never becomes
    # current, and detail and queue agree.
    assert row.finding == %{
             cve: "",
             package_name: "",
             package_version: "",
             severity: "",
             suppressed: nil,
             image: %{digest: "", repository: "", tag: ""}
           }

    assert row.image == %{digest: "", repository: "", tag: ""}

    assert {:ok, %{evidence_status: :source_missing}} = Cases.get_case(cse.id)
  end

  test "suppressed observations stay listed and keep the same status contract" do
    fid = finding_id("CVE-2025-3003", "libc6")
    {cse, _} = open_case!(fid, owner: "beta", environment: @env)

    row = queue_row_for(cse.id)

    assert row.finding.suppressed == true
    assert row.evidence_status == :current
    assert row.review_status == :awaiting_review

    assert {:ok, %{evidence_status: :current}} = Cases.get_case(cse.id)
  end

  ## Row projection and frozen display

  test "rows are plain projection maps without histories, tokens or hashes" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, snap} = open_case!(fid, @scope)

    token = Ecto.UUID.generate()

    assert {:ok, %{review: review}} =
             Cases.submit_review(cse.id, cse.revision, snap.id, token, @review_attrs)

    assert {:ok, %{rows: [row]}} = Cases.list_cases()

    assert Map.keys(row) |> Enum.sort() == [
             :current_snapshot_id,
             :environment,
             :evidence_status,
             :finding,
             :finding_id,
             :id,
             :image,
             :latest_review,
             :opened_at,
             :owner,
             :review_status,
             :revision,
             :snapshot
           ]

    assert Map.keys(row.image) |> Enum.sort() == [:digest, :repository, :tag]

    assert Map.keys(row.finding) |> Enum.sort() == [
             :cve,
             :image,
             :package_name,
             :package_version,
             :severity,
             :suppressed
           ]

    assert Map.keys(row.finding.image) |> Enum.sort() == [:digest, :repository, :tag]
    assert Map.keys(row.snapshot) |> Enum.sort() == [:captured_at, :id, :version]

    assert Map.keys(row.latest_review) |> Enum.sort() == [
             :applicability,
             :id,
             :inserted_at,
             :next_action,
             :priority,
             :snapshot_id
           ]

    # Server-only material never reaches the queue: tokens, request hashes,
    # payload hashes, full histories and rationale stay on the detail page.
    leaked = inspect(row)
    refute String.contains?(leaked, token)
    refute String.contains?(leaked, review.request_hash)
    refute String.contains?(leaked, snap.payload_hash)
    refute String.contains?(leaked, @review_attrs["rationale"])
  end

  test "frozen display text comes from the snapshot payload, not the live source" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, _} = open_case!(fid, @scope)

    Repo.get!(Inventory.Finding, fid)
    |> Inventory.Finding.changeset(%{suppressed: true})
    |> Repo.update!()

    row = queue_row_for(cse.id)

    # Frozen captured identity: the badge changed, the display text did not.
    assert row.evidence_status == :changed
    assert row.finding.suppressed == false
    assert row.finding.cve == "CVE-2025-1001"
    assert row.finding.package_name == "busybox"
    assert row.finding.package_version == "1.37"
    assert row.finding.image.repository == "registry.internal/app-a"
    assert row.finding.image.tag == "1.0"
  end

  test "top-level image and nested finding.image are the same captured identity" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, snap} = open_case!(fid, @scope)

    captured = %{
      digest: "sha256:aaa1111111111111111111111111111111111111111111111111111111111111",
      repository: "registry.internal/app-a",
      tag: "1.0"
    }

    # Both maps exist, share the same keys and represent the CAPTURED image.
    row = queue_row_for(cse.id)
    assert row.image == captured
    assert row.finding.image == captured
    assert row.finding.image == row.image

    # The live source image identity changes: the badge changes, but both
    # frozen display maps keep showing the captured image.
    image = Repo.get!(Inventory.Image, Repo.get!(Inventory.Finding, fid).image_id)

    image
    |> Inventory.Image.changeset(%{repository: "registry.internal/renamed", tag: "9.9"})
    |> Repo.update!()

    row = queue_row_for(cse.id)
    assert row.evidence_status == :changed
    assert row.image == captured
    assert row.finding.image == captured

    # Only an explicit recapture freezes the new image identity into both maps.
    cse = Repo.reload(cse)

    assert {:ok, %{snapshot: fresh}} = Cases.refresh_evidence(cse.id, cse.revision, snap.id)

    row = queue_row_for(cse.id)
    assert fresh.version == 2
    assert row.evidence_status == :current

    assert row.image == %{captured | repository: "registry.internal/renamed", tag: "9.9"}
    assert row.finding.image == row.image
  end

  test "the latest review is deterministic by inserted_at then id" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, snap} = open_case!(fid, @scope)

    assert {:ok, %{review: first}} =
             Cases.submit_review(
               cse.id,
               cse.revision,
               snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    cse = Repo.reload(cse)

    later_attrs = %{@review_attrs | "priority" => "expedited_review"}

    assert {:ok, %{review: second}} =
             Cases.submit_review(cse.id, cse.revision, snap.id, Ecto.UUID.generate(), later_attrs)

    row = queue_row_for(cse.id)

    # inserted_at ties (second precision) fall back to id DESC; when they
    # differ the later submission still wins. Either way: deterministic.
    assert row.latest_review.id == second.id
    assert row.latest_review.id != first.id
    assert row.latest_review.priority == "expedited_review"
    assert row.latest_review.inserted_at == second.inserted_at
  end

  ## Purity and query budget

  test "queue reads are pure: counts and content fingerprints stay identical" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, snap} = open_case!(fid, @scope)

    assert {:ok, _} =
             Cases.submit_review(
               cse.id,
               cse.revision,
               snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    :ok = touch_source(fid)
    cse = Repo.reload(cse)
    assert {:ok, _} = Cases.refresh_evidence(cse.id, cse.revision, snap.id)
    :ok = retire_scope(fid)

    before_counts = counts()
    before_fingerprints = fingerprints()

    assert {:ok, _} = Cases.list_cases()
    assert {:ok, _} = Cases.list_cases(owner: "alpha", environment: @env, before_id: @max_id)
    assert {:ok, _} = Cases.list_cases(owner: "no-such-team")
    assert {:ok, _} = Cases.list_cases(owner: "alpha")
    assert %{owners: _owners, environments: _environments} = Cases.case_filter_options()

    assert counts() == before_counts
    assert fingerprints() == before_fingerprints
  end

  test "one SELECT hydrates the case, snapshot and latest review binding together" do
    fid = finding_id("CVE-2025-1001", "busybox")
    {cse, snap} = open_case!(fid, @scope)

    assert {:ok, %{review: review}} =
             Cases.submit_review(
               cse.id,
               cse.revision,
               snap.id,
               Ecto.UUID.generate(),
               @review_attrs
             )

    cse = Repo.reload(cse)

    {selects, {:ok, page}} = capture_queries(fn -> Cases.list_cases() end)

    # The returned binding is correct and reads like the detail page.
    assert [row] = page.rows
    assert row.revision == cse.revision
    assert row.current_snapshot_id == snap.id
    assert row.snapshot.id == snap.id
    assert row.latest_review.id == review.id
    assert row.latest_review.snapshot_id == snap.id

    # The case pointer/revision, current snapshot and latest review are read
    # TOGETHER: exactly one SELECT touches review_cases,
    # review_evidence_snapshots and review_reviews, so the binding can never
    # mix rows across reads or cases, within the fixed SELECT budget.
    assert [binding] =
             Enum.filter(selects, fn sql ->
               String.contains?(sql, "review_cases") and
                 String.contains?(sql, "review_evidence_snapshots") and
                 String.contains?(sql, "review_reviews")
             end)

    assert String.starts_with?(binding, "SELECT")
    assert length(selects) <= 8
  end

  test "query budget: fixed SELECT families, never per-row loading" do
    fid = finding_id("CVE-2025-1001", "busybox")
    open_scope_cases(60, fid)

    full_page = count_queries(fn -> Cases.list_cases() end)
    assert full_page > 1
    assert full_page <= 8

    assert {:ok, page} = Cases.list_cases()
    assert length(page.rows) == 25

    min_id = Repo.aggregate(ReviewCase, :min, :id)
    one_page_cursor = min_id + 1
    assert {:ok, one_page} = Cases.list_cases(before_id: one_page_cursor)
    assert length(one_page.rows) == 1

    one_page_queries = count_queries(fn -> Cases.list_cases(before_id: one_page_cursor) end)
    assert one_page_queries <= 8

    # The same 25-row page over 60 stored cases costs the same fixed queries:
    # no per-row scaling by stored case count.
    again = count_queries(fn -> Cases.list_cases() end)
    assert again == full_page

    options_queries = count_queries(fn -> Cases.case_filter_options() end)
    assert options_queries <= 2

    empty_queries = count_queries(fn -> Cases.list_cases(owner: "no-such-team") end)
    assert empty_queries <= 2
  end

  test "filter options list sorted distinct saved scopes only" do
    fid = finding_id("CVE-2025-1001", "busybox")
    open_case!(fid, @scope)
    open_case!(fid, owner: "beta", environment: @env)

    image_id = Repo.get!(Inventory.Finding, fid).image_id
    place!(image_id, "alpha", "staging")
    open_case!(fid, owner: "alpha", environment: "staging")

    # An inventory-only team with no saved case is not a filter option.
    place!(image_id, "gamma", @env)

    options = Cases.case_filter_options()
    assert options.owners == ["alpha", "beta"]
    assert options.environments == ["prod", "staging"]
  end
end
