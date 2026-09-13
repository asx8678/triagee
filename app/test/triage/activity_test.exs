defmodule Triage.ActivityTest do
  @moduledoc """
  Domain tests for the read-only `Triage.Activity` What's New feed: request
  validation with zero queries, id-ordered pagination independent of
  observation time, current-metadata vs recorded-event separation,
  same-placement AND scoping, lifecycle-kind inclusion and the SELECT budget.
  """

  # async: false so the telemetry SELECT counter cannot observe queries from
  # concurrently running async modules.
  use Triage.DataCase, async: false

  alias Triage.{Activity, Repo}
  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}

  @now ~U[2026-09-09 06:00:00Z]

  setup do
    # Inventory-wide feed: start from a known-empty baseline.
    # See Triage.DataCase.reset_inventory!/0 for the full rationale.
    Triage.DataCase.reset_inventory!()
    :ok
  end

  ## Fixture helpers

  defp image!(seed) do
    Repo.insert!(%Image{
      digest: "sha256:" <> String.duplicate(seed, 64),
      repository: "registry.internal/" <> seed,
      tag: "1.0"
    })
  end

  defp finding!(image, opts \\ []) do
    Repo.insert!(%Finding{
      image_id: image.id,
      cve: Keyword.get(opts, :cve, "CVE-2025-1001"),
      package_name: Keyword.get(opts, :package_name, "busybox"),
      package_version: Keyword.get(opts, :package_version, "1.0"),
      severity: Keyword.get(opts, :severity, "HIGH"),
      suppressed: Keyword.get(opts, :suppressed, false),
      resolved_at: Keyword.get(opts, :resolved_at),
      first_seen: @now,
      last_seen: @now
    })
  end

  defp event!(finding, name, opts \\ []) do
    Repo.insert!(%FindingEvent{
      finding_id: finding.id,
      event: name,
      occurred_at: Keyword.get(opts, :occurred_at, @now),
      note: Keyword.get(opts, :note)
    })
  end

  defp placement!(image, opts) do
    Repo.insert!(%ImagePlacement{
      image_id: image.id,
      namespace: Keyword.get(opts, :namespace, "web"),
      owner: Keyword.fetch!(opts, :owner),
      environment: Keyword.fetch!(opts, :environment),
      active: Keyword.get(opts, :active, true),
      first_seen: @now,
      last_seen: @now
    })
  end

  defp seed_events(count, seed) do
    image = image!(seed)
    finding = finding!(image)

    if count > 0 do
      Enum.each(1..count, fn i ->
        event!(finding, "appeared", occurred_at: DateTime.add(@now, i, :second))
      end)
    end

    finding
  end

  defp walk_ids(opts \\ [], acc \\ []) do
    assert {:ok, page} = Activity.list_events(opts)
    ids = acc ++ Enum.map(page.rows, & &1.id)

    if page.has_more? do
      walk_ids([before_id: page.next_before_id], ids)
    else
      ids
    end
  end

  # Counts [:triage, :repo, :query] telemetry events during one isolated call,
  # with fixture setup excluded: a direct SELECT budget check, never a latency
  # claim.
  defp count_selects(fun) do
    counter = :counters.new(1, [])
    id = "activity-" <> Integer.to_string(:erlang.unique_integer([:positive, :monotonic]))

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

  describe "event kinds and ordering" do
    test "returns all three event kinds with raw values and recorded times" do
      image = image!("a")
      finding = finding!(image)
      event!(finding, "appeared", occurred_at: ~U[2026-08-01 06:00:00Z])
      event!(finding, "resolved", occurred_at: ~U[2026-08-05 06:00:00Z])
      event!(finding, "reopened", occurred_at: ~U[2026-08-06 06:00:00Z])

      assert {:ok, %{rows: rows, has_more?: false, next_before_id: nil}} = Activity.list_events()
      assert Enum.map(rows, & &1.event) |> Enum.sort() == ["appeared", "reopened", "resolved"]
      assert Enum.all?(rows, &match?(%DateTime{}, &1.occurred_at))
    end

    test "orders strictly by record id DESC despite backdated and tied observation times" do
      image = image!("b")
      finding = finding!(image)
      first = event!(finding, "appeared", occurred_at: ~U[2026-09-09 06:00:00Z])
      backdated = event!(finding, "resolved", occurred_at: ~U[2026-09-01 00:00:00Z])
      tied = event!(finding, "reopened", occurred_at: ~U[2026-09-09 06:00:00Z])

      assert {:ok, %{rows: rows}} = Activity.list_events()
      assert Enum.map(rows, & &1.id) == [tied.id, backdated.id, first.id]

      assert Enum.map(rows, & &1.occurred_at) == [
               tied.occurred_at,
               backdated.occurred_at,
               first.occurred_at
             ]
    end
  end

  describe "pagination" do
    test "empty feed returns an empty page" do
      assert {:ok, %{rows: [], has_more?: false, next_before_id: nil}} = Activity.list_events()
    end

    test "single row has no further page" do
      seed_events(1, "c")
      assert {:ok, %{rows: [row], has_more?: false, next_before_id: nil}} = Activity.list_events()
      assert row.event == "appeared"
    end

    test "exactly 25 rows fill one page with no cursor" do
      seed_events(25, "d")
      assert {:ok, %{rows: rows, has_more?: false, next_before_id: nil}} = Activity.list_events()
      assert length(rows) == 25
    end

    test "26 rows return 25 with a cursor and one remaining row" do
      seed_events(26, "e")
      assert {:ok, %{rows: rows, has_more?: true, next_before_id: next}} = Activity.list_events()
      assert length(rows) == 25
      assert next == List.last(rows).id

      assert {:ok, %{rows: page2, has_more?: false, next_before_id: nil}} =
               Activity.list_events(before_id: next)

      assert length(page2) == 1
    end

    test "more than 50 rows walk without duplicates or skips" do
      seed_events(53, "f")
      ids = walk_ids()
      assert length(ids) == 53
      assert ids == Enum.sort(ids, :desc)
      assert Enum.uniq(ids) == ids
    end

    test "an insertion between pages never duplicates or shifts the older page" do
      finding = seed_events(30, "g")
      assert {:ok, page1} = Activity.list_events()
      assert length(page1.rows) == 25
      assert page1.has_more?

      page1_ids = Enum.map(page1.rows, & &1.id)

      # A newer event arrives after page one was read.
      event!(finding, "resolved", occurred_at: @now)

      assert {:ok, page2} = Activity.list_events(before_id: page1.next_before_id)
      page2_ids = Enum.map(page2.rows, & &1.id)

      assert length(page2_ids) == 5
      assert MapSet.disjoint?(MapSet.new(page1_ids), MapSet.new(page2_ids))
      refute page2.has_more?

      # The new event is only reachable from a fresh newest page.
      assert {:ok, fresh} = Activity.list_events()
      refute hd(fresh.rows).id in page1_ids
    end
  end

  describe "scoping" do
    test "owner-only scope matches only that owner's placements" do
      alpha_image = image!("h")
      beta_image = image!("i")
      placement!(alpha_image, owner: "alpha", environment: "prod")
      placement!(beta_image, owner: "beta", environment: "prod")
      alpha_event = event!(finding!(alpha_image), "appeared")
      event!(finding!(beta_image), "appeared")

      assert {:ok, %{rows: rows}} = Activity.list_events(owner: " alpha ")
      assert Enum.map(rows, & &1.id) == [alpha_event.id]

      assert [%{owner: "alpha", environment: "prod", namespace: "web", active: true}] =
               hd(rows).placements

      assert hd(rows).detail_available?
    end

    test "environment-only scope matches only that environment's placements" do
      prod = image!("j")
      staging = image!("k")
      placement!(prod, owner: "alpha", environment: "prod")
      placement!(staging, owner: "alpha", environment: "staging")
      prod_event = event!(finding!(prod), "appeared")
      event!(finding!(staging), "appeared")

      assert {:ok, %{rows: rows}} = Activity.list_events(environment: "prod")
      assert Enum.map(rows, & &1.id) == [prod_event.id]
    end

    test "owner and environment combine with AND on the same placement" do
      image = image!("l")
      placement!(image, owner: "alpha", environment: "prod")
      placement!(image, owner: "alpha", environment: "staging")
      event = event!(finding!(image), "appeared")

      assert {:ok, %{rows: [row]}} = Activity.list_events(owner: "alpha", environment: "prod")
      assert row.id == event.id

      assert {:ok, %{rows: []}} = Activity.list_events(owner: "alpha", environment: "no-such-env")
    end

    test "owner from one placement and environment from another must not match" do
      image = image!("m")
      placement!(image, owner: "alpha", environment: "prod")
      placement!(image, owner: "beta", environment: "staging")
      event!(finding!(image), "appeared")

      # No single placement carries both values.
      assert {:ok, %{rows: []}} = Activity.list_events(owner: "alpha", environment: "staging")
      assert {:ok, %{rows: []}} = Activity.list_events(owner: "beta", environment: "prod")

      # Each individual value still matches its own placement.
      assert {:ok, %{rows: [_]}} = Activity.list_events(owner: "alpha", environment: "prod")
      assert {:ok, %{rows: [_]}} = Activity.list_events(owner: "beta", environment: "staging")
    end

    test "unknown but valid scope is an honest empty feed" do
      image = image!("n")
      placement!(image, owner: "alpha", environment: "prod")
      event!(finding!(image), "appeared")

      assert {:ok, %{rows: [], has_more?: false, next_before_id: nil}} =
               Activity.list_events(owner: "no-such-team")

      assert {:ok, %{rows: [], has_more?: false, next_before_id: nil}} =
               Activity.list_events(environment: "no-such-env")
    end

    test "an inactive recorded placement keeps the event visible in scope" do
      image = image!("o")
      placement!(image, owner: "alpha", environment: "prod", active: false)
      event = event!(finding!(image), "appeared")

      assert {:ok, %{rows: [row]}} = Activity.list_events(owner: "alpha", environment: "prod")
      assert row.id == event.id

      assert [%{owner: "alpha", environment: "prod", namespace: "web", active: false}] =
               row.placements

      refute row.detail_available?
    end

    test "unscoped includes events with no placements; scoped excludes them" do
      image = image!("p")
      event = event!(finding!(image), "appeared")

      assert {:ok, %{rows: [row]}} = Activity.list_events()
      assert row.id == event.id
      assert row.placements == []
      assert row.detail_available?

      assert {:ok, %{rows: []}} = Activity.list_events(owner: "alpha")
      assert {:ok, %{rows: []}} = Activity.list_events(environment: "prod")
    end

    test "one row per event even when the image has many matching placements" do
      image = image!("q")
      placement!(image, owner: "alpha", environment: "prod")
      placement!(image, owner: "beta", environment: "prod")
      placement!(image, owner: "alpha", environment: "staging")
      finding = finding!(image)
      first = event!(finding, "appeared")
      second = event!(finding, "resolved")

      assert {:ok, %{rows: rows}} = Activity.list_events()
      assert length(rows) == 2
      assert MapSet.new(Enum.map(rows, & &1.id)) == MapSet.new([first.id, second.id])

      row = Enum.find(rows, &(&1.id == first.id))
      assert length(row.placements) == 3
    end

    test "scoped placements keep only matching placements, active and inactive" do
      image = image!("r")
      placement!(image, owner: "alpha", environment: "prod", namespace: "web", active: true)
      placement!(image, owner: "alpha", environment: "prod", namespace: "api", active: false)
      placement!(image, owner: "beta", environment: "prod", namespace: "web")
      event = event!(finding!(image), "appeared")

      assert {:ok, %{rows: [row]}} = Activity.list_events(owner: "alpha", environment: "prod")
      assert row.id == event.id
      assert length(row.placements) == 2
      assert Enum.all?(row.placements, &(&1.owner == "alpha" and &1.environment == "prod"))
      assert Enum.any?(row.placements, & &1.active)
      assert row.detail_available?
    end

    test "placements have a deterministic order" do
      image = image!("s")
      placement!(image, owner: "beta", environment: "prod")
      placement!(image, owner: "alpha", environment: "staging")
      placement!(image, owner: "alpha", environment: "prod")
      event!(finding!(image), "appeared")

      assert {:ok, %{rows: [row]}} = Activity.list_events()

      assert Enum.map(row.placements, &{&1.owner, &1.environment}) == [
               {"alpha", "prod"},
               {"alpha", "staging"},
               {"beta", "prod"}
             ]
    end
  end

  describe "lifecycle inclusion and current metadata" do
    test "resolved and suppressed findings' events are included" do
      image = image!("t")
      placement!(image, owner: "alpha", environment: "prod")
      suppressed = finding!(image, cve: "CVE-2025-7001", package_name: "supp", suppressed: true)

      resolved =
        finding!(image,
          cve: "CVE-2025-7002",
          package_name: "res",
          resolved_at: ~U[2026-08-05 06:00:00Z]
        )

      suppressed_event = event!(suppressed, "appeared")
      resolved_event = event!(resolved, "resolved")

      assert {:ok, %{rows: rows}} = Activity.list_events()

      assert MapSet.new(Enum.map(rows, & &1.id)) ==
               MapSet.new([suppressed_event.id, resolved_event.id])

      assert Enum.find(rows, &(&1.id == suppressed_event.id)).finding.suppressed

      assert Enum.find(rows, &(&1.id == resolved_event.id)).finding.resolved_at ==
               ~U[2026-08-05 06:00:00Z]
    end

    test "detail_available? truth table: unscoped always, scoped requires an active match" do
      # unscoped, no placement
      bare = image!("u")
      bare_event = event!(finding!(bare), "appeared")

      # unscoped, inactive-only placement; scoped, inactive-only placement
      inactive = image!("v")
      placement!(inactive, owner: "alpha", environment: "prod", active: false)
      inactive_event = event!(finding!(inactive), "appeared")

      # scoped, at least one matching active placement
      active = image!("w")
      placement!(active, owner: "alpha", environment: "prod", namespace: "web", active: true)
      placement!(active, owner: "alpha", environment: "prod", namespace: "api", active: false)
      active_event = event!(finding!(active), "appeared")

      assert {:ok, %{rows: rows}} = Activity.list_events()
      assert Enum.find(rows, &(&1.id == bare_event.id)).detail_available?
      assert Enum.find(rows, &(&1.id == inactive_event.id)).detail_available?
      assert Enum.any?(Enum.find(rows, &(&1.id == inactive_event.id)).placements, &(!&1.active))

      assert {:ok, %{rows: scoped_rows}} =
               Activity.list_events(owner: "alpha", environment: "prod")

      refute Enum.find(scoped_rows, &(&1.id == inactive_event.id)).detail_available?
      assert Enum.find(scoped_rows, &(&1.id == active_event.id)).detail_available?
      refute Enum.any?(scoped_rows, &(&1.id == bare_event.id))
    end

    test "current finding and image metadata are joined, not frozen into the event" do
      image = image!("x")
      finding = finding!(image, cve: "CVE-2025-8001", package_name: "old", severity: "LOW")

      event =
        event!(finding, "appeared",
          occurred_at: ~U[2026-01-01 00:00:00Z],
          note: "historical note"
        )

      assert {:ok, %{rows: [row]}} = Activity.list_events()
      assert row.event == "appeared"
      assert row.occurred_at == ~U[2026-01-01 00:00:00Z]

      assert row.finding == %{
               cve: "CVE-2025-8001",
               package_name: "old",
               package_version: "1.0",
               severity: "LOW",
               suppressed: false,
               resolved_at: nil
             }

      new_digest = "sha256:" <> String.duplicate("z", 64)

      finding
      |> Ecto.Changeset.change(%{
        cve: "CVE-2025-8002",
        package_name: "new",
        package_version: "2.0",
        severity: "CRITICAL",
        suppressed: true,
        resolved_at: @now
      })
      |> Repo.update!()

      image
      |> Ecto.Changeset.change(%{
        digest: new_digest,
        repository: "registry.internal/renamed",
        tag: "9.9"
      })
      |> Repo.update!()

      assert {:ok, %{rows: [row]}} = Activity.list_events()
      assert row.id == event.id
      assert row.event == "appeared"
      assert row.occurred_at == ~U[2026-01-01 00:00:00Z]
      assert row.note == "historical note"

      assert row.finding == %{
               cve: "CVE-2025-8002",
               package_name: "new",
               package_version: "2.0",
               severity: "CRITICAL",
               suppressed: true,
               resolved_at: @now
             }

      assert row.image == %{
               digest: new_digest,
               repository: "registry.internal/renamed",
               tag: "9.9"
             }
    end
  end

  describe "request validation performs no queries" do
    test "rejects malformed request shapes before any query" do
      bad_requests = [
        nil,
        "opts",
        123,
        %{},
        %{owner: "alpha"},
        %Image{},
        [1, 2],
        ["owner"],
        [{"owner", "alpha"}],
        [:not_a_keyword],
        [owner: "alpha", owner: "beta"],
        [owner: "alpha", q: "x"]
      ]

      n =
        count_selects(fn ->
          Enum.each(bad_requests, fn bad ->
            assert Activity.list_events(bad) == {:error, :invalid_request}, inspect(bad)
          end)
        end)

      assert n == 0
    end

    test "rejects malformed scopes before any query" do
      bad_scopes = [
        123,
        :alpha,
        true,
        ["alpha"],
        {"alpha", "beta"},
        %URI{path: "/"},
        String.duplicate("a", 121),
        "alpha\n",
        "alpha\0",
        "alpha\x01",
        "alpha\x7F",
        <<0xFF>>
      ]

      n =
        count_selects(fn ->
          Enum.each(bad_scopes, fn bad ->
            assert Activity.list_events(owner: bad) == {:error, :invalid_scope}, inspect(bad)

            assert Activity.list_events(environment: bad) == {:error, :invalid_scope},
                   inspect(bad)
          end)
        end)

      assert n == 0
    end

    test "rejects malformed cursors before any query" do
      bad_cursors = [0, -1, true, false, 1.5, "7", [1], Integer.pow(2, 63)]

      n =
        count_selects(fn ->
          Enum.each(bad_cursors, fn bad ->
            assert Activity.list_events(before_id: bad) == {:error, :invalid_cursor}, inspect(bad)
          end)
        end)

      assert n == 0
    end

    test "accepts the largest valid cursor" do
      seed_events(2, "9")
      max_id = Integer.pow(2, 63) - 1
      assert {:ok, %{rows: rows, has_more?: false}} = Activity.list_events(before_id: max_id)
      assert length(rows) == 2
    end
  end

  describe "filter options and query budget" do
    test "options are sorted distinct nonblank values from all placements including inactive" do
      image = image!("y")
      placement!(image, owner: "beta", environment: "prod")
      placement!(image, owner: "alpha", environment: "staging", active: false)
      placement!(image, owner: "alpha", environment: "  ")

      other = image!("1")
      placement!(other, owner: "  ", environment: "staging")

      assert Activity.event_filter_options() == %{
               owners: ["alpha", "beta"],
               environments: ["prod", "staging"]
             }
    end

    test "list_events uses at most three SELECTs at one and 25 rows; options at most two" do
      seed_events(1, "2")
      assert count_selects(fn -> assert {:ok, _} = Activity.list_events() end) <= 3

      seed_events(25, "3")

      assert count_selects(fn ->
               assert {:ok, %{rows: rows, has_more?: true}} = Activity.list_events()
               assert length(rows) == 25
             end) <= 3

      assert count_selects(fn -> Activity.event_filter_options() end) <= 2
    end
  end
end
