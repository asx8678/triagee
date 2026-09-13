defmodule Triage.InventoryPagingTest do
  @moduledoc """
  Regressions for bounded, sortable advisory groups: the unpaged total a page is
  computed from, the strict total order of every published sort, and the keyset
  partition property — walking the list with only the positions it hands out
  neither duplicates nor drops a group, at any depth.
  """

  use Triage.DataCase, async: true

  alias Triage.Inventory
  alias Triage.Inventory.GroupCursor
  alias Triage.Seeds

  @now ~U[2026-09-10 12:00:00Z]
  @severities ~w(CRITICAL HIGH MEDIUM LOW)

  setup do
    :ok = Seeds.seed()
    :ok = add_advisories!(12)
    :ok
  end

  test "count_groups/1 matches the unpaged rows for the same predicates" do
    for opts <- [
          [],
          [owner: "alpha"],
          [owner: "beta"],
          [environment: "prod-cluster-1"],
          [severity: "CRITICAL"],
          [severity: "LOW"],
          [search: "busybox"],
          [search: "no-such-package"],
          [include_suppressed: true],
          [owner: "no-such-team"],
          [owner: "alpha", include_suppressed: true, severity: "LOW"]
        ] do
      assert Inventory.count_groups(opts) == length(Inventory.list_groups(opts)),
             "count_groups/1 disagreed with list_groups/1 for #{inspect(opts)}"
    end
  end

  test "every published sort is a strict total order that repeats identically" do
    for sort <- Inventory.group_sorts() do
      keys = Enum.map(Inventory.list_groups(sort: sort), & &1.cve)

      assert keys == Enum.uniq(keys), "sort #{sort} repeated a group"

      assert Enum.map(Inventory.list_groups(sort: sort), & &1.cve) == keys
    end
  end

  test "each sort orders by the field it names" do
    newest = Enum.map(Inventory.list_groups(sort: "newest"), & &1.first_seen)
    assert newest == Enum.sort(newest, {:desc, DateTime})

    occurrences = Enum.map(Inventory.list_groups(sort: "occurrences"), & &1.occurrences)
    assert occurrences == Enum.sort(occurrences, :desc)

    ids = Enum.map(Inventory.list_groups(sort: "cve"), & &1.cve)
    assert ids == Enum.sort(ids)

    ranks = Enum.map(Inventory.list_groups(sort: "severity"), & &1.severity_rank)
    assert ranks == Enum.sort(ranks, :desc)
  end

  test "the default order is the published default" do
    assert Inventory.default_group_sort() in Inventory.group_sorts()

    assert Enum.map(Inventory.list_groups(), & &1.cve) ==
             Enum.map(Inventory.list_groups(sort: Inventory.default_group_sort()), & &1.cve)
  end

  test "walking the list with only its own positions partitions it, for every order" do
    for sort <- Inventory.group_sorts() do
      all = Enum.map(Inventory.list_groups(sort: sort), & &1.cve)
      assert length(all) > 5

      walked = walk_positions([sort: sort], 5)

      assert walked == all, "sort #{sort} lost or repeated a group while paging"
      assert walked == Enum.uniq(walked)
    end
  end

  test "every order's positions are its own" do
    # A position names the order it belongs to, so using it with another order
    # is a programming error rather than a silently different slice.
    severity_position = %{severity_rank: 4, images: 1, cve: "CVE-2098-70011"}

    for sort <- ["cve", "occurrences", "newest"] do
      assert_raise ArgumentError, fn ->
        Inventory.list_groups(sort: sort, before: severity_position)
      end
    end

    rows = Inventory.list_groups(sort: "severity", before: severity_position)
    assert rows != []

    assert Enum.all?(rows, fn row ->
             {-row.severity_rank, -row.images, row.cve} > {-4, -1, "CVE-2098-70011"}
           end)
  end

  test "paging keeps every filter, not only the ordering" do
    scoped = Inventory.list_groups(owner: "alpha", sort: "cve")
    assert scoped != []

    assert Inventory.list_groups(owner: "alpha", sort: "cve", limit: 3)
           |> Enum.map(& &1.cve) == scoped |> Enum.map(& &1.cve) |> Enum.take(3)

    assert Inventory.count_groups(owner: "alpha") == length(scoped)

    assert walk_positions([owner: "alpha", sort: "cve"], 3) == Enum.map(scoped, & &1.cve)

    # A position continues inside the scoped list too: the filters, not the
    # position, decide which groups exist.
    {:ok, cursor} =
      Inventory.list_groups(owner: "alpha", sort: "cve", limit: 1)
      |> List.last()
      |> then(&GroupCursor.parse("cve", GroupCursor.encode("cve", &1)))

    assert Inventory.list_groups(owner: "alpha", sort: "cve", before: cursor)
           |> Enum.map(& &1.cve) == scoped |> Enum.map(& &1.cve) |> Enum.drop(1)
  end

  test "a position past the last group is an empty page, not a wrapped one" do
    {:ok, cursor} =
      Inventory.list_groups(sort: "cve")
      |> List.last()
      |> then(&GroupCursor.parse("cve", GroupCursor.encode("cve", &1)))

    assert Inventory.list_groups(sort: "cve", limit: 5, before: cursor) == []
  end

  test "the page size is bounded and a position must be one this order could produce" do
    assert Inventory.list_groups(limit: 0) == []
    assert length(Inventory.list_groups(limit: 2)) == 2

    assert_raise ArgumentError, fn -> Inventory.list_groups(limit: -1) end
    assert_raise ArgumentError, fn -> Inventory.list_groups(limit: 201) end
    assert_raise ArgumentError, fn -> Inventory.list_groups(limit: "2") end
    assert_raise ArgumentError, fn -> Inventory.list_groups(sort: "nonsense") end
    assert_raise ArgumentError, fn -> Inventory.list_groups(sort: :newest) end

    # Not the parsed shape of any position, so it is rejected rather than
    # coerced into one.
    for bad <- [
          "4~1~CVE-x",
          5,
          :cve,
          %{cve: "CVE-x"},
          %{severity_rank: 4, images: 1},
          %{severity_rank: 4, images: 1, cve: "CVE-x", extra: 1},
          %{severity_rank: 5, images: 1, cve: "CVE-x"}
        ] do
      assert_raise ArgumentError, fn -> Inventory.list_groups(sort: "severity", before: bad) end
    end
  end

  test "the newest rail shares the list's newest order" do
    assert Enum.map(Inventory.newest_cve_groups(3), & &1.cve) ==
             Inventory.list_groups(sort: "newest", limit: 3) |> Enum.map(& &1.cve)
  end

  # Walks one order with only the positions it hands out, page by page. The
  # page bound keeps a broken position from looping forever: it fails as a
  # partition mismatch instead of hanging the suite.
  defp walk_positions(opts, page_size) do
    sort = Keyword.get(opts, :sort) || Inventory.default_group_sort()
    bound = div(Inventory.count_groups(opts), page_size) + 2

    {_, pages} =
      Enum.reduce_while(1..bound, {nil, []}, fn _page, {before, acc} ->
        case Inventory.list_groups(opts ++ [limit: page_size, before: before]) do
          [] ->
            {:halt, {nil, acc}}

          rows ->
            {:ok, cursor} = GroupCursor.parse(sort, GroupCursor.encode(sort, List.last(rows)))
            {:cont, {cursor, acc ++ [Enum.map(rows, & &1.cve)]}}
        end
      end)

    List.flatten(pages)
  end

  defp add_advisories!(count) do
    {:ok, image} =
      Inventory.upsert_image(
        %{
          digest: "sha256:" <> String.duplicate("e", 64),
          repository: "registry.internal/paging-fixture",
          tag: "1.0",
          description: "Fixture for bounded, sorted, paged advisory groups"
        },
        @now
      )

    {:ok, _placement} =
      Inventory.upsert_placement(
        image,
        %{namespace: "web", owner: "alpha", environment: "prod-cluster-1"},
        @now
      )

    for n <- 1..count do
      {:ok, _finding} =
        Inventory.upsert_finding(
          image,
          %{
            cve: "CVE-2098-7001#{n}",
            package_name: "paging-package-#{n}",
            package_version: "1.#{n}",
            severity: Enum.at(@severities, rem(n, 4)),
            fix: nil,
            description: "Paging fixture #{n}",
            suppressed: false
          },
          DateTime.add(@now, n, :minute),
          reopen: false
        )
    end

    :ok
  end
end
