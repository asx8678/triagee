defmodule Triage.InventoryPagingTest do
  @moduledoc """
  Regressions for bounded, sortable advisory groups: the unpaged total a page is
  computed from, the strict total order of every published sort, and the
  partition property that paging neither duplicates nor drops a group.
  """

  use Triage.DataCase, async: true

  alias Triage.{Inventory, Seeds}

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

  test "paging partitions the unpaged list exactly" do
    all = Enum.map(Inventory.list_groups(sort: "cve"), & &1.cve)
    assert length(all) > 5

    paged =
      for offset <- 0..(length(all) - 1)//5 do
        Inventory.list_groups(sort: "cve", limit: 5, offset: offset) |> Enum.map(& &1.cve)
      end
      |> List.flatten()

    assert paged == all
  end

  test "paging keeps every filter, not only the ordering" do
    scoped = Inventory.list_groups(owner: "alpha", sort: "cve")
    assert scoped != []

    assert Inventory.list_groups(owner: "alpha", sort: "cve", limit: 3)
           |> Enum.map(& &1.cve) == scoped |> Enum.map(& &1.cve) |> Enum.take(3)

    assert Inventory.count_groups(owner: "alpha") == length(scoped)

    assert Inventory.list_groups(owner: "alpha", sort: "cve", offset: 1)
           |> Enum.map(& &1.cve) == scoped |> Enum.map(& &1.cve) |> Enum.drop(1)
  end

  test "a page past the end is empty rather than shortened or wrapped" do
    assert Inventory.list_groups(limit: 5, offset: 10_000) == []
    assert Inventory.list_groups(limit: 5, offset: Inventory.count_groups([])) == []
  end

  test "the page size is bounded while a deep offset stays reachable" do
    assert Inventory.list_groups(limit: 0) == []
    assert length(Inventory.list_groups(limit: 2)) == 2

    # A late page of a large inventory must not be rejected by the page-size cap.
    assert Inventory.list_groups(limit: 2, offset: 10_000) == []

    assert_raise ArgumentError, fn -> Inventory.list_groups(limit: -1) end
    assert_raise ArgumentError, fn -> Inventory.list_groups(limit: 201) end
    assert_raise ArgumentError, fn -> Inventory.list_groups(limit: "2") end
    assert_raise ArgumentError, fn -> Inventory.list_groups(offset: -1) end
    assert_raise ArgumentError, fn -> Inventory.list_groups(offset: 2.0) end
    assert_raise ArgumentError, fn -> Inventory.list_groups(sort: "nonsense") end
    assert_raise ArgumentError, fn -> Inventory.list_groups(sort: :newest) end
  end

  test "the newest rail shares the list's newest order" do
    assert Enum.map(Inventory.newest_cve_groups(3), & &1.cve) ==
             Inventory.list_groups(sort: "newest", limit: 3) |> Enum.map(& &1.cve)
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
