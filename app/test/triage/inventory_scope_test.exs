defmodule Triage.InventoryScopeTest do
  @moduledoc """
  Context regressions for scope validation (owner/environment/search) and
  finding-id guards on the public `Triage.Inventory` entrypoints.
  """

  use Triage.DataCase, async: true

  import Ecto.Query
  alias Triage.{Inventory, Repo, Seeds}
  alias Triage.Inventory.{Finding, Image, ImagePlacement}

  @staging "staging-cluster-1"
  @now ~U[2026-09-09 06:00:00Z]

  setup do
    :ok = Seeds.seed()

    image_a = Repo.one!(from i in Image, where: i.repository == "registry.internal/app-a")

    {:ok, _} =
      Repo.insert(
        ImagePlacement.changeset(%ImagePlacement{}, %{
          image_id: image_a.id,
          namespace: "web",
          owner: "alpha",
          environment: @staging,
          active: true,
          first_seen: @now,
          last_seen: @now
        })
      )

    {:ok, _} =
      Repo.insert(
        ImagePlacement.changeset(%ImagePlacement{}, %{
          image_id: image_a.id,
          namespace: "web",
          owner: "beta",
          environment: @staging,
          active: false,
          first_seen: @now,
          last_seen: @now
        })
      )

    :ok
  end

  describe "scope validation on public entrypoints" do
    test "non-binary scope values raise instead of being coerced into a name" do
      assert_raise ArgumentError, fn -> Inventory.list_groups(owner: 123) end
      assert_raise ArgumentError, fn -> Inventory.list_groups(environment: ["prod-cluster-1"]) end
      assert_raise ArgumentError, fn -> Inventory.fetch_finding(1, owner: %{x: 1}) end
    end

    test "NUL and control characters are rejected before reaching PostgreSQL" do
      # A NUL byte would make PostgreSQL fail with character_not_in_repertoire;
      # the context rejects it with a predictable ArgumentError first.
      assert_raise ArgumentError, fn -> Inventory.list_groups(owner: "al\u0000pha") end
      assert_raise ArgumentError, fn -> Inventory.list_groups(search: "a\u0001b") end
      assert_raise ArgumentError, fn -> Inventory.fetch_finding(1, environment: "a\u007Fb") end
    end

    test "raw control characters are rejected before trimming, even edge-only values" do
      # \talpha would otherwise trim into a real team name; control-only and
      # edge-control values must never become a scope or the All choice.
      for value <- ["\talpha", "alpha\n", "\ralpha", " \t ", "\t", "\n", "\u0000", "\u007F"] do
        assert_raise ArgumentError, fn -> Inventory.list_groups(owner: value) end
        assert_raise ArgumentError, fn -> Inventory.list_groups(search: value) end
        assert_raise ArgumentError, fn -> Inventory.fetch_finding(1, environment: value) end
      end
    end

    test "invalid UTF-8 binaries are rejected before trimming instead of reaching PostgreSQL" do
      assert_raise ArgumentError, fn -> Inventory.list_groups(owner: "alpha" <> <<0xFF>>) end
      assert_raise ArgumentError, fn -> Inventory.fetch_finding(1, environment: <<0x80>>) end
    end

    test "overlong scopes are not truncated into another team's name" do
      assert Inventory.list_groups(owner: String.duplicate("alpha-", 25)) == []
      assert Inventory.list_groups(environment: String.duplicate("prod-cluster-1-", 9)) == []
    end

    test "blank scopes remain the intentional All choice" do
      assert Inventory.list_groups(owner: "  ") != []
      assert Inventory.list_groups(owner: "") != []
    end
  end

  describe "fetch_finding/2 id guards" do
    # 2^63 is one past the int8 maximum; the expectation is computed
    # independently of the runtime constant under test.
    test "malformed, zero, negative and out-of-range ids fail predictably" do
      for bad <- ["1", "abc", 0, -1, true, Integer.pow(2, 63)] do
        assert :error = Inventory.fetch_finding(bad)
      end
    end

    test "the true int8 boundary id is valid and 2^63 is rejected before querying" do
      image_a = Repo.one!(from i in Image, where: i.repository == "registry.internal/app-a")
      max_id = Integer.pow(2, 63) - 1

      Repo.insert!(%Finding{
        id: max_id,
        image_id: image_a.id,
        cve: "CVE-2025-9001",
        package_name: "edge-package",
        package_version: "1.0",
        severity: "LOW",
        first_seen: @now,
        last_seen: @now
      })

      assert {:ok, %{finding: %{cve: "CVE-2025-9001"}}} = Inventory.fetch_finding(max_id)

      # One past the int8 maximum would make PostgreSQL raise "bigint out of
      # range" if it reached a query; the context guard rejects it first.
      assert :error = Inventory.fetch_finding(Integer.pow(2, 63))
    end
  end

  describe "CVE aggregate placement scope" do
    test "owner, environment and combined scopes constrain placements on shared images" do
      for scope <- [
            [owner: "alpha"],
            [environment: @staging],
            [owner: "alpha", environment: @staging]
          ] do
        assert {:ok, detail} = Inventory.fetch_cve("CVE-2026-60002", scope)
        assert detail.placements != []

        assert Enum.all?(detail.placements, fn %{placement: placement} ->
                 Enum.all?(scope, fn {key, value} -> Map.fetch!(placement, key) == value end)
               end)
      end
    end

    test "unscoped reads retain all placements, including retired context" do
      assert {:ok, detail} = Inventory.fetch_cve("CVE-2026-60002")
      assert Enum.any?(detail.placements, &(&1.placement.owner == "alpha"))
      assert Enum.any?(detail.placements, &(&1.placement.owner == "beta"))
      assert Enum.any?(detail.placements, &(not &1.placement.active))
    end
  end

  describe "environment and owner scoping through fetch_finding/2" do
    test "environment-only scope keeps active-gated placements and scoped occurrences" do
      openssh_client =
        Repo.one!(
          from f in Finding,
            where: f.cve == "CVE-2026-60002" and f.package_name == "openssh-client"
        )

      {:ok, data} = Inventory.fetch_finding(openssh_client.id, environment: @staging)

      # display keeps every matching placement, active or retired
      assert Enum.map(data.placements, &{&1.owner, &1.active}) |> Enum.sort() ==
               [{"alpha", true}, {"beta", false}]

      # related occurrences follow only active placements in the environment
      assert Enum.map(data.other_occurrences, & &1.package_name) == ["openssh-client-common"]
    end

    test "owner+environment intersection" do
      openssh_client =
        Repo.one!(
          from f in Finding,
            where: f.cve == "CVE-2026-60002" and f.package_name == "openssh-client"
        )

      {:ok, data} =
        Inventory.fetch_finding(openssh_client.id, owner: "alpha", environment: @staging)

      assert [%{owner: "alpha", environment: @staging}] = data.placements
      assert Enum.map(data.other_occurrences, & &1.package_name) == ["openssh-client-common"]
    end

    test "a retired-only matching placement is out of scope" do
      openssh_client =
        Repo.one!(
          from f in Finding,
            where: f.cve == "CVE-2026-60002" and f.package_name == "openssh-client"
        )

      assert {:error, :out_of_scope} =
               Inventory.fetch_finding(openssh_client.id, owner: "beta", environment: @staging)
    end

    test "unknown valid scopes return empty lists or out_of_scope, never everything" do
      openssh_client =
        Repo.one!(
          from f in Finding,
            where: f.cve == "CVE-2026-60002" and f.package_name == "openssh-client"
        )

      assert Inventory.list_groups(owner: "beta", environment: @staging) == []

      assert {:error, :out_of_scope} =
               Inventory.fetch_finding(openssh_client.id, environment: "ghost")

      assert {:error, :out_of_scope} = Inventory.fetch_finding(openssh_client.id, owner: "ghost")
    end

    test "unscoped calls keep the full history, placements and occurrences" do
      openssh_client =
        Repo.one!(
          from f in Finding,
            where: f.cve == "CVE-2026-60002" and f.package_name == "openssh-client"
        )

      {:ok, data} = Inventory.fetch_finding(openssh_client.id)

      assert length(data.placements) == 4

      assert Enum.map(data.other_occurrences, & &1.package_name) == [
               "openssh-client-common",
               "openssh-sftp-server"
             ]

      assert Enum.map(data.events, & &1.event) == ["appeared"]
    end
  end
end
