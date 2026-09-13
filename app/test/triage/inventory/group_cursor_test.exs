defmodule Triage.Inventory.GroupCursorTest do
  @moduledoc """
  Unit regressions for the keyset position contract: one key list per published
  order, canonical encoding, and strict total parsing that rejects anything the
  order could not have produced instead of coercing it into a position.
  """

  use ExUnit.Case, async: true

  alias Triage.Inventory
  alias Triage.Inventory.GroupCursor

  @rows %{
    "severity" => %{severity_rank: 4, images: 12, cve: "CVE-2024-1001"},
    "newest" => %{first_seen: ~U[2026-09-10 12:00:00Z], cve: "CVE-2024-1001"},
    "occurrences" => %{occurrences: 7, cve: "CVE-2024-1001"},
    "cve" => %{cve: "CVE-2024-1001"}
  }

  test "every published order has one key list ending in the unique advisory id" do
    for sort <- Inventory.group_sorts() do
      keys = GroupCursor.keys(sort)
      names = Enum.map(keys, fn {name, _direction, _type} -> name end)

      assert names == Enum.uniq(names)
      assert List.last(names) == :cve
      assert Enum.all?(keys, fn {_name, direction, _type} -> direction in [:asc, :desc] end)
    end

    assert_raise ArgumentError, fn -> GroupCursor.keys("nonsense") end
    assert_raise ArgumentError, fn -> GroupCursor.keys(nil) end
  end

  test "a position round trips for every order" do
    for sort <- Inventory.group_sorts() do
      row = Map.fetch!(@rows, sort)

      assert GroupCursor.parse(sort, GroupCursor.encode(sort, row)) == {:ok, row}
    end
  end

  test "boundary values round trip" do
    smallest = %{severity_rank: 0, images: 0, cve: "CVE-1999-0001"}

    assert GroupCursor.parse("severity", GroupCursor.encode("severity", smallest)) ==
             {:ok, smallest}

    largest = %{severity_rank: 4, images: 9_223_372_036_854_775_807, cve: "CVE-2026-0001"}

    assert GroupCursor.parse("severity", GroupCursor.encode("severity", largest)) ==
             {:ok, largest}

    earliest = %{first_seen: ~U[1970-01-01 00:00:00Z], cve: "CVE-1970-0001"}
    assert GroupCursor.parse("newest", GroupCursor.encode("newest", earliest)) == {:ok, earliest}
  end

  test "an absent or blank position is the start of the order" do
    for sort <- Inventory.group_sorts() do
      assert GroupCursor.parse(sort, nil) == {:ok, nil}
      assert GroupCursor.parse(sort, "") == {:ok, nil}
    end
  end

  test "a position must carry exactly the fields of its order" do
    assert GroupCursor.parse("severity", "4~12") == {:error, :before}
    assert GroupCursor.parse("severity", "4~12~CVE-x~extra") == {:error, :before}
    assert GroupCursor.parse("cve", "CVE-x~extra") == {:error, :before}
    assert GroupCursor.parse("newest", "CVE-x") == {:error, :before}
    assert GroupCursor.parse("severity", "CVE-x") == {:error, :before}
  end

  test "a number must be canonical and inside its field's range" do
    for bad <- [
          "01~2~CVE-x",
          "-1~2~CVE-x",
          "1.0~2~CVE-x",
          " 1~2~CVE-x",
          "1 ~2~CVE-x",
          "0x1~2~CVE-x",
          "1e2~2~CVE-x",
          "1~-2~CVE-x",
          "99999999999999999999~2~CVE-x",
          "5~2~CVE-x"
        ] do
      assert GroupCursor.parse("severity", bad) == {:error, :before}, "accepted #{inspect(bad)}"
    end

    assert GroupCursor.parse("occurrences", "9223372036854775808~CVE-x") == {:error, :before}
    assert GroupCursor.parse("occurrences", "9223372036854775807~CVE-x") != {:error, :before}
  end

  test "a timestamp must be canonical UTC" do
    for bad <- [
          "2026-09-10T12:00:00+02:00~CVE-x",
          "2026-09-10T12:00:00~CVE-x",
          "2026-09-10T12:00:00.000000Z~CVE-x",
          "2026-09-10T12:00:00.123456Z~CVE-x",
          "2026-09-10 12:00:00Z~CVE-x",
          "not-a-time~CVE-x"
        ] do
      assert GroupCursor.parse("newest", bad) == {:error, :before}, "accepted #{inspect(bad)}"
    end

    assert GroupCursor.parse("newest", "2026-09-10T12:00:00Z~CVE-x") ==
             {:ok, %{first_seen: ~U[2026-09-10 12:00:00Z], cve: "CVE-x"}}
  end

  test "advisory text must be plain, canonical and unseparated" do
    for bad <- [
          "4~1~",
          "4~1~ cve",
          "4~1~cve ",
          "4~1~CVE~x",
          "4~1~" <> String.duplicate("c", 121),
          "4~1~cve\n"
        ] do
      assert GroupCursor.parse("severity", bad) == {:error, :before}, "accepted #{inspect(bad)}"
    end

    assert GroupCursor.parse("severity", "4~1~" <> <<0xFF>>) == {:error, :before}

    assert GroupCursor.parse("severity", "4~1~CVE-" <> String.duplicate("c", 115)) !=
             {:error, :before}
  end

  test "anything that is not a position is rejected, never raised" do
    for bad <- [5, :cve, %{}, [], {:ok, nil}, 1.5, <<0xFF>>] do
      assert GroupCursor.parse("cve", bad) == {:error, :before}, "accepted #{inspect(bad)}"
    end

    assert GroupCursor.parse("nonsense", "CVE-x") == {:error, :before}
    assert GroupCursor.parse(nil, "CVE-x") == {:error, :before}
    assert GroupCursor.parse(:cve, "CVE-x") == {:error, :before}
  end

  test "encoding a row that is not a position raises rather than writing one" do
    assert_raise ArgumentError, fn -> GroupCursor.encode("severity", %{severity_rank: 4}) end

    assert_raise ArgumentError, fn ->
      GroupCursor.encode("severity", %{severity_rank: "4", images: 1, cve: "CVE-x"})
    end

    assert_raise ArgumentError, fn ->
      GroupCursor.encode("severity", %{severity_rank: 5, images: 1, cve: "CVE-x"})
    end

    assert_raise ArgumentError, fn ->
      GroupCursor.encode("severity", %{severity_rank: 4, images: -1, cve: "CVE-x"})
    end

    assert_raise ArgumentError, fn ->
      GroupCursor.encode("newest", %{first_seen: "2026-09-10", cve: "CVE-x"})
    end

    assert_raise ArgumentError, fn -> GroupCursor.encode("cve", %{cve: " CVE-x"}) end
    assert_raise ArgumentError, fn -> GroupCursor.encode("cve", %{cve: "CVE~x"}) end
  end
end
