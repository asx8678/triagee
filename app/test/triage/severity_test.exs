defmodule Triage.SeverityTest do
  use ExUnit.Case, async: true
  alias Triage.{Inventory, Severity}

  test "all consumers retain the same scanner order and labels" do
    assert Severity.order() == ~w(CRITICAL HIGH MEDIUM LOW)
    assert Inventory.severity_order() == Severity.order()

    for {label, rank} <- Enum.zip(Severity.order(), 4..1//-1) do
      assert Severity.rank(label) == rank
      assert Severity.label(rank) == label
      assert Inventory.severity_label(rank) == label
    end
  end

  test "normalization is explicit and does not rewrite unknown legacy display ranks" do
    assert Severity.normalize(" high ") == "HIGH"
    assert Severity.normalize("MODERATE") == nil
    assert Severity.normalize(nil) == nil

    for unknown <- [nil, "", "critical", "MODERATE", false, 12] do
      assert Severity.rank(unknown) == 0
    end

    assert Severity.label(0) == "UNKNOWN"
    assert Inventory.severity_label(nil) == "UNKNOWN"
  end

  test "SQL ordering and the import lock keep their original contracts" do
    assert Severity.sql_max_rank() ==
             "max(case ? when 'CRITICAL' then 4 when 'HIGH' then 3 when 'MEDIUM' then 2 when 'LOW' then 1 else 0 end)"

    assert Triage.Import.Contract.lock_key() == 7_433_921_021_337
  end
end
