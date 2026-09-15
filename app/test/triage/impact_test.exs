defmodule Triage.ImpactTest do
  use Triage.DataCase, async: true

  import Ecto.Query

  import Triage.Fixtures

  alias Triage.Impact

  setup do
    reset_inventory!()
    image = image!("impact")
    placement = placement!(image, "alpha", "prod-cluster-1")
    %{placement: placement}
  end

  test "records impact evidence with its source and observation time", %{placement: placement} do
    assert {:ok, evidence} = Impact.record(placement.id, "high", "test:operator declared", at(0))
    assert evidence.impact == "high"

    current = Impact.current_by_placement([placement.id]) |> Map.fetch!(placement.id)
    assert current.impact == "high"
    assert current.label == "High"
    assert current.state == :active
    assert current.source == "test:operator declared"
    assert current.observed_at == at(0)
    assert current.expires_at == nil
  end

  test "the latest observation wins", %{placement: placement} do
    assert {:ok, _} = Impact.record(placement.id, "low", "test:older", at(4))
    assert {:ok, _} = Impact.record(placement.id, "critical", "test:newer", at(0))

    current = Impact.current_by_placement([placement.id]) |> Map.fetch!(placement.id)
    assert current.impact == "critical"
    assert current.source == "test:newer"
  end

  test "expired evidence stops asserting a judgement", %{placement: placement} do
    assert {:ok, _} =
             Impact.record(
               placement.id,
               "none",
               "test:expired",
               at(0),
               DateTime.add(at(0), 1, :day)
             )

    assert %{state: :active} =
             Impact.current_by_placement([placement.id]) |> Map.fetch!(placement.id)

    later = DateTime.add(at(0), 2, :day)
    expired = Impact.current_by_placement([placement.id], later) |> Map.fetch!(placement.id)
    assert expired.state == :expired
    assert expired.impact == nil
    assert expired.source == "test:expired"
  end

  test "an unknown impact word is refused", %{placement: placement} do
    assert {:error, :invalid_impact_evidence} =
             Impact.record(placement.id, "apocalyptic", "test", at(0))

    assert {:error, :invalid_impact_evidence} = Impact.record("123", "high", "test", at(0))
    assert {:ok, _} = Impact.record(placement.id, "high", "test", at(0))
  end

  test "history is append-only", %{placement: placement} do
    assert {:ok, _} = Impact.record(placement.id, "low", "test:one", at(3))
    assert {:ok, _} = Impact.record(placement.id, "high", "test:two", at(1))

    count = Repo.one(from(e in Impact.Evidence, select: count(e.id)))
    assert count == 2
  end

  test "no evidence is not the same as no impact", %{placement: placement} do
    assert Impact.current_by_placement([placement.id]) == %{}
    assert placement.id not in Map.keys(Impact.current_by_placement([placement.id]))
  end
end
