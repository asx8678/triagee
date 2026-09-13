defmodule Triage.ExposureTest do
  use Triage.DataCase, async: false

  import Ecto.Query
  alias Triage.{Exposure, Repo, Seeds}
  alias Triage.Inventory.ImagePlacement

  setup do
    :ok = Seeds.seed()
    :ok
  end

  test "record stores valid exposure evidence and history is preserved" do
    placement =
      Repo.one!(
        from(p in ImagePlacement,
          where: p.owner == "alpha" and p.namespace == "web",
          limit: 1
        )
      )

    now = DateTime.utc_now()

    assert {:ok, _} =
             Exposure.record(placement.id, "internet_exposed", "operator test", now)

    assert {:ok, _} = Exposure.record(placement.id, "internal", "second record", now)

    current = Exposure.current_by_placement([placement.id], now)
    assert current[placement.id] == "internal"
  end

  test "expired evidence falls back to unknown" do
    placement =
      Repo.one!(
        from(p in ImagePlacement, where: p.owner == "beta" and p.namespace == "web", limit: 1)
      )

    past = DateTime.add(DateTime.utc_now(), -3600, :second)
    future = DateTime.add(DateTime.utc_now(), 3600, :second)

    assert {:ok, _} = Exposure.record(placement.id, "internal", "stale test", past, past)

    assert Exposure.current_by_placement([placement.id], DateTime.utc_now())[placement.id] ==
             "unknown"

    # New evidence without expiry wins.
    assert {:ok, _} = Exposure.record(placement.id, "internet_exposed", "fresh", future)

    assert Exposure.current_by_placement([placement.id], DateTime.utc_now())[placement.id] ==
             "internet_exposed"
  end

  test "placements without any evidence stay unknown" do
    image_c =
      Repo.one!(
        from(i in Triage.Inventory.Image,
          join: p in ImagePlacement,
          on: p.image_id == i.id,
          where: p.namespace == "(unknown)",
          select: p
        )
      )

    assert Exposure.current_by_placement([image_c.id]) == %{}
  end

  test "record rejects invalid exposure and placement" do
    assert {:error, _} = Exposure.record(:not_int, "internal", "src", DateTime.utc_now())
    assert {:error, _} = Exposure.record(1, "compromised-forever", "src", DateTime.utc_now())

    placement = Repo.one!(from(p in ImagePlacement, limit: 1))

    assert {:error, _} =
             Exposure.record(placement.id, "internal", :atom_source, DateTime.utc_now())
  end
end
