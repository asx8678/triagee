defmodule Triage.ExposureTest do
  @moduledoc """
  Exposure evidence validity, structured current state and dismissal support
  (W01b/A08).

  Display and trust are separate: the latest observation decides what is shown
  (invalid evidence shows as `unknown`), while only evidence from a source with
  an approved bounded-age policy may support a dismissal.
  """
  use Triage.DataCase, async: false

  import Ecto.Query
  import Triage.Fixtures
  alias Triage.{Exposure, Repo, Seeds}
  alias Triage.Exposure.Policy
  alias Triage.Inventory.ImagePlacement

  setup do
    :ok = Seeds.seed()
    :ok
  end

  defp fresh_placement!(tag) do
    image = image!("exposure-#{tag}")
    placement!(image, "exposure-#{tag}", "prod").id
  end

  defp now, do: DateTime.utc_now() |> DateTime.truncate(:second)

  test "record stores valid exposure evidence and history is preserved" do
    placement = fresh_placement!("history")
    observed = now()

    assert {:ok, _} =
             Exposure.record(placement, "internet_exposed", "operator test", observed)

    # A strictly later observation supersedes; both rows remain in history.
    assert {:ok, _} =
             Exposure.record(
               placement,
               "internal",
               "second record",
               DateTime.add(observed, 60, :second)
             )

    current = Exposure.current_by_placement([placement], DateTime.add(observed, 120, :second))
    assert current[placement] == "internal"

    count =
      Repo.aggregate(from(e in Exposure.Evidence, where: e.placement_id == ^placement), :count)

    assert count == 2
  end

  test "expired evidence falls back to unknown" do
    placement = fresh_placement!("expiry")
    observed_at = DateTime.add(now(), -3600, :second)
    expired_at = DateTime.add(now(), -60, :second)

    assert {:ok, _} =
             Exposure.record(placement, "internal", "stale test", observed_at, expired_at)

    assert Exposure.current_by_placement([placement], now())[placement] == "unknown"

    assert %{state: :expired, usable?: false} =
             Exposure.current_evidence([placement], now())[placement]

    # New evidence without expiry wins.
    assert {:ok, _} = Exposure.record(placement, "internet_exposed", "fresh", now())

    assert Exposure.current_by_placement([placement], now())[placement] == "internet_exposed"
  end

  test "equal-time conflicting evidence is never resolved by row id" do
    placement = fresh_placement!("conflict")
    observed = now()

    assert {:ok, _} = Exposure.record(placement, "internet_exposed", "source a", observed)
    assert {:ok, _} = Exposure.record(placement, "internal", "source b", observed)

    # The old behavior picked the highest id; the display must not silently
    # choose between two contradicting assertions.
    assert Exposure.current_by_placement([placement], now())[placement] == "unknown"

    evidence = Exposure.current_evidence([placement], now())[placement]
    assert evidence.state == :conflicting
    refute evidence.usable?
    assert evidence.reason =~ "Conflicting"
  end

  test "future-dated evidence beyond the approved tolerance never displays as current" do
    placement = fresh_placement!("future")
    tolerance = Policy.clock_tolerance_seconds()

    # The effect boundary refuses a future observation outright...
    assert {:error, :future_observation} =
             Exposure.record(
               placement,
               "internet_exposed",
               "skewed clock",
               DateTime.add(now(), tolerance + 60, :second)
             )

    # ...and a row that already exists that way (legacy or direct write) is
    # invalid for display and trust rather than silently plausible.
    Repo.insert!(%Exposure.Evidence{
      placement_id: placement,
      exposure: "internet_exposed",
      source: "legacy future row",
      observed_at: DateTime.add(now(), 7200, :second)
    })

    assert Exposure.current_by_placement([placement], now())[placement] == "unknown"

    assert %{state: :future_dated, usable?: false} =
             Exposure.current_evidence([placement], now())[placement]

    # Within tolerance is a normal observation of the present.
    other = fresh_placement!("skew-ok")

    assert {:ok, _} =
             Exposure.record(
               other,
               "internet_exposed",
               "slightly skewed",
               DateTime.add(now(), tolerance - 30, :second)
             )

    assert Exposure.current_by_placement([other], now())[other] == "internet_exposed"
  end

  test "an expiry before its own observation is refused; a zero-length window is allowed" do
    placement = fresh_placement!("expiry-order")
    observed = now()

    assert {:error, :expiry_before_observation} =
             Exposure.record(
               placement,
               "internal",
               "impossible window",
               observed,
               DateTime.add(observed, -60, :second)
             )

    # Equality is a deliberate zero-length window: valid evidence that is already
    # expired once the clock passes its instant.
    assert {:ok, _} = Exposure.record(placement, "internal", "zero window", observed, observed)
    assert Exposure.current_by_placement([placement], observed)[placement] == "internal"

    later = DateTime.add(observed, 60, :second)
    assert Exposure.current_by_placement([placement], later)[placement] == "unknown"
  end

  test "only an approved bounded-age source policy can support a dismissal" do
    placement = fresh_placement!("policy")
    observed = DateTime.add(now(), -3600, :second)

    original = Application.get_env(:triage, :exposure_policy)

    on_exit(fn ->
      if original,
        do: Application.put_env(:triage, :exposure_policy, original),
        else: Application.delete_env(:triage, :exposure_policy)
    end)

    # No policy is approved by default: display works, trust does not.
    assert {:ok, _} = Exposure.record(placement, "internal", "scanner:trivy", observed)

    unbounded = Exposure.current_evidence([placement], now())[placement]
    assert unbounded.state == :current
    assert unbounded.exposure == "internal"
    refute unbounded.usable?
    assert unbounded.reason =~ "bounded-age policy"

    # An approved bounded policy with fresh evidence is usable.
    Application.put_env(:triage, :exposure_policy, %{
      "scanner:trivy" => %{max_age_days: 1, require_expiry: false}
    })

    assert Exposure.current_evidence([placement], now())[placement].usable?

    # An approved entry with an unusable shape stays unbounded (fail closed).
    Application.put_env(:triage, :exposure_policy, %{"scanner:trivy" => %{max_age_days: 0}})
    refute Exposure.current_evidence([placement], now())[placement].usable?

    # A source requiring an expiry rejects evidence without one.
    Application.put_env(:triage, :exposure_policy, %{
      "scanner:trivy" => %{max_age_days: 1, require_expiry: true}
    })

    refute Exposure.current_evidence([placement], now())[placement].usable?

    # Evidence older than the approved age is not usable either.
    fresh = fresh_placement!("policy-stale")
    stale_observed = DateTime.add(now(), -40, :day)

    assert {:ok, _} = Exposure.record(fresh, "internal", "scanner:trivy", stale_observed)

    Application.put_env(:triage, :exposure_policy, %{
      "scanner:trivy" => %{max_age_days: 30, require_expiry: false}
    })

    refute Exposure.current_evidence([fresh], now())[fresh].usable?
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

    assert {:error, _} = Exposure.record(placement.id, "internal", "   ", DateTime.utc_now())
  end
end
