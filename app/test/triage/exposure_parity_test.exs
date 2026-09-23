defmodule Triage.ExposureParityTest do
  @moduledoc """
  One exposure display policy, two implementations (W01b/A08).

  `Triage.Exposure` and the SQL lateral join in `Triage.Workspace.Query` must
  agree for valid, expired, future-dated and equal-time conflicting evidence,
  including the `unknown` bucket that drives queue modes, metrics and priority.
  """
  use Triage.DataCase, async: false

  import Triage.Fixtures
  alias Triage.{Exposure, Repo, Workspace}

  setup do
    reset_inventory!()
    :ok
  end

  test "the Elixir and SQL exposure projections agree for every validity case" do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    scenarios = [
      {"valid", "CVE-2095-1001", [{"internet_exposed", now, nil}]},
      {"expired", "CVE-2095-1002",
       [{"internal", DateTime.add(now, -3600, :second), DateTime.add(now, -60, :second)}]},
      {"future", "CVE-2095-1003", [{"internet_exposed", DateTime.add(now, 7200, :second), nil}]},
      {"conflict", "CVE-2095-1004", [{"internal", now, nil}, {"internet_exposed", now, nil}]}
    ]

    ids =
      for {tag, cve, rows} <- scenarios, into: %{} do
        image = image!("parity-#{tag}")
        placement = placement!(image, "parity-#{tag}", "prod")
        finding!(image, cve, severity: "HIGH")

        # Written directly: these are pre-existing evidence states (including
        # one the record boundary would now refuse) whose display must still be
        # one policy across both implementations.
        Enum.each(rows, fn {exposure, observed_at, expires_at} ->
          Repo.insert!(%Exposure.Evidence{
            placement_id: placement.id,
            exposure: exposure,
            source: "fixture",
            observed_at: observed_at,
            expires_at: expires_at
          })
        end)

        {cve, placement.id}
      end

    targets = Workspace.targets(%{})
    by_id = Map.new(targets, &{&1.id, &1.exposure})

    assert by_id[ids["CVE-2095-1001"]] == "internet_exposed"
    assert by_id[ids["CVE-2095-1002"]] == "unknown"
    assert by_id[ids["CVE-2095-1003"]] == "unknown"
    assert by_id[ids["CVE-2095-1004"]] == "unknown"

    # The SQL mode filter must select exactly the CVEs the Elixir projection
    # does: any divergence in expiry, clock tolerance or tie handling shows here.
    elixir_unknown =
      targets |> Workspace.select("unknown") |> Enum.map(& &1.cve) |> Enum.sort()

    sql_unknown =
      Workspace.page(%{"mode" => "unknown"}).page_rows |> Enum.map(& &1.cve) |> Enum.sort()

    assert sql_unknown == elixir_unknown
    assert elixir_unknown == ["CVE-2095-1002", "CVE-2095-1003", "CVE-2095-1004"]

    # A valid exposure still escalates priority through the SQL-backed page.
    row = Enum.find(Workspace.page(%{"mode" => "all"}).page_rows, &(&1.cve == "CVE-2095-1001"))
    assert row.risk.priority == "critical"
  end
end
