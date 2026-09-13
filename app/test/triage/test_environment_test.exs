defmodule Triage.TestEnvironmentTest do
  @moduledoc """
  Guards the test environment against silent data leakage.

  `ecto.reset` and `setup` used to chain `run priv/repo/seeds.exs`, including
  under `MIX_ENV=test`. The Ecto SQL sandbox rolls back writes made by tests
  but does not hide rows that already exist, so the synthetic inventory created
  by the seeds stayed visible to every test. Data-dependent assertions then
  failed with counts unrelated to the test itself (for example
  `assert length(rows) == 2` observing 13 rows), which presented as a query
  defect instead of an environment defect.
  """
  use ExUnit.Case, async: true

  @seed_task "run priv/repo/seeds.exs"

  test "ecto.setup never seeds, in any environment" do
    aliases = Mix.Project.config()[:aliases]

    refute @seed_task in aliases[:"ecto.setup"],
           "ecto.setup must not seed: `MIX_ENV=test mix ecto.reset` would leave " <>
             "synthetic inventory rows in the test database"
  end

  test "the test environment never implicitly seeds setup or reset" do
    aliases = Mix.Project.config()[:aliases]

    # Mix.env() is :test for this run, so the development convenience seeding
    # must be absent. Seeding is still reachable explicitly via `mix ecto.seed`.
    assert Mix.env() == :test
    refute "ecto.seed" in aliases[:setup]
    refute "ecto.seed" in aliases[:"ecto.reset"]
    refute @seed_task in aliases[:setup]
    refute @seed_task in aliases[:"ecto.reset"]
  end

  test "development keeps convenience seeding, guarded by the environment" do
    # The guard lives in mix.exs exactly because the alias list is evaluated in
    # the environment running the task. Asserting on the guard keeps a future
    # edit from re-seeding test setup while leaving dev setup convenient.
    source = File.read!("mix.exs")

    assert source =~ ~s|Mix.env() == :dev|
    assert source =~ ~s|"ecto.seed"|
  end

  test "seeding stays available explicitly" do
    aliases = Mix.Project.config()[:aliases]

    assert @seed_task in aliases[:"ecto.seed"]
  end

  test "the test alias creates and migrates without seeding" do
    aliases = Mix.Project.config()[:aliases]

    assert aliases[:test] == [
             "ecto.create --quiet",
             "ecto.migrate --quiet",
             "assets.setup",
             "test"
           ]
  end
end
