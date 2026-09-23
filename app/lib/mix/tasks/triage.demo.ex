defmodule Mix.Tasks.Triage.Demo do
  use Mix.Task
  alias Triage.Repo

  @shortdoc "Add the fictional presentation fleet without resetting existing data"
  @moduledoc """
  Add 30 fictional CVEs across 18 workloads and 54 placements:

      mix triage.demo --database triage_dev

  Development/local databases only. Adds missing cases atomically; never resets
  existing findings, decisions, drafts or timestamps. No network/provider calls.
  """
  @impl true
  def run(args) do
    {opts, rest, invalid} = OptionParser.parse(args, strict: [database: :string])

    unless Mix.env() == :dev and rest == [] and invalid == [] and
             Keyword.keys(opts) == [:database],
           do: Mix.raise("Use MIX_ENV=dev mix triage.demo --database EXACT_LOCAL_DATABASE")

    Mix.Task.run("app.config")
    config = Repo.config()
    expected = Keyword.fetch!(opts, :database)

    unless config[:hostname] in ["localhost", "127.0.0.1", "::1"] and
             is_nil(config[:url]) and is_nil(config[:socket_dir]) and
             config[:database] == expected,
           do:
             Mix.raise(
               "Demo seeding requires the exact configured local database; nothing changed"
             )

    {:ok, _} = Application.ensure_all_started(:ecto_sql)
    {:ok, _} = Application.ensure_all_started(:postgrex)
    {:ok, _} = Repo.start_link()
    %{rows: [[^expected]]} = Repo.query!("SELECT current_database()")
    result = Triage.Seeds.DemoFleet.seed!()
    Mix.shell().info("Fictional demo fleet in #{expected}: #{inspect(result)}")
  end
end
