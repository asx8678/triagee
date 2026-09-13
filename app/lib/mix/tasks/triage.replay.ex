defmodule Mix.Tasks.Triage.Replay do
  @shortdoc "Replays a bounded synthetic JSON file without starting the application"
  @moduledoc """
  Run `mix triage.replay --file PATH` or `mix triage.replay --help`.

  Prints JSON only. Exits 0 for a complete replay, 2 for an incomplete replay,
  and 1 for invalid input or execution failure. No authentication, endpoints,
  database access, output files, or save/history switches are supported.
  Input files and their containing directories must be trusted and stable.
  See `Triage.Replay.CLI` for bounds and symlink policy.
  """
  use Mix.Task

  @impl Mix.Task
  def run(argv) do
    # Compilation loads code paths but does not start the application. Avoid
    # app.config too: production runtime config requires unrelated DB secrets.
    # Build diagnostics, if needed, belong to Mix rather than replay output.
    Mix.Task.run("compile", ["--quiet"])
    {code, json} = Triage.Replay.CLI.main(argv)
    IO.puts(json)

    if code != 0, do: System.halt(code)
    :ok
  end
end
