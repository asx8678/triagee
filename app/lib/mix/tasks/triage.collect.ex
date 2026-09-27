defmodule Mix.Tasks.Triage.Collect do
  @shortdoc "Disabled: live collection is not approved"
  @moduledoc """
  Manual collection entry. Disabled until an owner supplies G01.

  `run/1` does not start the application, the database, or an HTTP client,
  and it does not ingest a report. Arguments are ignored so they cannot
  select an endpoint.
  """

  use Mix.Task

  @impl Mix.Task
  def run(args) do
    case execute(args) do
      {:error, :collection_disabled} ->
        Mix.shell().error("triage.collect is disabled; no collection or ingest was performed")

        exit({:shutdown, 1})
    end
  end

  @doc "Fail-closed decision used by tests. Does not ingest or open a transport."
  def execute(_args), do: Triage.Collection.Live.run()
end
