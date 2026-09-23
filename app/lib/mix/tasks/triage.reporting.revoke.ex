defmodule Mix.Tasks.Triage.Reporting.Revoke do
  use Mix.Task

  @shortdoc "Revoke one read-only reporting token by protected environment variable"

  @impl true
  def run([]) do
    Mix.Task.run("app.start")

    id =
      case Integer.parse(System.fetch_env!("TRIAGE_REPORTING_TOKEN_ID")) do
        {value, ""} when value > 0 -> value
        _ -> Mix.raise("TRIAGE_REPORTING_TOKEN_ID must be a positive integer")
      end

    case Triage.Accounts.ReportingTokens.revoke(id) do
      :ok -> Mix.shell().info("Reporting token #{id} revoked")
      {:error, :not_found} -> Mix.raise("Active reporting token not found")
    end
  end

  def run(_args), do: Mix.raise("Use TRIAGE_REPORTING_TOKEN_ID; this task accepts no arguments")
end
