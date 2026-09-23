defmodule Mix.Tasks.Triage.Reporting.Rotate do
  use Mix.Task

  @shortdoc "Rotate one read-only reporting token from protected environment variables"

  @impl true
  def run([]) do
    Mix.Task.run("app.start")
    id = positive_id!(System.fetch_env!("TRIAGE_REPORTING_TOKEN_ID"))
    expires_at = parse_time!(System.fetch_env!("TRIAGE_REPORTING_TOKEN_EXPIRES_AT"))

    case Triage.Accounts.ReportingTokens.rotate(id, expires_at) do
      {:ok, %{token: raw, record: record}} ->
        Mix.shell().info(
          "Reporting token #{id} revoked and replacement #{record.id} issued. " <>
            "Copy this secret now; it is not stored in plaintext:\n#{raw}"
        )

      {:error, :not_found} ->
        Mix.raise("Active reporting token not found")

      {:error, reason} ->
        Mix.raise("Reporting token rotation failed: #{inspect(reason)}")
    end
  end

  def run(_args),
    do: Mix.raise("Use protected environment variables; this task accepts no arguments")

  defp positive_id!(text) do
    case Integer.parse(text) do
      {value, ""} when value > 0 -> value
      _ -> Mix.raise("TRIAGE_REPORTING_TOKEN_ID must be a positive integer")
    end
  end

  defp parse_time!(text) do
    case DateTime.from_iso8601(text) do
      {:ok, time, 0} -> time
      _ -> Mix.raise("TRIAGE_REPORTING_TOKEN_EXPIRES_AT must be an ISO-8601 UTC timestamp")
    end
  end
end
