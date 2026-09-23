defmodule Mix.Tasks.Triage.Reporting.Issue do
  use Mix.Task

  @shortdoc "Issue one read-only reporting token from protected environment variables"

  @impl true
  def run([]) do
    Mix.Task.run("app.start")
    email = System.fetch_env!("TRIAGE_REPORTING_USER_EMAIL") |> String.trim() |> String.downcase()
    label = System.fetch_env!("TRIAGE_REPORTING_TOKEN_LABEL")
    expires_at = parse_time!(System.fetch_env!("TRIAGE_REPORTING_TOKEN_EXPIRES_AT"))
    scopes = parse_scopes!(System.fetch_env!("TRIAGE_REPORTING_TOKEN_SCOPES_JSON"))
    user = Triage.Repo.get_by!(Triage.Accounts.User, email: email)

    case Triage.Accounts.ReportingTokens.issue(user, %{
           label: label,
           expires_at: expires_at,
           scopes: scopes
         }) do
      {:ok, %{token: raw, record: record}} ->
        Mix.shell().info(
          "Reporting token #{record.id} issued. Copy this secret now; it is not stored in plaintext:\n#{raw}"
        )

      {:error, reason} ->
        Mix.raise("Reporting token issue failed: #{inspect(reason)}")
    end
  end

  def run(_args),
    do: Mix.raise("Use protected environment variables; this task accepts no arguments")

  defp parse_time!(text) do
    case DateTime.from_iso8601(text) do
      {:ok, time, 0} -> time
      _ -> Mix.raise("TRIAGE_REPORTING_TOKEN_EXPIRES_AT must be an ISO-8601 UTC timestamp")
    end
  end

  defp parse_scopes!(text) do
    case Jason.decode(text) do
      {:ok, "all"} ->
        :all

      {:ok, values} when is_list(values) ->
        values

      _ ->
        Mix.raise(
          "TRIAGE_REPORTING_TOKEN_SCOPES_JSON must be \"all\" or an array of team/environment objects"
        )
    end
  end
end
