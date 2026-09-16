defmodule Triage.Test.DBFree do
  @moduledoc "Shared test-only bootstrap for DB-free Mix tests and the focused regression runner."

  def start! do
    if Process.whereis(Triage.Repo), do: raise("DB-free tests must not start Triage.Repo")

    for app <- [:req, :bandit, :phoenix_live_view] do
      {:ok, _started} = Application.ensure_all_started(app)
    end

    {:ok, supervisor} =
      Supervisor.start_link(
        [{Phoenix.PubSub, name: Triage.PubSub}, {TriageWeb.Endpoint, server: false}],
        strategy: :one_for_one
      )

    supervisor
  end
end
