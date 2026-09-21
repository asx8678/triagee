defmodule Mix.Tasks.Triage.Accounts.Create do
  use Mix.Task
  @shortdoc "Provision an account from TRIAGE_ACCOUNT_EMAIL/PASSWORD/ROLE environment variables"
  @moduledoc """
  No public signup and no default credentials. Set TRIAGE_ACCOUNT_EMAIL,
  TRIAGE_ACCOUNT_PASSWORD (12–1024 bytes) and TRIAGE_ACCOUNT_ROLE
  (viewer, reviewer, or admin), then run `mix triage.accounts.create`.
  In a release: `bin/triage eval 'Triage.Accounts.bootstrap!()'`.
  Passwords must not be passed as CLI arguments. Existing accounts are never overwritten.
  """
  def run([]) do
    Mix.Task.run("app.config")
    user = Triage.Accounts.bootstrap!()
    Mix.shell().info("Provisioned #{user.email} (#{user.role})")
  end

  def run(_), do: Mix.raise("Use environment variables; this command accepts no arguments")
end
