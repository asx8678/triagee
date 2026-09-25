defmodule Triage.Portable do
  @moduledoc "Commands for the standalone Burrito executable. PostgreSQL remains external."

  @usage """
  Usage: triage [start | migrate | account | secret | --version | --help]

    start       Run the authenticated web app in the foreground (default).
    migrate     Apply pending database migrations; never seed or reset data.
    account     Create one account from TRIAGE_ACCOUNT_EMAIL, _PASSWORD, _ROLE.
    secret      Generate a SECRET_KEY_BASE without connecting to the database.
    --version   Print the application version.
    --help      Show this help.

  start, migrate and account require DATABASE_URL and SECRET_KEY_BASE.
  The listener stays on loopback. Use a TLS reverse proxy for shared access.
  See the bundled README.md for setup, PostgreSQL and backup instructions.
  """

  def command([]), do: :start
  def command(["start"]), do: :start
  def command(["migrate"]), do: :migrate
  def command(["account"]), do: :account
  def command(["secret"]), do: :secret
  def command([arg]) when arg in ["--help", "-h", "help"], do: :help
  def command([arg]) when arg in ["--version", "version"], do: :version
  def command(_args), do: :invalid

  def run(:help) do
    IO.puts(@usage)
    0
  end

  def run(:version) do
    IO.puts("Triage #{Application.spec(:triage, :vsn)}")
    0
  end

  def run(:secret) do
    IO.puts(Base.encode64(:crypto.strong_rand_bytes(64)))
    0
  end

  def run(:invalid) do
    # Never echo arbitrary arguments: they may contain accidentally pasted secrets.
    IO.puts(:stderr, @usage)
    64
  end

  def run(command) when command in [:migrate, :account] do
    case command do
      :migrate ->
        :ok = Triage.Release.migrate()
        IO.puts("Migrations complete.")

      :account ->
        Triage.Accounts.bootstrap!()
        IO.puts("Account created.")
    end

    0
  rescue
    _error ->
      # Do not print exception structs/changesets containing supplied credentials.
      IO.puts(
        :stderr,
        "Command failed. Check database access, migrations and required account variables. Existing accounts are never overwritten."
      )

      1
  end
end
