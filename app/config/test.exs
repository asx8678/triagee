import Config

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
# The owned-database guard (scripts/verify_owned_db.sh) may point tests at an
# owned, disposable PostgreSQL cluster on a non-default port. The override is
# honored ONLY alongside the guard's generated `_ab_` partition and only for a
# bounded decimal port; anything else fails closed instead of connecting
# somewhere unexpected. Dev/prod configuration never reads this variable.
owned_db_port =
  case {System.get_env("MIX_TEST_PARTITION"), System.get_env("TRIAGE_OWNED_DB_PORT")} do
    {_partition, nil} ->
      5432

    {partition, text} when is_binary(partition) and is_binary(text) ->
      if not Regex.match?(~r/^_ab_[A-Za-z0-9_]+$/, partition) do
        raise "TRIAGE_OWNED_DB_PORT is honored only with the guarded _ab_ test partition"
      else
        case Integer.parse(text) do
          {port, ""} when port >= 1024 and port <= 65_535 -> port
          _ -> raise "TRIAGE_OWNED_DB_PORT must be decimal 1024..65535"
        end
      end

    {nil, _text} ->
      raise "TRIAGE_OWNED_DB_PORT is honored only with the guarded _ab_ test partition"
  end

config :triage, Triage.Repo,
  # Local PostgreSQL 18 (Homebrew) trusts the local `postgres` superuser; no password.
  username: "postgres",
  hostname: "localhost",
  database: "triage_test#{System.get_env("MIX_TEST_PARTITION")}",
  port: owned_db_port,
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# The only environment allowed to compile in the network-capable loopback
# transport. `Triage.Collection.Loopback` reads this with `compile_env/3`;
# all gate consumers read its compiled value. Other environments disable it.
config :triage, :collection, loopback_transport: true

# Tests do not run a server by default. runtime.exs independently enforces this
# loopback address and uses port 4002 unless PORT is explicitly supplied.
config :triage, TriageWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "nKl8B9DVUkvFi9yO2qCpNhAg5X4ElbKo8i8qtgeJQKdwH211U+LvZ/wccRakWira",
  server: false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
