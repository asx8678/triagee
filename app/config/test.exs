import Config

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :triage, Triage.Repo,
  # Local PostgreSQL 18 (Homebrew) trusts the local `postgres` superuser; no password.
  username: "postgres",
  hostname: "localhost",
  database: "triage_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

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
