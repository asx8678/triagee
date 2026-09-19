# Coordinator-only companion to verify_owned_db.sh workspace_browser.
# No production route can enable this data. Never seeds an existing database.
expected = List.first(System.argv())
config = Triage.Repo.config()
unless Mix.env() == :test and is_binary(expected) and
         Regex.match?(~r/^triage_test_ab_[A-Za-z0-9_]+$/, expected) and
         config[:database] == expected and expected == "triage_test#{System.get_env("MIX_TEST_PARTITION")}" do
  raise "Owned test database required"
end
Application.put_env(:triage, Triage.Repo, Keyword.merge(config, pool: DBConnection.ConnectionPool, pool_size: 4))
endpoint = Application.fetch_env!(:triage, TriageWeb.Endpoint)
Application.put_env(:triage, TriageWeb.Endpoint, Keyword.merge(endpoint,
  server: true, http: [ip: {127, 0, 0, 1}, port: 0], check_origin: ["//localhost", "//127.0.0.1"]))
{:ok, _} = Application.ensure_all_started(:triage)
%{rows: [[^expected]]} = Triage.Repo.query!("SELECT current_database()")
if Triage.Repo.aggregate(Triage.Inventory.Finding, :count) != 0, do: raise("Refusing populated database")
image = Triage.Fixtures.image!("browser-workspace")
prod = Triage.Fixtures.placement!(image, "alpha", "prod")
staging = Triage.Fixtures.placement!(image, "alpha", "staging")
Triage.Fixtures.finding!(image, "CVE-2099-1001", severity: "CRITICAL",
  description: "Synthetic browser verification record. Production and staging are independent targets. " <> String.duplicate("Long evidence remains inside its scroll body. ", 30), fix: "2.0.0")
Triage.Fixtures.finding!(image, "CVE-2099-1002", severity: "HIGH", description: "Synthetic second advisory")
Triage.Exposure.record(prod.id, "internet_exposed", "synthetic-browser-probe", DateTime.utc_now())
{:ok, {{127, 0, 0, 1}, port}} = TriageWeb.Endpoint.server_info(:http)
IO.puts("WORKSPACE_BROWSER_READY url=http://127.0.0.1:#{port} pid=#{System.pid()} prod=#{prod.id} staging=#{staging.id}")
# Bounded owned probe; normal exit releases database sessions for wrapper cleanup.
receive do
  :stop -> :ok
 after
  600_000 -> :ok
end
