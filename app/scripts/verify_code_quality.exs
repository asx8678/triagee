# Focused, database-free regression runner. Run from app/:
# MIX_ENV=test mise x -- mix run --no-start scripts/verify_code_quality.exs
# Kept for focused modules; the normal DB-free command is now:
# TRIAGE_SKIP_DB_SETUP=1 mise x -- mix test --exclude db
if Mix.env() != :test, do: raise("run with MIX_ENV=test")

supervisor = Triage.Test.DBFree.start!()

ExUnit.start(autorun: false)

files =
  Path.wildcard("test/triage/collection/*_test.exs") ++
    [
      "test/triage/http_test.exs",
      "test/triage/inventory/schema_test.exs",
      "test/triage_web/filter_assigns_test.exs",
      "test/triage/lint_policy_test.exs",
      "test/triage/risk_test.exs",
      "test/triage/severity_test.exs",
      "test/triage/intel_client_test.exs",
      "test/triage/intel_config_test.exs",
      "test/triage/intel_transport_test.exs",
      "test/triage_web/ui_components_test.exs"
    ]

# Optional explicit modules allow rerunning only a failed check.
selected = if System.argv() == [], do: files, else: System.argv()
Enum.each(selected, &Code.require_file/1)
result = ExUnit.run()
Supervisor.stop(supervisor)
System.halt(if result.failures == 0, do: 0, else: 1)
