ExUnit.start()

if System.get_env("TRIAGE_SKIP_DB_SETUP") in ["1", "true"] do
  # Defense in depth: this mode never executes DB tests, even with --include db.
  ExUnit.configure(exclude: [:db], include: [])
  supervisor = Triage.Test.DBFree.start!()
  ExUnit.after_suite(fn _result -> Supervisor.stop(supervisor) end)
else
  Ecto.Adapters.SQL.Sandbox.mode(Triage.Repo, :manual)
end
