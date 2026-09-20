# Triage

The current application is a local Phoenix LiveView/PostgreSQL vulnerability
review workspace. Start with [app/README.md](app/README.md) for setup, workflows,
configuration and quality checks.

## Documentation

- [Local runtime and trust boundary](app/LOCAL_RUNTIME.md)
- [Isolated database verification](app/OWNED_DB_VERIFICATION.md)
- [Public CVE reference data](app/REAL_CVES.md)
- [Legacy collector reference](tmp/cve-collector/README.md) and
  [integration notes](tmp/cve-collector/INTEGRATION_NOTES.md)
- [Original architecture input](architecture%283%29.md): historical product and
  safety requirements, **not** a description of the current runtime. The shipped
  application uses Phoenix, not the original proposed Go stack.

Completed execution logs, old status snapshots and superseded plans have been
removed; their history remains in Git. Historical test results do not certify the
current application. Keep ongoing operational guidance with the application.
