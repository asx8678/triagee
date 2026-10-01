# Triage

The current application is a local Phoenix LiveView/PostgreSQL vulnerability
review workspace. Start with [app/README.md](app/README.md) for setup, workflows,
configuration and quality checks.

## Documentation

- [Going live with real data](app/docs/GO_LIVE.md)
- [Local runtime and trust boundary](app/LOCAL_RUNTIME.md)
- [Isolated database verification](app/OWNED_DB_VERIFICATION.md)
- [Public CVE reference data](app/REAL_CVES.md)
- [Standalone Kubernetes deployment](app/docs/KUBERNETES.md)

Historical design inputs (the original architecture, implementation plans and
bundles, design baselines and the legacy collector) have been removed. They remain
in Git history; the tag `archive/pre-cleanup` marks the last commit containing
them. Completed execution logs and old status snapshots were removed earlier. Historical test results do not certify the
current application. Keep ongoing operational guidance with the application.
