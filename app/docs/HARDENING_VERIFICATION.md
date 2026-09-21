# Shared-app hardening verification

## Implemented boundaries

- Scalar-only retired-route redirects, plus malformed list/map query regressions.
- Provisioned viewer/reviewer/admin accounts; no public signup/default password.
  PBKDF2-HMAC-SHA256 at 600,000 rounds, random salts, opaque hashed session tokens,
  eight-hour expiration, revocation/disconnect, login throttling, and server-side
  HTTP/LiveView checks. Roles are application-wide, not team tenancy.
- Authenticated workspace decisions ignore client actor fields and record verified
  user identity. Legacy trusted domain APIs remain explicitly self-declared and
  are not web entry points.
- Immutable durable Azure operations, single creation attempt, blocking uncertain
  outcomes, marker-based reconciliation, and explicit newer-evidence confirmation.
  Network requests execute outside source-table lock transactions. No test used
  real Azure credentials or established live Azure permission/connectivity.
- User-scoped database drafts retain original evidence/operation bindings.
  PubSub refreshes clean views and marks dirty ones stale without silent rebasing.
- SQL filtering, counts and pagination precede evidence hydration. At most 50 page
  CVEs plus explicit focused/inspector CVEs are hydrated. One CVE can still have
  substantial evidence; aggregates, OFFSET and timeline/history need load testing.
- Release migrations/readiness, systemd/TLS configuration examples, private atomic
  backups and restore-only-into-a-new-database safeguards.

## Coordinator evidence

All application DB verification used generated disposable databases. A dedicated
PostgreSQL cluster was also used for production-release/recovery rehearsal. No
operator inventory was migrated, overwritten or adopted.

- Full `mix precommit`: **1,147 passed**, with the two intentionally gated import
  concurrency tests skipped in this ordinary run.
- Separate owned-DB `concurrency` mode: **2 passed**.
- Affected UI/query regression run: **112 passed**.
- Strict compilation, formatting check, strict Credo and Dialyzer: passed.
- JavaScript hook/filter tests: **9 passed**.
- Owned-database and backup/restore shell safety probes: passed.
- Local production release: built and migrated; loopback-only listener, readiness
  200, anonymous login redirect, and public-host HTTPS redirect verified.
- Real PostgreSQL restore: source and restored inventory/history/accounts/drafts
  matched (9 images, 96 findings, 14 decisions, 1 account, 1 draft, 13 migrations).
  Restored account authorization and draft recovery were exercised.
- Final release probe: authenticated decision ignored a forged actor; database
  pagination worked under production repeatable-read isolation. A separate VM
  confirmed persisted evidence fingerprint and Fixed queue parity after restart.

Detailed local logs: `/tmp/triage-hardening.VqSBGq/`, notably
`precommit-final.log`, `concurrency-final.log`, `focused-ui.log`,
`dialyzer-final.log`, `release-final-build.log`, `production-behavior.log`, and
`restored-release.log`. These temporary files are not deployment artifacts.

Earlier failures were classified rather than ignored: legacy UI assertions run
through a **test-only** endpoint/router while production cutover tests retain the
actual authenticated redirect contract. Current manual-CVE/news/asset tests use
the production endpoint. No failing test was wholesale removed or disabled. Query
coverage tests compare SQL output with the original pure projection, including
exact evidence-hash bytes, expiry, Unicode, large IDs and scoped/global decisions.

## Not certified

Actual VPS deployment, public TLS/firewall/proxy behavior on that VPS, live Azure,
representative production-data migration/rollback, browser accessibility, and
production-scale performance remain operator acceptance steps. No VPS connection
details/access were supplied. Structural review tooling did not cover Elixir;
its zero findings are not approval. See `DEPLOYMENT.md` and the remaining gates
in `WORKSPACE.md`. A green suite is not a guarantee of security or absence of bugs.
