# Next implementation plan

Status: A+B IMPLEMENTED — fresh bounded integration + independent Astra verification PASS.
No staging/checkpoint commit performed. C–F remain gated and unimplemented here.
See [CURRENT_STATUS.md](CURRENT_STATUS.md) and [A_B_EXECUTION.md](A_B_EXECUTION.md)
for the current acceptance ledger, exact evidence, cleanup, and limits.

The roadmap below was prepared from the working tree and retained PR5–7/UI records;
its original findings and later-package descriptions are retained as planning context.

## 1. Goal and decision

Checkpoint the existing local review application, validate its historical import
against approved evidence, then introduce narrowly scoped live read-only access.
Shared deployment is a separate authentication/authorization project. Do not bundle
these into one PR or interpret this plan as permission to access credentials,
legacy databases, live endpoints, or deploy the application.

Recommended order: A (checkpoint) -> B (safe local baseline) -> C (historical
compatibility). D (live read-only collection) follows approved source access;
E (shared access) may proceed independently after B, but must finish before any
shared deployment. F (observation ingestion) requires its own contract after D.

## 2. Scope findings from code

- All `app/` is untracked in the root repository. HEAD is `dc48431`; subsequent
  Phoenix work is not recoverable from committed history yet.
- `app/lib/triage_web/router.ex` exposes findings, cases, activity, replay/history
  and import without authentication. Filters and import nonces are not authority.
- `app/config/runtime.exs` binds production HTTP to IPv6 all-interfaces. The
  documented loopback-only restriction is not a production startup guard.
- `app/lib/triage/collection.ex` permits Req transport only in test builds;
  `collection/config.ex` accepts literal HTTP 127.0.0.1 only and rejects HTTPS.
  Live collection is therefore a security-boundary implementation, not an env toggle.
- `collection/preview.ex` deliberately never builds a historical snapshot. Current
  observations cannot supply missing historical first/last-seen or lifecycle facts.
- Import v1 is strict and lossless within its supported schema; CLI allows
  5,000,000 bytes while `ImportFlow`/UI allows 1,000,000 bytes and depth 32.
  Larger approved input must use the documented CLI path or receive separately
  reviewed UI budget changes, not silent truncation.
- Legacy placements lack an explicit environment column; migration needs approved
  environment attribution. UNKNOWN/NEGLIGIBLE severity and extra metadata may not
  fit import v1. Do not coerce or discard them to obtain a successful import.
- Existing review/event actors are strings; shared identity must be server-derived
  while preserving immutable historical rows.
- README/roadmap/PR ledgers retain superseded verdicts. PR6's opening FAIL is
  superseded by its final bounded offline PASS, not by a live-source signoff.
- Historical evidence reports 473 tests passed/2 skipped before final UI fixes;
  latest bounded UI checks report 23 tests and 4 probes passed. Neither is a fresh
  full-tree result. Original historical baseline proof remains unavailable.

## 3. Work packages and acceptance ledger

### A — Source checkpoint and durable status (small)

Scope:
1. Inventory tracked/untracked files; distinguish source, generated assets,
   dependencies, crash dumps, credentials, local DBs and harness state.
2. Review ignore rules and sanitized source/configuration for accidental secrets.
   Do not inspect credential files or indiscriminately stage the repository.
3. Add a concise current-status document linking historical ledgers. Label old
   verdicts as superseded without deleting failures or claiming missing evidence.
4. Preserve approved, sanitized reproducible probes in versioned tests/scripts;
   keep sensitive dumps/screenshots outside Git. Record evidence availability,
   commands, revision/hash and exclusions; `/tmp` is not durable storage.
5. Prepare an explicit source-only staging list and checkpoint commit for approval.
   Do not include unrelated `.pi/` changes. No push or commit as part of planning.

Files: root/app ignore rules; status/docs; approved test/probe files; `app/` source.

Acceptance:
- [x] Intended app source, lockfile, migrations, tests and static source assets are
  covered by the reviewed prospective inventory; artifacts are excluded. This is
  checkpoint preparation only, not staged/committed coverage.
- [ ] Staged diff review remains pending: the approval and the commit are still not
  taken. **Partly superseded 2026-09-15:** a later approved execution did stage a
  source-only checkpoint (20 files, +697/−2622) and regenerated the inventory to
  `evidence/checkpoint/MANIFEST.sha256` (224 paths, re-verified 224/224 against the
  staged blobs), recorded by `scripts/checkpoint_inventory.sh` and
  [CHECKPOINT_REVIEW.md](CHECKPOINT_REVIEW.md). "Staging is prohibited in this
  execution" was a constraint on that execution, not a standing ban, and should not
  be read as one. Outstanding: the owner's decision on the staged diff, the commit
  itself, and the `architecture(3).md` decision.
- [x] One authoritative status links bounded latest verdicts and unresolved gaps.
- [x] Missing original-baseline proof stays explicitly unresolved; a new baseline
  is recorded as new, never described as recovery of the old one.

### B — Enforced local-only startup and reproducible verification (small–medium)

Scope:
1. Make unauthenticated startup loopback-only in dev and production configuration;
   reject a non-loopback bind while shared authenticated mode is unavailable.
   Define explicit port handling; do not occupy user ports 4000/4001 for tests.
2. Add runtime configuration/startup tests, including production configuration in
   an isolated subprocess/build and missing-secret failure behavior.
3. Add an owned-disposable-DB verification script or documented guarded procedure.
   Read task help first; confirm DB absent before creation, configured and actual
   `current_database()` equal the owned name before effects, then drop only that DB.
4. Run targeted tests and startup probes, then one full precommit on the candidate.
   Inspect its formatting/lockfile/asset side effects; do not call it a read-only check.
5. Run opt-in import concurrency tests only with their exact empty-owned-DB guard.
   Record separately from ordinary full-suite results.

Files: `app/config/{dev,test,runtime}.exs`, endpoint/startup checks if needed,
new config tests and verification scripts/docs. No inventory schema changes.

Acceptance:
- [x] Default unauthenticated runtime listens only on loopback; an explicit public
  bind fails closed. Assert actual listener addresses, not only config values.
- [x] Existing local navigation/import/replay behavior remains usable in the fresh
  bounded synthetic/local suite (no new browser or real-data signoff).
- [x] Fresh full candidate result and separately executed/skipped concurrency
  checks are recorded honestly; all owned processes/databases are cleaned up.
- [x] No shared/dev DB writes, migrations, resets or existing process interruption.

### C — Approved historical export compatibility (medium; externally gated)

Inputs required: data-owner-approved export or sanitized representative artifact,
source schema/version, collection provenance and environment mapping, retention
policy, permitted local storage and explicit permission for any read of legacy data.
The copied code is not authorization to open a live legacy database.

Scope:
1. Produce a field/identity/lifecycle mapping matrix from the approved artifact to
   `triage.snapshot` v1. Separate documented facts from unknowns and blockers.
2. Validate the existing parser and dry-run against that artifact in a disposable
   DB. If it already matches v1, do not build a converter.
3. If conversion is necessary, first approve a bounded offline exporter/converter
   contract. Use only the approved copy, never the active legacy DB; preserve
   timestamps and identities, require explicit environment, reject unsupported
   fields/severities and contradictory/ambiguous records with useful diagnostics.
   Choose implementation/dependency only after the actual input format is known.
4. Capture scrubbed representative regression fixtures without credentials or real
   sensitive identifiers. Record rejected records; never claim a partial export
   is a complete historical migration.
5. Exercise preview, explicit apply, repeated apply, stale metadata rejection and
   rollback against a disposable DB containing nonempty review history.

Files: `app/test/triage/import_test.exs`, import-flow/UI tests and fixtures,
compatibility report; optional new converter module/task/tests after approval.
Keep Import/Inventory/Cases unchanged unless a concrete incompatibility justifies
an explicitly reviewed schema/contract extension.

Acceptance:
- [ ] Every source field has a preserve/reject/not-applicable decision with reason.
- [ ] No invented first_seen/last_seen/resolution events or severity downgrades.
- [ ] Preview changes zero rows; apply touches only expected inventory/events;
  repeated apply is a no-op; case/snapshot/review/audit history hashes are unchanged.
- [ ] Same-ID metadata staleness and late transactional failure are tested.
- [ ] UI/CLI size differences and unsupported data have actionable documented paths.
- [ ] Data owner approves reconciliation; real user-DB apply requires a separate
  backup/restore rehearsal and explicit approval. Compatibility tests do not apply it.

### D — Explicit manual live read-only collection (large; security review required)

Preconditions: approved exact endpoint/environment/owners, read-only access method,
credential delivery/rotation policy, allowed request budget and pilot permission.
Confirm legacy behavior against approved current API documentation/fixtures:
Grype detail queries, rotating IDs, full-snapshot crawl and proxy 302 auth failures.

Scope:
1. Design a separate explicitly enabled live entry/config/transport boundary while
   preserving the default offline API and its test-only guarantees. Proposed names
   and runtime keys must be frozen in a dedicated contract before implementation.
2. Use Req, TLS verification and an exact approved endpoint policy. Reject arbitrary
   URLs, URL credentials and redirects. Define trusted DNS/proxy/egress policy for
   the actual infrastructure; do not add blanket TLS or private-network bypasses.
3. Proxy mode accepts exactly one approved cookie or bearer credential from a
   server-side secret source, never CLI values/forms/uploads/history. Initially
   exclude unauthenticated direct mode unless separately approved. Source credentials
   are not web-user sessions and must never be forwarded from browser requests.
4. Enforce concurrency <= 6 for the initial pilot, run/request/response/text/depth
   budgets, terminal 3xx/401/403/GraphQL failures, bounded transient retries,
   inflight cancellation and worker cleanup. Preserve existing normalization parity.
5. Add a manual CLI returning safe counts/completeness and controlled exit codes,
   not raw credentials/source dumps. No Repo/Endpoint startup, writes, UI button,
   scheduler, raw snapshot persistence or reuse of synthetic Runs receipts.
6. Test fake HTTP/TLS and secret-canary failures first. Only after explicit approval,
   perform one bounded real read-only pilot and record sanitized reconciliation.

Files: collection entry/config/transport/client/errors and dedicated live tests;
new Mix task/CLI; sanitized configuration reference. Review blast radius before edits.

Acceptance:
- [ ] Existing offline/default paths still make zero external requests in dev/prod.
- [ ] Missing/ambiguous credentials and unauthorized endpoints fail before network.
- [ ] No redirects or credential leakage through inspect/errors/logs/telemetry/CLI;
  forged config/transport values fail safely, including direct public helper calls.
- [ ] Deadline/cancellation/request/aggregate-byte limits hold with stalled servers.
- [ ] Genuine open/suppressed query fixtures preserve Normalize/Replay parity;
  incomplete or conflicting results cannot claim completeness/actionability.
- [ ] Direct pilot has no inventory/history writes and no source mutation operations.

### E — Shared SSO, authorization and deployment (large; independent contract)

Decisions required: identity provider/tenant, direct OIDC vs trusted proxy, session
expiry/revocation, team/environment entitlements, overlapping-owner visibility,
role matrix and deployment/TLS topology. Do not assume source oauth2-proxy is the
correct web authentication integration.

Proposed roles for approval: scoped reader; scoped reviewer; import operator;
access administrator. Import authorization must cover every affected scope and
must not permit scope reassignment to escape checks. Replay receipts currently
have no user/team ownership: decide isolation before sharing their history.

Scope:
- Add identity/session/membership persistence with additive migrations as needed.
- Enforce authorization on HTTP requests, LiveView mount/navigation/events and
  context read/write boundaries; URL filters and hidden controls never authorize.
- Scope all lists, detail lookups, filter options, activity and history to avoid
  cross-team metadata leakage. Derive audit actors from verified server identity;
  preserve old immutable actor strings without retroactive identity claims.
- Handle logout/revocation of active LiveViews and define audited non-web operator
  permissions. Authenticate/authorize imports, review writes and replay saves.
- Add TLS/session/cookie/origin/proxy controls, least-privilege DB runtime access,
  migrations/backup/restore/release runbooks and a fail-closed deployment gate.

Acceptance:
- [ ] Permission matrix tests cover every route/context/action, cross-team IDs,
  malformed events, scope changes, role revocation and active/reconnected sockets.
- [ ] Forged actor, membership, proxy headers and import scope cannot grant access.
- [ ] Migration and restore rehearsals preserve existing immutable review history.
- [ ] Shared bind/deployment is enabled only with configured verified auth; local
  mode cannot silently become a shared unauthenticated service.
- [ ] Browser sign-in/out/expiry and authorized/denied workflows pass in an owned
  environment; dependency and security review are complete before deployment.

### F — Separate future scope: observations and automation (not authorized here)

A live read-only report does not populate Findings. If that is the desired product
outcome, write a separate observation-ingestion contract after D: collection-run
provenance, measured vs historical times, atomic inventory reconciliation,
partial-scan behavior, no absence-implies-resolution, idempotency, staleness and
human-history preservation. Expect schema work; do not call `Preview.to_snapshot`
or fabricate v1 history to bypass this design.

Only after that contract: scheduling/Oban and operational retries, public enrichment,
assignments/notifications, AI proposals, upstream exception activation and automated
remediation. Each needs separate permissions and acceptance; none belongs in A–E.

## 4. Execution rules and handoff

- Freeze scope/public APIs/config entries per package, trace callers, review impact,
  implement end to end, then mechanically confirm registrations and call paths.
- Keep an acceptance ledger with commands, exit codes, fresh vs inherited evidence,
  source revision/hash and unresolved failures. A build alone is not completion.
- Use smallest affected tests plus direct adversarial probes; one full precommit
  at integration for cross-cutting changes. Do not rerun unchanged passing suites
  to avoid inspecting a failure. Browser-check user-visible workflow changes.
- Independent work may cover docs/fixtures after ownership is assigned; serialize
  integration and database checks. No parallel writers to shared config/backend.
- Preserve existing tests/history; new migrations must be additive and generated
  with Mix. Do not modify historical migrations to make populated databases fit.
- Rollback per package: retain baseline commit, default-disable live access, preserve
  receipts/history; rehearse data backup/restore before any approved real apply.
  Never use destructive migration rollback as an assumed production recovery plan.

## 5. Immediate handoff / approval questions

Start with A and B. C can perform contract mapping with sanitized fixtures, but its
real compatibility verdict stays blocked until the approved export is supplied.

Before D/E implementation, confirm:
1. Is the next milestone a local operator tool or a shared team service?
2. Who can approve/provide a historical export and its environment/provenance map?
3. Which exact live endpoint, auth mode, owner scope and read budget are approved?
4. Which IdP/tenant/team entitlement source and role policy govern shared access?
5. Must the next milestone populate Findings from live measurements? If yes, F's
   observation design is required; D alone is deliberately read-only diagnostics.

Sizing is relative, not a delivery-date promise. A/B are immediately actionable;
C/D/E estimates depend on the external contracts above. No tests, app startup,
credential reads, live calls, DB effects, commits or deployments were performed
while preparing this plan.

### Decisions taken on the owner's behalf (2026-09-15)

The owner delegated the remaining calls. Taken and recorded in
[CURRENT_STATUS.md](CURRENT_STATUS.md) → "Decisions taken on the owner's behalf":
no commit and no push (the reviewed unit worth committing is one commit over the
whole current tree, which is green under `mix ci`), no exposure write path, no new
queue filters — the domain exposes saved scope plus the keyset cursor and nothing
else, so a new filter would be a new query — and the three cross-links the data
actually supports (case → advisory under the saved scope, queue row → advisory under
the queue filter, advisory → scoped inventory and per affected package).

Still owner-only, because each needs a fact or an approval that does not exist
locally: questions 1–5 above, the `architecture(3).md` decision, and the commit
itself over the verified index and worktree.
