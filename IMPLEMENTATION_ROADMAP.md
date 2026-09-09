# CVE Triage — practical implementation roadmap

**Status: proposal, not an implemented application.** This is a source-backed companion to [the original architecture plan](./architecture%283%29.md). It proposes changes to that plan; it does not silently supersede an approved language or security decision.

Reviewed `/Users/adam2/projects/cve-collector` and all of `architecture(3).md`. Four independent `zro/glm-5.3` reviewers covered architecture/delivery, web workflows, data/integration, and security/operations; their findings were reconciled against source code. This was static inspection only: no application/test execution, credential-file access, live database inspection, production API calls, or model calls using CVE database contents. Source citations below establish implemented behavior, not current deployment health or passing tests.

## 1. Recommendation in one paragraph

**Build a usable CVE evidence-and-review web application before building an autonomous remediation system.** Use the existing TypeScript collector and web UI as the behavioral baseline, preserve their hard-won integration safeguards, and add durable cases, evidence snapshots, human decisions, notes, and history. Keep the old app operational while building an isolated successor in `triage`. Start locally with SQLite and the existing HTML/CSS/JavaScript approach. Add authenticated team access, optional AI proposal ingestion, and finally narrowly constrained remediation in separate, demonstrably safe steps. Do not make Go, React, PostgreSQL, AKS, Azure Boards, or a model service prerequisites for the first useful screen.

If Go is an organizational requirement, keep the same milestones but use the Go alternative in section 5. Do not rewrite the GraphQL collector and replace the entire frontend in the same milestone.

## 2. What changes in the original plan

| Original plan | Adjustment proposed for this user's requirement |
|---|---|
| Sections 1 and 12 prefer existing review tools and no custom frontend. | A web management interface is now a first-class deliverable. Reuse the existing UI behavior instead of introducing Azure Boards synchronization first. |
| Section 2.2 says the old application has not been inspected. | Source has now been inspected. Authentication in the real environment, freshness guarantees, and remediation capabilities are still unverified. |
| Go supersedes TypeScript. | Recommend TypeScript for the first release because the working integration, UI, and test corpus already exist. Confirm this change with the user; retain a Go migration option. |
| Short-lived pipeline jobs are the only initial runtime. | An interactive web UI needs an available HTTP service. Start with one local process; shared use needs one approved private host. Pipelines remain suitable for later isolated analysis/build/updater jobs. |
| Existing storage or Blob records for a serialized pipeline experiment. | SQLite is the simplest local application store. Blob is not a good primary query/review store for this UI. PostgreSQL is an explicit later operational decision, not already selected in the original plan. |
| Proposed changed-finding/cursor interfaces. | The inspected adapter is snapshot-based: owners, image inventories, then image details. No source pagination or trustworthy change cursor is implemented. Do not invent one. |
| A part-time two-week experiment includes collection, AI, Renovate, verification, and evaluation. | Aim first for a useful triage-only milestone. Do not promise the full automation scope plus a web UI in that window. Measure actual effort and resolve external prerequisites before estimating remediation. |

**Keep the original plan's safety controls:** unknown is not safe; internal-only does not prove non-applicability; AI proposes rather than approves; exception approval differs from activation; a merged PR is not a remediated deployment; incomplete scans cannot prove a fix.

## 3. Existing app: preserve, extend, or defer

Paths below are under `/Users/adam2/projects/cve-collector` unless otherwise stated.

| Capability | Evidence in existing code | Successor treatment |
|---|---|---|
| Overview, CVEs, Libraries, Images, Whitelist tabs | `public/index.html:30-60`, `src/server.ts:491-515` | Preserve the familiar navigation and drill-downs. Add a Cases/review queue rather than discard the existing views. |
| Owner, severity, search, reported-fix coverage, regression and sorting controls | `public/index.html:78-108`, `src/cve-query.ts`, `public/app.js` | Preserve semantics, stable pagination and URL-restorable filters. Owner filtering is not authorization. |
| Per-CVE/image/library details and local lifecycle history | `src/server.ts:536-549`, `src/db.ts:46-88` | Preserve first/last seen, resolved and reopened history. Do not relabel these as verified runtime fixes. |
| CSV/JSON inventory exports and focused triage exports | `src/server.ts:505-515`, `src/triage-http.ts:87-116`, `src/stream.ts` | Preserve safe streaming. Clearly distinguish current table, selected CVEs, and all-owner-scope export semantics. |
| Collection with progress and cancellation | `src/server.ts:517-534`, `src/collect.ts` | Preserve UI behavior; replace process-local-only job status with durable jobs/restart reconciliation when collection is added to the successor. |
| Exposure CSV import; public descriptions and intelligence | `src/triage-http.ts:39-85`, `src/exposure.ts`, `src/enrichment.ts`, `src/descriptions.ts` | Keep unknown/stale/error states visible. Manually supplied exposure does not establish complete workload inventory. |
| Kiro bundle export, not automated analysis | `src/kiro-bundle.ts`, `src/triage-instructions.ts`, `src/triage-http.ts:87-101` | Keep the manual export path. Add validated proposal import later to close the loop before considering headless execution. |
| Whitelist audit and cleanup handoff | `src/whitelist.ts`, `src/whitelist-cleanup.ts`, `src/server.ts:482-491` | Read-only by default. The existing cleanup POST refreshes collection; it does not remove whitelist entries. Make this explicit in labels. |
| Browser safety and accessibility | `public/app.js:31-36`, `public/index.html`, `src/csv.ts`, `src/server.ts:449-459` | Preserve text-safe rendering, keyboard navigation, focus behavior and CSV formula escaping. Extend request protections, not replace them with a frontend framework. |

**The biggest missing product capability:** the current Kiro workflow ends at an exported file. The inspected DB schema and HTTP routes do not provide persisted assessment proposals and human review outcomes. That gap is more valuable to fix first than automating dependency upgrades.

### Integration facts that must become contract tests

| Confirmed by code | Implementation consequence |
|---|---|
| Images use immutable digest keys; API IDs rotate (`src/db.ts:4-11`). | Never migrate to API-ID-based history. Keep API IDs only as source correlation. |
| Current finding key is digest + CVE + package name + version (`src/db.ts:46-67`); dedupe uses the same package tuple within an image (`src/collect.ts:286-308`). | Preserve a legacy identity map. The existing key cannot represent every possible distinct package occurrence; do not claim lost distinctions can be reconstructed. |
| `packagePath` is mapped to `purl` in `src/collect.ts:388-389`. | Do not assume it is a filesystem path. Adding purl to a primary key is not, by itself, an occurrence-identity migration. Confirm actual semantics before changing keys. |
| Owner-scoped image queries do not populate findings; image-detail queries require an engine (`src/queries.ts:29-89`). | Preserve the two-phase crawl and configured, validated engine. No CVE-first vendor endpoint is established. |
| Suppressed findings live in a separate array and contribute to claimed counts (`src/collect.ts:262-307`). | Store and display suppression separately, never as proof of safety. Compare counts using both arrays. |
| Zero returned findings with nonzero claimed counts is a failure; other count drift is a warning (`src/collect.ts:268-284`). | Preserve those distinctions for parity. Flag drift as a quality limitation for new decision/verification policy; warnings do not become proof of complete evidence. |
| `lastClusterScan` advances frequently; a wall-clock interval guards recrawls (`src/collect.ts:101-113`). | Use bounded snapshot replay and run identities. Do not treat this timestamp as a reliable source cursor. |
| Only successful, unfiltered, unlimited **full-scope** runs resolve findings (`src/collect.ts:312-324`). | Partial, severity-filtered, failed, and owner-only runs cannot globally resolve findings. Successful unfiltered owner-only runs may retire placements for the requested owners only. |
| Redirects, 401 and 403 are authentication failures (`src/graphql.ts:128-139`). | No redirect-following that silently turns a login page into collection data; stop doomed requests. |
| Writable `Store` construction runs schema setup/migrations (`src/db.ts:218-245`). | Never point the successor's writable store at the live legacy DB. Open an approved snapshot read-only for import. |
| `relatedArtifact` is queried (`src/queries.ts:81`) but is not a complete persisted source/build/workload graph in the inspected store. | Repository-to-manifest-to-build-to-digest provenance remains a blocker for automated fixes, not a relationship the model can supply. |

Important existing regression fixtures live in `test/fake-api.ts`, `test/collect.test.ts`, `test/db.test.ts`, `test/server.test.ts`, `test/triage-http.test.ts`, `test/cve-selection.test.ts`, and `test/whitelist-cleanup.test.ts`. These are source references; this planning pass did not execute them.

## 4. What the web interface should do

### Early navigation

- **Overview:** current findings, new/regressed findings, cases awaiting review, collection quality and age. Keep scanner counts and workflow counts separate.
- **CVE inventory:** retain existing owner/search/severity/fix/regression filters, pagination and image/library drill-downs.
- **Cases:** a work queue with applicability, priority, assigned reviewer, next action, workflow status and stale-evidence indicator. Saved views such as My open cases, New/regressed, and Expedited are useful follow-ups.
- **Case detail:** source facts and timestamps; affected package/artifact/deployment contexts; unknowns and contradictions; any AI proposal in a visually separate panel; reviewer decision/rationale; append-only timeline.
- **Exceptions:** existing whitelist audit first. Later show scoped proposals, expiry and external approval/activation references. Never rename a candidate to “safe to whitelist.”
- **Runs/settings:** collection/import/enrichment jobs, progress, failures, last success and effective scope. Configure secret references server-side, never show or accept source tokens in ordinary browser forms.

### Management actions and their boundaries

| Browser action | What it changes |
|---|---|
| Assign a case, add a note, record a next action | Local workflow records, with an audit event. |
| Record applicability/review outcome | A version-bound human review in this app. It does **not** change the scanner's authoritative disposition. |
| Import AI output | An untrusted proposal, after strict validation. Never a human approval record. |
| Request an exception | A scoped proposal for authorized review. No platform suppression write. |
| Link a fix PR or source-system decision | A correlation record, not proof of verification or deployment. |
| Mark “source no longer reports finding” | Collector observation only, under completeness rules. Distinct from runtime-verified remediation. |

Use ordinary UI language: “Reported fix available,” “Evidence incomplete,” “Awaiting review,” “Proposal only,” and “Merged, deployment not verified.” Do not hide uncertainty behind green badges.

### Five browser acceptance journeys

1. Filter by owner and CVE, navigate pages and details, and return to the same filter state. The selected owner/floor scope is consistent across detail and export; selected CVEs across pages never silently become all CVEs.
2. Open a case, inspect evidence, add rationale and a human review, refresh, restart the app, and see the same review/history. A different deployment context does not inherit the decision.
3. Two tabs review the same revision. The second stale submission receives a conflict and offers a refresh; it does not overwrite the first review. Refreshed evidence marks the old review as needing revalidation without erasing history.
4. Import a proposal containing a nonexistent evidence ID, fabricated approval, invalid enum, duplicate JSON key or stale snapshot. Reject/stage as blocked with a useful error and no authoritative state change. A valid proposal still requires human review.
5. Start collection, observe progress, cancel or restart during work, and retain the last good evidence. The job becomes cancelled/interrupted/reconciled, not successful; retry does not duplicate findings or globally resolve them.

## 5. Architecture: deliberately small

### Recommended default: TypeScript modular monolith

- Node supported by the existing app's `package.json` (currently Node >=24), TypeScript and an independently pinned successor lockfile.
- SQLite on one host for the local/single-instance pilot. Keep backups, schema migrations, explicit transactions and bounded writes.
- Reuse the current HTML/CSS/JavaScript behavior; split code by feature as it changes. Do not introduce React/Vite solely to obtain tables, forms and a drawer. React is an option if later UI complexity and team preference justify it.
- Thin HTTP and CLI entrypoints call the same application services; source adapters and persistence sit behind narrow interfaces.
- One durable job queue/table with a single collector worker initially. Polling is sufficient for progress; add SSE only if it materially improves the UX.

```text
Browser
  -> local HTTP server (later TLS + authenticated proxy)
      -> case/review/query application services
          -> local workflow + evidence store (SQLite)
      -> enqueue job; return 202 + job ID
          -> bounded worker -> read-only security adapter

Later: isolated analyst / updater / CI jobs
  -> authenticated, version-bound result ingestion
  -> proposals or verification evidence, never invented human decisions
```

Suggested boundaries, **not a request to move every existing file at once**:

```text
src/
  domain/        evidence, case identity, reviews, policy, validators
  application/   collect/import/review/assess use cases
  adapters/      legacy-snapshot, security GraphQL, intelligence, later Kiro
  persistence/   SQLite queries, migrations, transactions, job claims
  web/           thin handlers, auth/authorization, serializers
  cli/           thin local/batch commands
public/          feature-oriented views and assets
migrations/
test/            unit, API, contract and browser tests
testdata/        synthetic/sanitized fixtures only
```

Do not import application source from the sibling repository at runtime. Establish a reviewed, code-only baseline in `triage`; leave `cve-collector` untouched. Copy only explicitly reviewed source/assets/tests and dependency metadata as needed, never the whole directory: it contains credentials, live DBs, reports, `node_modules`, and local agent configuration.

**Runtime is not just folders.** Separate modules do not isolate credentials. The web process must not hand source credentials to browsers or later model/updater code. Use separate process/job identities and staged evidence when those trust boundaries are introduced.

**Pipeline compatibility:** do not mount a SQLite file over a network share or expect ephemeral Azure agents to share the web host's local file. A pipeline can emit an immutable, scoped artifact for authenticated ingestion. If remote writers, HA or multiple app replicas become real requirements, select an existing PostgreSQL service and test a deliberate migration; do not pretend the storage switch is free.

### If Go is a firm constraint

Use a Go HTTP service with `html/template` and optionally locally served HTMX, plus SQLite for the first local slice. Keep the existing collector as a temporary producer of approved snapshots; implement Go adapter parity against exported, sanitized contract fixtures before allowing live collection. Replace one adapter at a time. Keep the same domain/review invariants and milestones below. A Go binary does not replace the separate runtimes needed by Kiro, Renovate and builds.

## 6. Data model: a CVE is not a review case

A CVE can affect several packages, images, owners and deployments. The UI may group by CVE; an approval must stay bound to the actual affected scope.

Proposed logical records (add only those needed by the current milestone):

| Record | Purpose |
|---|---|
| Source finding / package occurrence / artifact | Source-specific facts, aliases, digest/platform and known package identity; preserve legacy keys and unresolved identity gaps. |
| Deployment context | Workload/environment/inventory scope where actually known; explicit unknowns otherwise. Owner or namespace alone is not invented workload evidence. |
| Case | Finding/occurrence plus artifact and deployment scope, assignment and revision. An unknown-context case cannot authorize a global disposition. |
| Evidence snapshot | Immutable, versioned inputs, source observations/retrieval times, coverage, warnings, collector version and content hash. |
| Assessment proposal | Snapshot reference, proposed applicability/priority/action, model/prompt version where applicable, raw result and separate validation result. |
| Human review | Authenticated actor (or explicit local-operator label in the offline demo), time, reviewed case/proposal/snapshot revision, outcome, rationale and optional external decision reference. |
| Note / audit event | Append-only who/what/when, changed versions and correlation IDs. Corrections append; they do not erase old decisions. |
| Job / collection run | Type/scope, requestor, queued/running/completed/failed/cancelled/interrupted state, attempt/claim, progress and completeness metadata. |
| Later remediation / verification / exception | Separate scoped paths linked to cases. Do not overload `case.status` to mean everything. |

Separate these dimensions:

- Applicability: `affected`, `not_affected_with_evidence`, `unknown`.
- Priority: `expedited_review`, `normal_review`, `insufficient_context`.
- Next action: investigation, dependency update, base-image update, rebuild/deploy, mitigation review, or exception proposal.
- Review outcome: pending, accepted, rejected, unsure; this rates/records the reviewed proposal or manual assessment, not external exception activation.
- Fix progress: planned, PR opened, verified, merged, runtime verified; also blocked/failed/expired/superseded.

Generate IDs with canonical structured serialization, not delimiter concatenation of unchecked strings. Keep stable case identity separate from changing evidence revisions. A content hash detects changes; it does not establish that its producer is trusted. Revalidate freshness independently of hash equality.

New human writes should require a case/evidence revision (`If-Match` or an equivalent expected-version field). Write the review, version transition and audit event atomically. Preserve rejected and superseded proposals for evaluation, subject to agreed access and retention rules.

### Proposed API surface (not currently registered endpoints)

- `GET /api/cases` and `GET /api/cases/:id`: paginated, authorized case queries.
- `GET /api/cases/:id/evidence` and `/history`: immutable evidence and timeline.
- `POST /api/cases/:id/reviews`: validated human outcome plus expected revision.
- `POST /api/cases/:id/notes`: audited local annotation.
- `PATCH /api/cases/:id/assignment`: optional follow-up, not needed for a single-user first demo.
- `POST /api/proposals/import`: bounded strict JSON, known IDs, snapshot binding, proposals only.
- `POST /api/jobs/collect`, `GET /api/jobs/:id`, `POST /api/jobs/:id/cancel`: later durable job lifecycle.

Retain legacy list/detail/export routes during the transition where practical. Endpoints enforce methods, body bounds, authorization, validation and CSRF protection; a frontend button is not a security boundary.

## 7. Small, controllable milestones

Each milestone has a user-visible demonstration and a stop gate. Split it into reviewable PRs; do not combine a collector rewrite, schema migration and frontend rewrite in one diff.

| Milestone | Deliverable | Acceptance / stop gate |
|---|---|---|
| **M0: baseline and decisions** | Confirm TypeScript vs required Go; local vs shared first; define one pilot owner/scope; establish safe code-only baseline and synthetic contract fixtures. | Baseline runs offline in its own directory/store when implemented; no sibling credentials/config/data copied. Document current behavior and known gaps. |
| **M1: usable local web review** | Familiar inventory + case detail, immutable evidence snapshot, manual review/rationale and timeline. No AI and no live API required. | Browser round-trip survives refresh and restart; same-CVE contexts stay distinct; stale write rejected; a review cannot change scanner status or whitelist. This is the first release worth showing. |
| **M2: safe historical import** | Approved legacy snapshot import with dry-run validation, identity mapping and reconciliation report. | Preserve image/finding/placement/lifecycle/run history and source metadata. Reimport is idempotent. Errors roll back; mismatch blocks cutover. Old app remains usable. |
| **M3: reliable refresh** | Reuse/extract the source adapter, add durable jobs/progress/cancel and freshness/completeness UI. | Offline fake-API tests prove wrong-engine, auth, sparse/duplicate data, scope and resolution safeguards; interrupted work is visible and safely replayed. Live validation only with approved read-only credentials and scope. |
| **M4: shared team pilot** | Approved SSO, roles, CSRF, trusted proxy boundary, audit attribution, persistent hosting and restore procedure. | Anonymous/unauthorized requests denied server-side; owner filter cannot bypass access rules; backups restore successfully; secrets remain outside web/client artifacts. No network exposure before this gate. |
| **M5: complete the AI handoff loop** | Export a snapshot-bound bundle; import validated Kiro output as a proposal; accept/reject/unsure and measure reviewer effort. | Unknown refs, injection attempts, malformed output and forged approval fields fail safely. Raw unsafe proposals counted even when blocked. Entire review workflow works with AI disabled. |
| **M6: optional automated assessment** | Pinned isolated Kiro adapter with no source/publisher credentials or privileged tools, bounded input/output/time/cost and kill switch. | Data-sharing approval and effective isolation tests pass. Timeout produces a visible abstention, not approval. Proceed only if automation improves the measured manual handoff. |
| **M7: one verified remediation path** | One approved repo/ecosystem/direct dependency: trusted fix resolution, constrained Renovate PR, protected CI/SBOM/scan verification, human merge and runtime reconciliation. | Real source/build/digest provenance and candidate scanning are prerequisites. Missing/partial/suppressed/wrong-artifact evidence is unverified, never success. No auto-merge or exception activation. |

**Do not gate M1 on M7.** A successful release can stop at M1-M4 and remain valuable. If the time budget is two part-time weeks, scope it to a demonstrated triage-only slice and measured follow-up, not the whole table.

### The first three PRs

1. **PR 1 — safe baseline and offline harness.** Establish the selected code-only successor baseline, independent dependency metadata, fixture-only config and disposable test DB. Preserve current list/detail/export behavior and capture collector contract fixtures. No new live connection or directory-wide copy. Run the existing applicable unit/API tests against fixtures when implementing; do not run live schema introspection or public smoke scripts as part of an offline check.
2. **PR 2 — one case with evidence and review persistence.** Add the minimal additive schema/domain service for a snapshot, case revision, manual review and audit event. Test migration, restart persistence, transaction rollback, repeat requests and stale-version conflict. Do not add model calls, assignments, PR creation or a general workflow engine.
3. **PR 3 — one complete browser review journey.** Add the Cases view/detail and review endpoint/form. Test owner-scoped navigation, keyboard access, safe third-party text, review persistence and conflicting tabs. Demonstrate the fixture-driven workflow end to end before adding live collection.

These PRs are scoped changes, not promises that each takes exactly a day. Re-estimate after PR 1. Move to M2 only after the offline demo is genuinely usable.

## 8. Migration and rollback without losing history

1. Leave `/Users/adam2/projects/cve-collector` unchanged and serving its existing role until parity is accepted. The successor gets a distinct store/config and disabled-by-default external connectors.
2. Use synthetic fixtures first. Before handling real inventory, obtain approval for its destination, access, retention and backup procedure.
3. Produce a consistent snapshot using an approved SQLite online-backup procedure, the existing backup facility under reviewed operating conditions, or a coordinated stopped-writer snapshot. **Do not copy only `cve.db` while WAL writes may be active.** `src/db.ts` implements a `VACUUM INTO` backup; do not invoke the old CLI blindly, because its writable Store path may run schema migrations.
4. Open only the resulting copy read-only. Validate schema version, integrity and required tables. Read into a new destination transaction; never migrate the old live DB in place.
5. Inventory and reconcile images, findings (including suppressed/resolved), placements (including retired), finding events, scan runs, deployment context, enrichment, descriptions and whitelist snapshot metadata. Preserve unavailable values as unknown; retain an import manifest with source snapshot hash/schema and counts.
6. Preserve `first_seen`, `last_seen`, `resolved_at`, `reopen_count` and historical run IDs through an explicit source-ID map. Replaying an import must not emit new appeared/reopened events or duplicate notes/reviews.
7. Do not manufacture source hashes, timestamps, reviewer identities, workload provenance or package occurrences that the old store never recorded. Keep legacy identity and any future richer occurrence key side by side until a tested mapping exists.
8. Compare per-owner/per-severity counts and selected CVE/image histories, not just one global total. Partial/floor-filtered legacy snapshots retain their coverage label. Absence from an import never globally resolves a finding.
9. Shadow the same approved snapshot/collection and compare outputs before switching the collection schedule. Avoid double-polling production unnecessarily; only one collector schedule owns an operational scope at cutover.
10. Rehearse restoring the new store. On rollback, disable successor collection/publication and reopen the untouched old UI for inventory; retain/export successor reviews for recovery because the old app cannot display those new records. Do not discard new human history during rollback.

## 9. Security and operating gates

### Before the first local demo

- Bind loopback only. Preserve same-origin checks; validate allowed Host/Origin values rather than trusting an arbitrary Host header. No wildcard CORS.
- Synthetic fixtures by default; connectors off. Bounded bodies, safe text rendering, safe CSV export, no arbitrary URL fetches or shell commands from requests.
- Explicit local-operator attribution is acceptable for an offline demo, but must not be presented as authenticated corporate approval.
- Audit local review changes, keep evidence/proposals separate, and reject stale revisions. The local process is a trust boundary, not a multi-tenant sandbox.

### Before sharing with a team

- Reuse approved Entra/OIDC authentication or the existing trusted oauth2-proxy pattern. Do not substitute one shared token for named reviewer identities.
- Server-enforced roles such as viewer, reviewer and operator. Decide whether owner scope is an authorization boundary; implement and test it if so. A dropdown does not grant or deny access.
- TLS, session-bound CSRF protection, secure cookie settings, explicit origin policy, and proxy-header trust only from the protected proxy path. Block direct access that can spoof identity headers.
- Dedicated read-only source identity and server-side secret references. Do not copy the old `.env` or developer PAT. Bound collection/import/export load and restrict inventory exports.
- Persistent disk, migration/backup/restore test, job interruption reconciliation, structured non-secret logs, source freshness indicators, retention and an operator stop control.
- One SQLite host/instance initially. Reassess storage for HA/remote writers rather than adding replicas against a shared SQLite file.

### Before AI or external writes

- Confirm approval for sending internal inventory to a model. Exporting a bundle is also data sharing; manual execution is not proof of isolation.
- Manual Kiro sessions must also use approved tool/credential restrictions. Automated analysis uses an isolated workspace with bounded evidence and no production/repository/state-write credentials.
- Strict proposal validation, raw-versus-validated records, explicit unknowns, evidence freshness and deterministic policy before and after model execution.
- New least-privilege publishing identity, separate from existing read-only credentials; no automatic widening of the whitelist PAT. Effective permission tests in a disposable repo precede live use.
- Scoped, version-bound exception proposals only. No bot can activate suppression, tag a final security disposition, merge or deploy.
- Trusted plan/diff gates, deterministic external action IDs, persisted intent and timeout reconciliation; never blindly retry a PR creation with an ambiguous outcome.
- Separate switches for AI, fix publication and exception-proposal publication. Revoking write credentials must not break read-only collection or existing alerting.

## 10. Testing and evaluation ledger

These are **future implementation acceptance checks**, not claims of tests already run.

| Check | Smallest useful evidence |
|---|---|
| Existing feature parity | Fixture-backed API assertions plus one browser journey for filters/detail/export/selection; mechanically enumerate expected routes. |
| Correct collection | Existing fake-API contract cases: engine-empty mismatch, rotating IDs, 302/401/403, duplicate/suppressed rows, null fields, owner scope, interval floor. |
| No false closure | Failed/filtered/limited/owner-only runs cannot globally resolve; only safe owner scope retires its placements. Unknown/stale evidence never becomes “not affected.” |
| Migration safety | Read-only input, integrity/schema validation, transactional failure rollback, deterministic ID maps, repeated import and count/history reconciliation. |
| Durable review | Restart/reload, expected-version conflicts, append-only corrections, separate contexts, atomic review+audit, evidence supersession. |
| Shared interface security | Unauthenticated/unauthorized denial, CSRF/host/proxy-boundary negative tests, identity attribution, escaped CVE text and CSV formula payloads. |
| Job reliability | Double-click, crash/cancel, stale claim, retry and partial evidence retention; no false successful job or duplicate lifecycle event. |
| AI guardrails | Malformed JSON/duplicate keys/unknown fields/fabricated refs/forged approvals/injection/stale snapshot; preserve blocked raw output and continue manual workflow. |
| Remediation gate | Wrong artifact/commit, missing or partial scan, suppression hiding the CVE, still-vulnerable lockfile, unrelated diff, nonexistent target, stale verification and missing deployment proof all block success. |

When implementing, keep an acceptance ledger per PR: requirement -> code path -> targeted automated test -> direct browser/CLI probe. Run the smallest checks covering the change; a build/typecheck alone is not done. Do not use live public-intelligence smoke tests or schema codegen checks as if they were offline unit tests.

Start recording baseline reviewer effort with the first human-review slice. Compare manual handling, evidence/rules only, and evidence/rules plus AI using comparable cases. Count wrong/unsure/blocked outcomes and correction work; distinguish time-to-review, time-to-PR, time-to-merge and runtime-verified remediation. Set thresholds with Security before the live trial. Stop publication on unsafe dismissal proposals or broken isolation/verification; evidence-only operation may remain useful.

## 11. Decisions needed before implementation

1. **Language:** accept TypeScript reuse for the first release, or confirm that Go is mandatory? Recommendation: TypeScript first.
2. **First audience:** one local analyst or a shared team service? Recommendation: local fixture-based slice first, with shared access gated by M4.
3. **Meaning of “manage”:** local cases/reviews/notes and links, or authoritative scanner changes? Recommendation: local workflow plus explicit external decision references; no scanner mutation in the pilot.
4. **Pilot scope and data:** which owner/repositories and approved snapshot destination? No live import until agreed.
5. **Identity and deployment:** approved internal host/SSO, reviewer roles and source read-only identity. Do not assume a developer cookie is deployable authentication.
6. **AI:** approved data handling and whether manual Kiro proposal import is enough initially. Recommendation: close the manual loop before adding headless calls.
7. **Remediation:** can CI provide source/manifest/build/digest provenance, SBOM, complete unsuppressed candidate scans and comparable baseline results? Until proven, this remains a later unverified capability.

## 12. Concrete starting point

Start with PR 1 above, not Renovate and not Kubernetes. The first meaningful demo is:

> Open the web app -> filter a CVE -> inspect one affected-context case and its evidence -> record a human decision with rationale -> restart -> see the same decision and history, without changing any source-system finding.

Once that is reliable, bring in an approved legacy snapshot, then collection, then team access. Only add AI and remediation where measured value and verified capabilities justify them.
