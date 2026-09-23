# Grafana reporting API — scope of work and implementation plan

**Status:** local v1 API implementation checkpoint. The read-only endpoints, scoped machine tokens, exact-target drilldowns, OpenAPI contract and credential-free dashboard starter are implemented in the working tree. Live Grafana/plugin/network validation, representative load evidence and production rollout remain blocked release gates.

**Reviewed and implementation reconciled:** 23 September 2026.

**Baseline:** `main`, HEAD `9eaff24cfa51f0271f28c4ee54a804101b12a2b9`, plus the existing dirty working tree. Recheck before implementation; do not overwrite unrelated changes.

## 1. Objective and recommendation

Expose recorded active CVEs, effective scoped whitelists and related operational information to Grafana through an authenticated, read-only JSON API in the existing Phoenix application.

```text
Grafana server / datasource
  -> approved HTTPS reverse proxy
  -> Phoenix /api/v1 (service-token authorization)
  -> shared reporting/domain projection
  -> PostgreSQL
```

Use normal Phoenix controllers and explicit JSON serializers, not LiveView events, HTML scraping, a separate microservice or direct access to writable database tables. Grafana owns visualization; Triage owns state definitions and authorization.

Recommended first integration: Grafana Infinity with server-side/backend parsing and server-side bearer authentication. Confirm the installed Grafana/plugin versions, permitted plugins, pagination and alerting capabilities before promising a working dashboard. Prometheus aggregates are a separate optional follow-up, not a replacement for CVE/whitelist detail tables.

### Scope sources and precedence

- Current owner request: implement the approved first-release reporting slice for Grafana. This is not production deployment or authorization to execute the larger redesign.
- [Existing reporting contract](../../triagee-implementation-bundle/spec/06_GRAFANA_CONTRACT.md), [product scope](../../triagee-implementation-bundle/spec/01_PRODUCT_SCOPE.md), and [M3/T11 work](../../triagee-implementation-bundle/spec/04_IMPLEMENTATION_PLAN.md).
- [Existing acceptance catalog](../../triagee-implementation-bundle/qa/ACCEPTANCE.md): especially A047–A049 and A052.
- [Proposed reporting schema](../../triagee-implementation-bundle/contracts/reporting-target.schema.json): a design input, NOT an implemented or published API. Its example `placement_ids` link is not currently supported by WorkspaceLive.
- [Broader experiment plan](../../CVE_TRIAGE_REMEDIATION_IMPLEMENTATION_PLAN.md): retain its human-authority, read-only integration and loopback/security boundaries. This API does not complete its collection, AI or remediation work packages.
- [Deployment](DEPLOYMENT.md), [domain contracts](DOMAIN_API.md), and [owned database verification](../OWNED_DB_VERIFICATION.md).

Do not resurrect old navigation/design requirements while implementing this API. Do not claim the broader M2/M3 or experiment milestones complete because a reporting adapter exists.

## 2. Checked baseline and gaps

Paths below are repository-relative; existing modules are not proposed new APIs.

| Area | Witnessed current behavior | Work required |
|---|---|---|
| `app/lib/triage_web/router.ex` | JSON pipeline exists; `/health` is the only mounted JSON reporting-adjacent route. | Versioned reporting scope, bearer authentication, JSON errors. |
| `app/lib/triage/workspace.ex` | Target identity is CVE × placement; active means unresolved findings on an active placement. Reference-only inventory is excluded. | Reuse state rules, expose explicit DTOs; do not serialize whole domain maps. |
| `app/lib/triage/workspace/query.ex` | SQL reduces targets, pages 50 CVEs and uses a repeatable-read, read-only transaction per request. | Shared reusable target projection, API-specific aggregation and target pagination. Fifty CVEs does not bound the number of placements/packages hydrated. |
| Same query module | Headline metrics count from `targets`; text/severity/state matching occurs separately. | Do not return existing UI metrics as though all API filters applied. Define aggregation filters explicitly and test them. |
| `app/lib/triage/decisions.ex` | Latest scoped/global decision wins by chronology; expiry cannot resurrect an older approval. | Reuse exact chronology and inclusive/exclusive legacy expiry rules. |
| `app/lib/triage/evidence.ex` and `workspace/evidence_sql.ex` | Evidence changes affect coverage. Default legacy policy can keep approvals effective as `legacy_flagged`. | Preserve policy and expose the unverified flag. Some older comments describe demotion rather than the current default; behavior and parity tests govern. |
| `app/lib/triage/attention.ex` | Attention is distinct from needing a decision. Reported fixes require verification. Elixir expiry attention reads wall-clock time internally; SQL accepts a supplied clock. | Thread one evaluation clock through both paths without breaking existing callers. Do not invent extra overdue-work behavior only in the API. |
| `app/lib/triage/risk_decision_history.ex` | Historical register groups recorded approvals; explicitly not effective coverage. | Do not use its counts for current whitelist panels. |
| `app/lib/triage/accounts.ex` | Application-wide roles and revocable eight-hour browser sessions. | Dedicated read-only machine tokens. Team filters are not authorization. |
| `app/config/runtime.exs` | Loopback-only Phoenix binding enforced. | Preserve it; expose through the documented TLS/private-network boundary. |
| Workspace links/components | Current URL whitelist has no placement-focus parameter. Target row ID is only present on selectable checkboxes; viewers cannot rely on it. | Small read-only exact-target focus/drilldown addition; no automatic checkbox selection or draft changes. |
| Timeline/statistics | Recorded observation and action history exists; no verified-remediation reporting model or durable reporting snapshot API was found. | Do not manufacture verified outcomes, historical current-state snapshots or successful scan timestamps. |
| Grafana artifacts | No running Grafana integration, datasource provisioning or dashboard export established from app code. | Integration configuration and real Grafana validation remain separate deliverables/gates. |

## 3. Scope boundaries

### First release — included

1. Shared reporting projection and explicit counting definitions.
2. Read-only `/api/v1` endpoints for summary, CVEs, targets, target package detail and filter options.
3. Service-token provisioning, expiry, rotation, revocation and scope enforcement.
4. Validated filters, bounded pagination, consistent per-response reads, documented freshness and errors.
5. Effective whitelist status, expiry, partial/full CVE coverage and legacy verification flags.
6. Safe links back to the exact CVE/placement; preserve existing browser authentication and drafts.
7. OpenAPI contract, synthetic examples, automated acceptance tests and performance observations.
8. A minimal Grafana integration example: datasource instructions, variables and an importable example dashboard if the selected plugin is available. Actual connection requires approved environment access.
9. Additive migrations only for machine credentials and their scope grants; no inventory/decision backfill.

### Explicitly excluded

- Whitelist/create/update/delete API, ticket creation, remediation, AI execution or source refresh triggered by reporting.
- New collectors, live asset-register integration, new source-completeness claims or automatic suppression.
- Changes to approval policy, verified-remediation workflows, merging case exceptions into workspace coverage, or reclassifying historical decisions.
- New Phoenix charts, navigation redesign, generic GraphQL API or another backend service.
- Public token-management endpoints, a new admin console, production rollout or credentials in repository examples.
- Historical trends, frozen multi-request exports and Prometheus instrumentation unless separately promoted from follow-up scope below.

## 4. Data semantics to lock before implementation

### Counting units

- **CVE:** distinct CVE identifier within the authorized requested scope.
- **Target:** one `{cve, placement_id}`. Multiple packages on the same target are evidence, not additional targets.
- **Decision record:** one historical approval/work record. This is not a CVE count or target count.

| API concept | Definition |
|---|---|
| `active` / recorded present | At least one unresolved finding on an active placement. This is recorded inventory, not proof of complete live scanning. |
| `needs_decision` | Active target without effective covering decision, matching the current workspace rule. |
| `needs_attention` | Current shared attention policy requires a new human step; includes more than just `needs_decision`. |
| `whitelisted` | Active target whose effective covering decision is `accepted_risk`, under the configured evidence/legacy policy. Not a scanner suppression flag. |
| `whitelist_coverage` | CVE-level `none`, `partial` or `full`, calculated against ALL active targets for that CVE inside the authorized team/environment scope. Use `not_applicable` if there are no active targets. |
| `expiring_whitelist` | Effective whitelisted target whose expiry is within the shared seven-day review window. Preserve exact boundary rules. |
| `not_affected` | Separate effective recorded assessment; never counted as risk acceptance. Preserve legacy/evidence flags. |
| `reported_fixed` | Recorded fix claim, not a verified remediation and not necessarily no longer observed. |
| `coverage_state` | Existing evidence state such as covered, evidence_changed, legacy_flagged or legacy_unverified; preserve meaning rather than replacing with a green boolean. |

Important consequences:

- Active and whitelisted overlap. Never calculate active CVEs by subtracting whitelists from all detections.
- `whitelisted=false` is not equivalent to `needs_decision=true`: work, not-affected assessments and reported fixes have separate meanings.
- A CVE with two whitelisted targets and one uncovered target remains partially whitelisted. Filtering the output to whitelisted targets must not change its denominator to two.
- Team-level distinct CVE counts are not additive; compute the estate total independently.
- Preserve expired/replaced/invalidated records as history, but do not count them as current operational whitelists.
- An expired replacement must not reactivate an older acceptance. Future decisions do not cover current targets.
- Retired placements and reference-only records do not enter operational totals.
- An existing browser demo flag does not prove all stored rows are synthetic, and disabling demo mode does not make seeded records production evidence.
- Unsupported verification metrics are `null`/unsupported with a limitation, not a fabricated zero. Unknown KEV/exposure/source coverage remains unknown.
- The older handoff allows attention/in-progress overlap and richer overdue behavior. Current predicate behavior must be characterized; do not silently implement a new workflow policy only for Grafana. Any domain-policy alignment is a separately reviewed change.

### Filter/count contract

Authorization scope is applied first. Team/environment narrow that scope. CVE/search/severity select eligible CVEs or targets according to the documented endpoint contract; package matches never discard other evidence needed to calculate coverage.

For CVE coverage, calculate the full active-target denominator within authorized team/environment scope BEFORE applying whitelist/disposition output filters. Explicitly identify that coverage scope in metadata. Summary, rows and drilldowns use the same defined population; pagination never changes totals. Compare API counts with equivalent UI views, not an intentionally wider UI headline total.

## 5. Implemented local v1 HTTP contract

All endpoints below are implemented, authenticated and GET-only. Unsupported methods cannot mutate anything. The checked-in source of truth is [`openapi/grafana-v1.yaml`](openapi/grafana-v1.yaml).

| Endpoint | Response/use |
|---|---|
| `GET /api/v1/summary` | One summary with clearly named CVE/target counters and severity/team/environment breakdowns. Cap high-cardinality breakdowns and expose truncation/continuation, never silent omission. |
| `GET /api/v1/cves` | Paged CVE rows: severity, priority, active-target count, whitelisted-target count, needs-decision count, whitelist coverage and app link. |
| `GET /api/v1/targets` | Paged flat CVE × placement rows for Grafana tables; current observation/decision/evidence/expiry state. |
| `GET /api/v1/cves/:cve` | Scoped CVE summary and links to target/package pages; no unbounded embedded placement/history arrays. |
| `GET /api/v1/targets/:placement_id/packages?cve=...` | Paged package evidence for the exact pair; installed version and scanner-reported fix value without inventing a verified candidate version. |
| `GET /api/v1/options` | Authorized team/environment options and supported enums; bound large option sets and support option search/paging. |

No separate whitelist implementation: `GET /api/v1/targets?whitelisted=true` uses the same effective projection. A later `/whitelists` alias, if requested, must delegate to it.

### Filters and limits

Proposed defaults, to freeze in the OpenAPI review:

- Shared selectors: `team`, `environment`, `cve`, `q`, `severity` as supported by each route.
- Target selectors: `active`, `whitelisted`, `needs_decision`, `needs_attention`, `expires_within_days` (1–90, valid only with `whitelisted=true`).
- CVE selector: `whitelist_coverage=none|partial|full|not_applicable`.
- Default current lists: `active=true`; explicitly request history/inactive records where supported. Contradictory filter combinations return validation errors.
- Default page size 50, maximum 100; deterministic keyset order by CVE, then placement/finding identity where applicable. Avoid exposing arbitrary SQL sorting/grouping.
- Cursor is signed, bounded and bound to endpoint, normalized filters and authorization scope. Revalidate authorization on every page; a cursor is never permission.
- Unknown keys, invalid booleans/enums, nested values, malformed IDs/cursors and oversized text return `400`; never ignore them and widen the query.
- Unknown but syntactically valid scope values produce an empty authorized result, or `403` when outside the token grant. Distinguish this from malformed input.
- IDs and dates have stable OpenAPI types. Prefer decimal strings for PostgreSQL bigint identifiers to avoid JavaScript precision loss; record this difference from the older draft schema.
- All timestamps ISO-8601 UTC. Retain explicit expiry-boundary metadata for legacy records.
- Proposed initial bounds: 2 seconds database statement timeout, 5 seconds overall request budget and 1 MiB response budget. Validate/tune against measured volume before rollout; never return a silent partial success when a budget is exceeded.

### Fields

Summary: `active_cves`, `active_targets`, `needs_decision_cves`, `needs_attention_cves`, `fully_whitelisted_cves`, `partially_whitelisted_cves`, `whitelisted_targets`, `expiring_whitelist_targets`, `not_affected_targets`, `reported_fixed_targets`, `unknown_exposure_targets`, and `legacy_flagged_targets`.

Target rows: `cve`, `placement_id`, `team`, `environment`, `namespace`, image identity/repository/tag, severity, review priority, `active`, `decision_type`, `decision_id`, `coverage_state`, `needs_decision`, `needs_attention`, `whitelisted`, `expires_at`, `expiry_boundary`, first/last observed times, package count and an encoded internal `detail_path`. Separate active placement state from recorded observation state for historical rows.

Keep list rows flat and bounded for Grafana. Do not dump Ecto structs, arbitrary metadata, evidence packets, AI prompts/responses, credentials, raw source payloads or session information. Reviewer identities and free-text reasons are excluded from initial bulk responses; the authenticated app retains audit detail. Adding them later requires an explicit field/access review.

Illustrative CVE aggregate, not measured inventory:

```json
{
  "cve": "CVE-2099-1001",
  "active_targets": 3,
  "whitelisted_targets": 2,
  "needs_decision_targets": 1,
  "whitelist_coverage": "partial"
}
```

### Envelope, errors and freshness

Responses use `data`, `meta` and `pagination` where applicable. Metadata includes schema version, effective policy versions/legacy policy, `evaluated_at`, applied filters, coverage scope, consistency mode, recorded source limitations and available last-observed timestamps. Totals declare their counting unit.

`evaluated_at` is not a scan timestamp. Max finding `last_seen` is not proof every deployment was scanned recently. Persisted source completeness is currently insufficient for a blanket complete-coverage claim; report `unknown` unless a real source contract establishes more.

- `401`: missing/invalid/expired/revoked bearer token; JSON, never a login redirect.
- `403`: authenticated token cannot request the scope/capability.
- `404`: CVE/target pair unavailable within authorized scope; no existence leak.
- `400`: structured invalid-filter/cursor error; no SQL or credentials in messages.
- `429`: bounded rate limit with `Retry-After`.
- `503`: disabled API, unavailable database or exhausted query budget; never an all-zero success response.

Use `Cache-Control: no-store` initially. Empty valid recorded results are distinct from failed reads and unknown source coverage. Start with a 60-second Grafana refresh interval and the configured fixed-window per-token rate limit (default 120 requests/minute); benchmark rather than promising performance.

## 6. Consistency decision — explicit release boundary

**Recommended small first release:** per-response repeatable-read consistency. Capture one clock, use it in SQL and Elixir, and calculate each response's page and totals in the same transaction. No reporting writes or external calls on GET.

A keyset cursor does NOT preserve a PostgreSQL snapshot between HTTP requests. Separate panels/pages may legitimately observe a concurrent import, expiry or decision change. Expose `consistency: "per_response"`; do not accept an arbitrary historical `as_of`, emit a fake durable snapshot ID, or advertise an atomic all-pages export. Grafana summary panels should consume server aggregates rather than sum paginated tables.

The older reporting proposal asks for one logical captured snapshot. The MVP above is an explicit narrowing, requiring scope approval; it must not be reported as full frozen-snapshot acceptance. A047/A052 still require deterministic fixture parity and within-request concurrency tests, while across-request consistency remains unfulfilled.

**If frozen multi-page reporting is required for v1:** promote API-08 below to a release dependency. Capture immutable reporting generations in a scheduled/operator-triggered process, atomically publish only complete generations, and bind every page/aggregate to a generation ID. GET only reads; it never starts capture. Document capture lag, scope isolation, unsupported freshness, retention, quotas and expired-generation errors. Do not hold a database transaction open across HTTP requests.

## 7. Security and deployment

- New credential type for machine reporting, separate from browser sessions and human review authority. Capability: `reports:read` only, never reusable for approvals, tickets or admin operations.
- Generate cryptographically random tokens; persist only a hash and safe identifier, owner/service label, grants, created/expiry/revocation metadata. Mandatory expiry; proposed maximum lifetime 90 days pending security approval.
- Provision/rotate/revoke through trusted operator Mix/release commands. Deliver the secret once through a protected operator channel; never a URL, command argument, committed file, log or public token-creation route.
- Prefer linking a token to a dedicated enabled viewer service identity; every request checks the identity and token grant. A parent identity gaining reviewer privileges never grants the token mutation authority.
- Scope grants support explicit all-scopes authorization or explicit allowed team/environment pairs. An empty grant denies all; it must not mean wildcard. Preserve pair relationships rather than forming a cross product of independently allowed teams/environments.
- Apply grants in SQL and to summaries, totals, options, package detail, cursors and links. No metadata/option leak from other scopes. Browser filters remain display controls, not newly asserted tenancy.
- Grafana datasource credentials live server-side. Dashboard variables are not a security boundary; use separate scoped datasource tokens where team isolation is required.
- Preserve loopback-only Phoenix, existing CSRF/browser sessions and production sign-in restrictions. Use approved TLS proxy/private connectivity; do not set `TRIAGE_BIND=0.0.0.0`.
- Do not enable permissive CORS for a server-side datasource. Filter authorization headers from request/error logs and avoid secrets in provisioning/dashboard exports.
- API gate is `TRIAGE_REPORTING_API_ENABLED`, default false; disabled requests fail closed before inventory queries. Invalid values fail startup.
- Read-only means no business DB writes/jobs/network effects during reporting. Operational in-memory rate-limit/telemetry counters are allowed; do not introduce a per-poll token `last_used_at` database write under this contract.

## 8. Ordered work packages

The packages remain the acceptance decomposition. Current checkpoint:

| Package | Local status |
|---|---|
| API-00 | OpenAPI and deterministic characterization tests implemented. |
| API-01 | Shared projection and semantic tests implemented; representative-volume performance measurement remains open. |
| API-02 | Hashed expiring scoped tokens, issue/rotate/revoke tasks, rate limit and additive migration implemented; owned rollback rehearsal passed locally. |
| API-03 | Six authenticated GET routes, strict filters/cursors, JSON errors and default-off gate implemented and HTTP-tested. |
| API-04 | Exact target links and fail-closed viewer/reviewer LiveView tests implemented. |
| API-05 | Credential-free Infinity starter and setup guide added; real plugin/server validation remains open. |
| API-06 | Full local suite and repository precommit gate pass; representative load, private TLS and rollout approval remain open.

### API-00 — Contract and characterization (first checkpoint)

**Depends on:** scope review. **Size:** small/medium.

- Freeze endpoint/field/filter/count semantics and decide per-response versus frozen-generation scope.
- Map the older reporting schema to supported current fields; mark unsupported verification/workflow/source facts explicitly.
- Add deterministic mixed-scope fixtures: partial whitelist, package multiplicity, reference-only, retired, expired/replaced, legacy flagged/demoted, changed evidence and reported fixed.
- Record equivalent UI predicates versus wider headline metrics. Pin exact target IDs, not only totals.
- Publish `app/docs/openapi/grafana-v1.yaml` and fixture examples; never claim live Grafana validation from a local contract artifact.

**Exit:** reviewed OpenAPI draft, semantic ledger and reproducible characterization results on an owned database. Missing Grafana credentials do not block this package.

### API-01 — Shared reporting projection

**Depends on:** API-00. **Size:** medium/large; highest semantic risk.

- Add `app/lib/triage/reporting.ex` plus narrow query/filter/serialization helpers.
- Extract/reuse the common target/evidence/coverage SQL from `workspace/query.ex`; keep the existing workspace behavior and public context contracts compatible.
- Thread one explicit clock through attention/coverage evaluation; retain backwards-compatible defaults for existing callers.
- Add database-side summary/CVE/target aggregation, correct denominators and bounded package detail. Do not call `Workspace.targets(%{})` for every dashboard refresh.
- Add keyset cursors and complete-target coverage calculation; a response field limit must not truncate evidence used to determine status.

**Exit:** SQL/domain/reporting exact-ID parity, filtered totals and boundary tests pass; no UI behavior regression. Query/read/memory measurements recorded for many CVEs and one very large CVE.

### API-02 — Machine identity and read authorization

**Depends on:** API-00; can proceed independently of API-01 after ownership is assigned. **Size:** medium.

- Add `app/lib/triage/accounts/api_token.ex`, a narrow token context, additive token/scope-grant migration and operator issue/rotate/revoke commands.
- Add a dedicated API authentication plug and rate limiter; never broaden the browser read-event whitelist for machine access.
- Revalidate token and parent identity, enforce exact grants and redact secrets. Revoke immediately without waiting for an application result cache.
- Update owned-DB verification guards if the new storage requires it; do not weaken ownership/pristine checks.

**Exit:** invalid/expired/revoked/disabled/wrong-scope credentials rejected, rotation exercised, no token accepted for browser/domain mutations; migration/rollback rehearsal preserves existing data.

### API-03 — HTTP surface and contract enforcement

**Depends on:** API-01 and API-02. **Size:** medium.

- Add thin `app/lib/triage_web/controllers/api/v1/` controllers/JSON modules and register `/api/v1` behind the read-only pipeline.
- Add strict parameter validation, correct status codes, response budgets, content type, no-store headers and API enable flag.
- Expose only allowlisted DTO fields. Detail endpoints remain scoped and bounded.
- Validate actual responses against OpenAPI/examples and mechanically check routes, config entries and public context functions.

**Exit:** API works via authenticated HTTP on an owned local instance; reads produce no business writes, jobs or outbound calls; disabled/unavailable states are honest.

### API-04 — Exact-target app drilldowns

**Depends on:** API-01/API-03. **Size:** small/medium.

- Add a validated read-only `focus_target` parameter or equivalent supported route for the CVE/placement pair; decide the precise route at API-00.
- Add a stable target-row anchor available to viewers, not only a reviewer checkbox ID. Preserve the exact requested pair and team/environment context.
- A missing/out-of-scope target shows a truthful result; never substitute another CVE/deployment.
- Focusing a target must not select a mutation checkbox, overwrite an existing draft or call external services. Use relative encoded app links and approved deployment base URLs.

**Exit:** viewer/reviewer, malformed, wrong-CVE, retired and mixed-scope link tests plus a private-browser probe. Existing draft and navigation tests remain passing.

### API-05 — Grafana integration example

**Depends on:** API-03/API-04 and confirmed datasource capabilities. **Size:** small/medium.

- Provide `app/docs/GRAFANA_API.md`, safe provisioning instructions and a version-pinned example dashboard under `app/priv/grafana/`.
- Panels: active CVEs, targets needing decisions, full/partial whitelist counts, expiring whitelist table, severity/team/environment breakdowns and current CVE/target tables with app links.
- Variables use authorized options; handle URL encoding and genuine pagination. Show errors/unknown freshness, not all-green zeros. Do not silently treat the first 100 rows as the whole dataset.
- Keep reasons/personally identifying reviewer detail out of broadly shared panels by default.
- Optional configured Grafana utility link only if an approved URL exists; no navigation redesign or fake destination.

**Exit:** local examples validated; actual Grafana server successfully reads, filters and drills down using a read-only token, OR live validation explicitly remains blocked by missing access/plugin/connectivity. An example export is not live integration evidence.

### API-06 — Verification, performance and controlled rollout

**Depends on:** API-01 through API-05. **Size:** medium.

- Run targeted contract/security/parity tests first, then the required integrated suites and owned concurrency/browser probes.
- Measure representative refresh concurrency, database statement count/plans, response bytes and worst-case package/target fan-out. Tune indexes/limits based on evidence, not page size alone.
- Rehearse additive migrations and rollback on owned representative data. Do not drop token tables or rewrite decision history as an emergency rollback.
- Keep API disabled until the proxy, credentials, grants, data-origin warnings and dashboard interpretation are approved. Rollback: disable API, revoke token, disable datasource queries; existing app remains usable.
- Record exact commands/results, limitations and live-service evidence separately. No production migration/deployment without approval.

**Exit:** all applicable acceptance checks below evidenced, docs current and rollout signed off. No claim of full T11/frozen-snapshot or verified-remediation completion beyond delivered scope.

### Follow-up packages — not in the recommended first release

- **API-07: time-series/Prometheus.** Choose intentional periodic snapshots or recorded-event aggregation with documented missing-history semantics. Prometheus uses low-cardinality bounded dimensions; never CVE IDs, image digests, reasons, packages or ticket URLs as labels. Define retention and freshness before promising historical charts/alerts.
- **API-08: frozen reporting generations.** Required before release if the owner rejects per-response consistency. Implement immutable capture/publication, generation-bound pagination/aggregates, expiry/retention, authorization, failed-capture behavior and concurrent-import tests. Not a synthetic timestamp token or a long-lived request transaction.
- Audit-history API, reviewer/reason exports, richer work/ticket reporting and legacy-case union require separate contracts. They cannot silently alter operational whitelist coverage.

Dependency path: `API-00 -> (API-01 || API-02) -> API-03 -> API-04 -> API-05 -> API-06`. If required for v1, insert API-08 after projection design and before HTTP/integration acceptance. API-07 is independent later reporting work, not a reason to delay the current-state API.

## 9. Acceptance ledger

The local automated slice now exercises token lifecycle, strict filters/cursors, exact scope grants, aggregate semantics, HTTP failures and exact-target LiveView behavior. The contract and dashboard artifacts are checked in. Items requiring a real Grafana/plugin, approved network, representative load or production controls remain open and must not be inferred from local tests.

Latest local evidence (23 September 2026):

- reporting-focused owned-DB suite: **18 passed**;
- repository precommit gate: **1,343 passed, 2 skipped**;
- reporting migration: migrate → one-step rollback → table-absence check → remigrate passed on a uniquely named owned database;
- OpenAPI/dashboard parse, six route registrations, local `$ref` resolution and issue/rotate/revoke task discovery passed.

| ID | Check and required evidence |
|---|---|
| GAPI-01 | Route/OpenAPI/serializer agreement; all public endpoints read-only and versioned. |
| GAPI-02 | Missing, malformed, expired, revoked and disabled-identity tokens fail; no browser login redirect. |
| GAPI-03 | Scope grants cover rows, aggregates, options, package detail and cursors; empty grants deny, no pair cross-product leak. |
| GAPI-04 | Direct mutation attempts using machine credentials fail; GET leaves inventory, decisions, drafts, jobs and external-call probes unchanged. |
| GAPI-05 | One CVE with several packages/placements/teams counts correctly; distinct team counts are not summed as estate CVEs. |
| GAPI-06 | Partial whitelist remains partial after `whitelisted=true` filtering; zero-active-target CVE is never vacuously fully whitelisted. |
| GAPI-07 | Exact expiry boundaries, future records, newer scoped/global replacements and non-resurrection match Decisions and SQL. |
| GAPI-08 | Changed inventory/exposure/intelligence invalidates coverage according to shared policy; unchanged facts do not spuriously invalidate. |
| GAPI-09 | Legacy flag/demote configurations agree in SQL/domain/HTTP; unverified is visible and never represented as verified remediation. |
| GAPI-10 | Not affected, accepted risk, reported fixed, no longer observed and scanner suppression remain distinct. |
| GAPI-11 | Reference-only/retired records excluded from operational counts; unknown sources and failed reads do not become zero risk. |
| GAPI-12 | Authorization, filters, counts and drilldowns agree on exact target IDs. Test q/severity/status combinations, not only team filters. |
| GAPI-13 | Page/count/detail calculations share one transaction/clock; explicit expiry-boundary and concurrent-import probes. Document cross-request limitation. |
| GAPI-14 | Invalid/oversized/nested parameters fail closed; cursors cannot change endpoint/filter/scope; stable-data paging has no duplicates/omissions. |
| GAPI-15 | Large-CVE/large-package and multi-panel load obey measured limits; no unbounded list hydration or silent evidence truncation. |
| GAPI-16 | Exact-target viewer/reviewer links preserve context and existing drafts; no automatic action/target selection, secret URL or open redirect. |
| GAPI-17 | Real datasource handles pagination, authorized variables, errors, unknown freshness and app links; distinguish local fixture evidence from live Grafana signoff. |
| GAPI-18 | TLS/private exposure, feature flag, token rotation/revocation, log redaction and disabled-mode rollback exercised. |
| GAPI-19 | Additive migrations and owned-resource guards preserve histories, IDs, scopes and durable ticket operations; no production data used. |
| GAPI-20 | If API-08 is promoted: every page/aggregate for a generation remains identical under concurrent source changes; expired/failed generations fail honestly. |

Mapping to older acceptance: GAPI-05/06/08/12 support A047; GAPI-07/09/10/11 support A048; GAPI-16/17 support A049; GAPI-13/14/15 support A052 only within declared consistency scope; GAPI-19 supports retained A050/A051 requirements. Existing broader workflow/verification items stay open.

### Verification workflow

Follow the current owned-DB guide and task help before execution. Implemented focused tests are `test/triage/reporting_test.exs`, `test/triage/reporting_tokens_test.exs`, `test/triage_web/controllers/api/v1/reporting_controller_test.exs`, and `test/triage_web/live/reporting_drilldown_live_test.exs`.

Use `./scripts/verify_owned_db.sh focused ...` for the new tests plus affected workspace/evidence/auth tests, then the project's required `precommit`/`ci` gate and appropriate owned concurrency/browser probes. A build or JSON schema validation alone is not completion. Record any pre-existing failures separately; do not rerun unchanged passing suites after every documentation edit.

## 10. Owner decisions and release gates

| Decision | Recommended default | When needed |
|---|---|---|
| Grafana installation/plugin availability | Infinity backend/server-side JSON integration; confirm actual versions and permission to install. | Before API-05/live certification; offline API work can proceed. |
| Snapshot guarantee | Per-response first release, explicitly narrower than frozen multi-request snapshots. | Before freezing API-00; promote API-08 if atomic all-page reporting is required. |
| Reporting principal/scope | Dedicated viewer service identity with explicit grants; global access only if expressly authorized. | Before token issuance/live use. |
| Data origin/coverage | Recorded inventory with explicit unknown/synthetic limitations; do not label demo data production. | Before demo/production dashboard signoff. |
| Network path | Existing approved HTTPS reverse proxy/private connection; keep Phoenix loopback-only. | Before remote access. |
| Volume, refresh and latency | Start with 60-second refresh and bounded responses; measure representative estate/fan-out. | Before performance acceptance. |
| Sensitive audit fields | Omit reasons/reviewer identities from bulk v1. | Approve separately if required. |

**Next release step:** validate the credential-free starter against the approved Grafana/Infinity versions, exercise pagination and links through the real private TLS path, measure representative load, and complete controlled rollout approval. No production migration, credential issuance or live deployment is implied by the local implementation checkpoint.
