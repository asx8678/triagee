# 07 · Integrating the accepted design into the existing application

## 7.1 Keep the existing architecture

Use the framework, routing, asset pipeline and data-access conventions discovered in the audit. The reference's single HTML file is a portability device. Its render functions are a component map, not a recommendation to replace the app with a global client-state object.

If the application is Phoenix/LiveView, build components and LiveViews using the versions and idioms already present. Keep queries, authorization, scoped decisions and audit writes on the server. Use small client hooks only for drawer focus/scroll restoration, measurement, chart interaction or other browser-only needs. Do not trigger server rerenders on every keystroke in a way that loses cursor position or drafts. Use stable IDs and preserve input state deliberately.

If the application is a client-rendered framework, integrate with its existing route/query/cache/form layers. Do not add another global state system merely to mirror the prototype. Use stable keys, abort/version protection for stale fetches and explicit mutation results. Use native semantic elements where practical.

If the application is server-rendered without a rich client framework, preserve that model and add bounded progressive enhancements. The central requirements are persistent action layout, scoped state and direct navigation—not a prescribed frontend language.

## 7.2 Suggested component responsibilities

| Component responsibility | Inputs | Output/side effects |
|---|---|---|
| App shell | Active destination, workspace context, shared scope, queue count | Navigation only. |
| Scope bar | Allowed teams/environments, current scope, health | Explicit scope-change intent. |
| Metric link | Unit, total, qualifier, predicate/IDs | Exact read drilldown. |
| Shared data table | Stable rows, sort/page/selection, column definitions | Read and selection events; no implicit decision. |
| CVE inspector | Advisory, visible target set, section, originating context | Close/expand/read/review intents. |
| Review queue | Stable ordered eligible IDs, current ID, filter | Navigate current assessment. |
| Review evidence | Recorded evidence and selected scope context | Read disclosures; exact target selection. |
| Decision form | Draft, allowed actions, target version, pending/errors | Explicit validate/submit command. |
| Persistent action row | Draft/submit state, permitted actions | Save or Save & next only. |
| Timeline views | Scope/window/timezone, events, coverage | Same-entity event inspection/export. |
| Integration preview | Validated local work, destinations, preview version | Explicit remote submit; separate result. |

Adapt actual names/files to the repository. Do not duplicate these responsibilities into unrelated implementations for each screen. In particular share severity/priority/status display, scope predicates and inspector behavior.

## 7.3 Read-model contract

Each read should carry scope/dataset, a consistent snapshot or version where possible, generated-at/as-of time, coverage/freshness and relevant totals. Lists return stable IDs and pagination metadata. Rows must include enough data to show the accepted UI without N+1 queries for each team/occurrence.

Use a shared query/predicate implementation for a metric and its drilldown. Treat unit as explicit metadata: distinct CVEs, occurrences, immutable images, deployment scopes, events. A count object should not be a bare number whose meaning differs between tabs.

Recommended conceptual presentation data:

```text
ScopeContext(dataset_id, team_ids, environments, operational_only)
Metric(unit, value, predicate, as_of, completeness, contributing_ids/targets)
AdvisoryRow(id, packages, severity, scoped_priority, visible_scopes,
            observation_summary, workflow_summary, exceptions,
            exposure_summary, first_observed, fix_information)
EvidenceReceipt(source, source_record_id, observed_at, ingested_at,
                scan_run_id, intended_coverage, completeness)
```

These are conceptual structures, not a mandate to add a new API or replace existing tables. Serialize only what the user is allowed to see. Hidden UI filters are not authorization.

## 7.4 Decision command and result

A decision command needs a canonical advisory ID, explicit stable target IDs, action, responsibility/attribution, rationale, relevant date and timezone, evidence references, expected version and operation identity. The server confirms current eligibility and permitted scope, validates dates and records a transaction.

Return committed decision ID, exact accepted target set, resulting scoped work state, audit reference, updated version and any validation/conflict/partial-operation status. Reject unexpected target expansion. The UI should render the durable result rather than optimistically declare a successful exception before receiving it.

The same logical operation retried after a timeout must not create duplicate local work/audit records. Use existing transactional uniqueness/idempotency mechanisms. Do not claim exactly-once behavior across an external system merely because a UUID was generated in the browser.

Separate local work records from remote submission jobs. Only confirmed remote success produces a remote ticket link. Do not hold a database transaction open during a slow AI or ticket request. Use the existing job/transaction model when available; document added infrastructure rather than silently adding a platform dependency.

## 7.5 State preservation and concurrency

Read state: route/query and stable table position. Ephemeral UI state: active inspector, tabs, expansion, in-view focus. Draft state: existing authorized server/session storage or explicitly approved local handling. Persisted decision: durable audited mutation. Keep these layers separate.

Use stable identity when restoring scroll or finding the next queue record. A background refresh cannot silently select a different item while a user writes a rationale. Show an available-update indicator and merge read-only facts safely; reconcile changed targets at commit.

For multiple operators, detect concurrent decisions. Show the newer decision and preserve the current draft for comparison, rather than overwriting it. A conflict is not a generic validation error that clears form fields. In local single-user mode, retain the same safety for concurrent tabs or late imports.

## 7.6 Security and external boundaries

Continue the application's existing local-only/network defaults. Escape untrusted advisory text, image names and notes. Render descriptions as text or through the repository's vetted sanitizer; the old screenshots include synthetic markup-like text, so include an inert-markup test. Never interpolate arbitrary content as HTML merely because the demo renderer does so with its own escaping helper.

Use the framework's existing CSRF/session/auth patterns for mutations. Keep credentials server-side and out of logs, snapshots, exports and browser storage. Do not add an external font/analytics/CDN call to achieve the design.

Do not refresh intelligence, run AI or submit Azure DevOps work on mount, navigation or a passive drawer open. Each is an explicit action with progress, failure and provenance. Preserve preview/confirmation boundaries already present in the app.

## 7.7 Performance without changing the design

Avoid loading all CVE/occurrence evidence into a browser merely to calculate counts. Keep aggregations server-side and request detail on demand, without losing scope. Use actual pagination/virtualization when the real dataset requires it. Preserve a complete accessible representation and explicit total.

Keep layouts stable during data loading; skeletons use the same row/card geometry. Bound description rendering and table layout without silently hiding core values. Expensive timeline/event aggregation should be cached or queried at the right scope/time granularity, with explicit freshness.

Measure current response/interaction behavior on representative fixtures before setting performance claims. Add a larger test fixture, for example thousands of rows, and record actual list/inspector/review latency and browser interaction observations. Do not assert a universal millisecond SLA from the visual prototype.

## 7.8 Test-only fixture adapter

Use `contracts/synthetic-fixture.json` as the deterministic visual fixture. Map its stable advisory/scope IDs and relationships into the existing test persistence model; keep fake intelligence/priority assertions confined to this adapter. Freeze server time and displayed timezone according to the fixture. Use the same visible content and disabled integrations as the accepted reference.

Enable the adapter only in isolated test/development configuration. Render the fixture readiness marker required by the capture tool only in that mode. Do not add an unauthenticated production query parameter that turns on sample data, resets a database or exposes test controls. The test adapter must not alter the production interpretation of real CVEs.
