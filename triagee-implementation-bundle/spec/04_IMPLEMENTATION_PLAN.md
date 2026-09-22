# 04 — Execution plan

`tasks.json` is the machine-readable work list. Follow dependency order; independent read-only audits can run in parallel. Only the coordinator owns disposable database lifecycle and shared migrations. Shared core modules should have one writer at a time.

## M0 — Establish truth before changes

T00: inspect current checkout, applicable instructions, old handoff, routes, data/write/read boundaries, and current tests. Record actual SHA, worktree state, source-map drift, existing external adapters, and applicable old acceptance cases. Reconcile contradictory documentation against code. Do not change data.

T01: add or identify characterization tests for authenticated exact-scope decisions, legacy chronology/expiry, evidence hashes, query ordering, durable drafts, and uncertain ticket operations. Create the isolated fixture adapter from `qa/semantic-fixtures.json`; do not load it into a real inventory.

**Gate:** an audit report with verified mappings and a baseline test run, or precise environment blockers. Baseline failing tests must be classified before attributing later failures to the redesign. No migration design based solely on the prototype.

## M1 — Deliver one real actionable workflow

T02: remove preselected fixed/acceptance defaults and unsupported prewritten conclusions. Support the existing investigation/remediation/verification paths with correct validation, instead of forcing fixed/whitelist/ticket. Display actual fix values, environment/image identity, and existing ticket links.

T03: consolidate the inventory/review/inspector rendering and events into Findings plus one CVE detail. Keep durable draft ownership, scope selection, previews, and operation recovery. Use the four-column hierarchy and responsive flow.

T04: make Findings the homepage; keep Needs attention, In progress, All tracked as projections of the same table. Preserve search/scope/deep links and compatibility mappings. Remove Overview/Review/News/Timeline from primary navigation. Keep global Timeline read-only via legacy URL until reporting transition is safe.

T05: implement the deterministic scope-local attention policy and view/count semantics in SQL and application projections. Source-backed Why now; no opaque score. Test mixed scopes and more than one page.

T06: introduce the compact read-only Exceptions register from existing records, preserving source identity, history, and legacy semantics. No fake not-affected write yet.

**Gate:** complete real-app finding → exact target → existing safe action → preview/commit → history path, plus list/detail/legacy URL/error/reconnect checks. M1 may be reviewed or rolled out independently with missing M2 actions accurately unavailable. It must not claim final typed-exception/verified-remediation completion.

## M2 — Finish exception and verification semantics

T07: add typed not-affected assessments and strengthen exception requirements through the right domain API. Add validity/review/invalidation behavior and legacy compatibility. Extend schema/readers only where needed; include migration/reconciliation tests. Preserve existing case store boundaries.

T08: replace unsupported immediate-fixed UX with reporting-for-verification and a truly evidence-supported verified outcome. Distinguish old unverified fixed records. Deduplicate verification work and keep post-change source limitations explicit.

T09: finish exception action/history/register behavior, review-due requeue, material-change handling, and repeated-observation collapse. Test multiple owners/scopes, mixed legacy/new records, and exact time boundaries.

**Gate:** real typed exceptions and verified-remediation transitions, or explicit unresolved domain blockers. No partial milestone success declared as finished M2. Representative history reconciliation and rollback rehearsal must pass before real-data rollout.

## M3 — Add optional assistance and reporting boundary

T10: add explicit, bounded AI analysis of selected scope. Reuse/adapt the opt-in read-only wrapper with a versioned contract. Validate structure and semantic evidence bindings; cache by relevant context; retain manual operation when unavailable. No autonomous approval and no unapproved live calls.

T11: implement the shared read-only reporting projection and a configured Grafana deep link. Reuse actual existing Grafana/data integration if found; otherwise provide the smallest suitable read-only adapter and examples without inventing a deployed dashboard. Snapshot/count semantics and authorization must be tested.

T12: final integrated QA, old acceptance mapping, representative migration/rollback rehearsal, responsive/accessibility checks, performance observations, documentation cleanup, and release report. Delete unused presentation code only after reachability/compatibility tests establish it is unused. Retain audit/domain storage.

**Gate:** core build complete under deterministic tests and real local application checks; absent credentials are a documented live-service validation gap, not fake success. Deployment, production migrations, real AI inventory transmission, and live ticket operations need separate owner authorization.

## Later — Explicitly excluded from default execution

T90: group genuinely shared remediation (same owner, artifact/change path, constraints, and destination) into one plan/ticket with linked CVEs. Keep per-target decisions. Design later inside Findings; no Campaigns dashboard and no grouping merely by CVE equality.

## Implementation order within each change

Characterize → implement domain/read mapping → implement UI → test server/events → exercise actual browser → record evidence/limitations → reconcile documentation. Do not adjust fixture expectations only to make broken behavior pass. Small commits are useful when the working-tree policy allows them; pushing is not authorized by this handoff.

## Source boundaries to inspect first

`app/lib/triage_web/live/workspace_live.ex`; `app/lib/triage_web/components/workspace_components.ex`; `app/lib/triage/workspace.ex`; `app/lib/triage/workspace/query.ex`; `app/lib/triage/workspace/commit.ex`; `app/lib/triage/decisions.ex`; routes/redirects; case/exception APIs; stylesheet and actual asset pipeline. Do not invent module names for new functionality before checking existing equivalents.

## Quality commands

The current repository documents `mise x -- mix ci` as a non-rewriting combined gate and an owned-database wrapper for mutation/browser checks. Read current guidance and script help before running commands. From `app/`, documented examples include:

```sh
./scripts/verify_owned_db.sh workspace
./scripts/verify_owned_db.sh precommit
./scripts/verify_owned_db.sh concurrency
node --test test/workspace_hooks_test.cjs test/saved_queue_filters_test.cjs
./scripts/verify_owned_db_test.sh
./scripts/verify_owned_db.sh workspace_browser
```

These are source-baseline examples, not commands executed while preparing this handoff. Inspect whether each still exists and what it mutates. Do not run setup/migrations against an operator's existing database. `mix precommit` may rewrite files; keep it distinct from a read-only check. DB-free tests are not a replacement for database-backed scope/expiry/concurrency verification.
