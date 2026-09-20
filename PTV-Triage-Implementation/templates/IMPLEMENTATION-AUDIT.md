# Implementation audit — fill using the actual repository

Status: NOT STARTED. Template entries are not findings.

## Repository and baseline

Repository root/commit: __
Existing working-tree changes to preserve: __
Framework, exact installed versions, lockfile: __
Run/build/test commands from repository instructions: __
Before screenshot directory: __
Existing test results and pre-existing failures: __
Current local/authentication/identity mode: __
Feature-flag or reversible route seam: __

## Route/component mapping

| Current route/view | Actual files | Target destination/component | Compatibility behavior |
|---|---|---|---|
| Root/landing | __ | Overview | __ |
| Vulnerability inventory | __ | InventoryTable | __ |
| CVE/occurrence detail | __ | Shared CveInspector / full detail | __ |
| Action queue | __ | ReviewQueue | __ |
| Four wizard steps | __ | Evidence + ScopeSelection + DecisionForm | __ |
| Previous/saved assessments | __ | Decision history | __ |
| Timeline/tracks | __ | Tracks / Event log / Daily activity | __ |
| Data tools/settings | __ | Data & settings | __ |

## Entity and state dictionary

For each: actual table/module/type, stable key, source of truth, possible states, evidence/provenance fields, missing/unknown behavior, and migration need.

Advisory/aliases: __
Package occurrence/immutable image identity: __
Deployment/placement/team/environment: __
Assessment target scope: __
Observation/run/coverage/completeness: __
Suppression/source attribution: __
Decision/work/owner/exception/expiry: __
Verification evidence: __
Intelligence cache/source freshness: __
External ticket linkage/submission state: __

## Metric and field map

| UI metric/field | Actual query/source | Unit | Scope predicate | Freshness/unknown behavior | Test |
|---|---|---|---|---|---|
| Active CVEs | __ | distinct CVEs | __ | __ | __ |
| Need a decision | __ | distinct CVEs + explicit work scopes | __ | __ | __ |
| Immediate priority | __ | distinct CVEs from scoped policy | __ | __ | __ |
| Exposure unknown | __ | deployment scopes | __ | __ | __ |
| Team counts | __ | distinct per team | __ | __ | __ |
| First/last observation | __ | timestamp + entity scope | __ | __ | __ |

## Action mapping

Map all45 reference click actions and16 inputs from `contracts/reference-actions.json`. Include actual route/handler, read/local commit/export/external class, validation, target set, persistence, error path and test IDs. Mark demo-only actions explicitly excluded; do not leave enabled stubs.

## Trace evidence

Two-environment advisory trace: __
Suppressed-with-unknown-attribution trace: __
Disappearance-without-verification trace: __
Draft/URL/scroll-loss points: __
Current inbound/outbound boundaries: __
Legacy/new assessment-store differences: __

## Plan and risks

Minimal vertical slice: __
Required additive model changes: __
Migration and reconciliation method: __
Rollback including new writes: __
Genuine blockers requiring decision: __
Approved visual deviations, if any: __

Gate A verdict with evidence: __
