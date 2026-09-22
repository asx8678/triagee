# Repository evidence and source map

## Baseline and verification scope

The GitHub connector returned current `main` as **`33bc06f2dc46932a69b1e07ea35ffd87b223756a`** during preparation on 22 September 2026. Its commit message is “Simplify workspace UI and improve responsive review workflows.” [Commit](https://github.com/asx8678/triagee/commit/33bc06f2dc46932a69b1e07ea35ffd87b223756a). The preceding source review used this same baseline.

This handoff was prepared from the preceding review, supplied visual artifacts, and the source/documentation reads listed below. The repository application was **not cloned, built, started, migrated, or tested** in this handoff session. No repository files, issues, branches, pull requests, or external services were changed. Artifact validation, where reported in `qa/BUNDLE_VALIDATION.md`, concerns this package only.

The agent must inspect the actual checkout. A pinned baseline identifies evidence; it is not an instruction to reset newer work. Some sources are documentation and may lag code; their claims are not runtime verification.

## Pinned sources

| ID | File | Inspection status | Why it matters |
|---|---|---|---|
| R01 | [README.md](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/README.md) | Freshly read | Current application versus historical architecture; Phoenix, not a new Go stack. |
| R02 | [app/README.md](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/README.md) | Freshly read | Runtime, roles, routes, reference-data boundaries, optional integrations, quality commands. |
| R03 | [app/docs/WORKSPACE.md](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/docs/WORKSPACE.md) | Freshly read | Source map, scoped read/write model, history boundaries, performance limits, retained acceptance gaps and owned-resource commands. |
| R04 | [PTV-Triage-Implementation/AGENTS.md](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/PTV-Triage-Implementation/AGENTS.md) | Freshly read | Older visual/task requirements that conflict with the new information architecture; retained functional safeguards. |
| R05 | [app/docs/REVIEW_ACTIONS.md](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/docs/REVIEW_ACTIONS.md) | Freshly read | Current documented fixed/accepted-risk/ticket workflows and ADO configuration; portions lag current authenticated code. |
| R06 | [app/lib/triage/workspace/commit.ex](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/lib/triage/workspace/commit.ex) | Freshly read, relevant visible sections | Action validation, authenticated save overload, explicit IDs, server evidence binding, durable ticket claims, exclusive workspace expiry, reconciliation boundary. |
| R07 | [app/lib/triage/workspace/query.ex](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/lib/triage/workspace/query.ex) | Freshly read | SQL severity-first ordering, target-local facts, effective decision coverage, 50-CVE OFFSET pagination, reference-data exclusions. |
| R08 | [app/lib/triage_web/live/workspace_live.ex](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/lib/triage_web/live/workspace_live.ex) | Reviewed in the preceding review; rediscover current code | Shared LiveView state, routing, drafts, selection, and previously identified default fixed/prefilled rationale. |
| R09 | [app/lib/triage_web/components/workspace_components.ex](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/lib/triage_web/components/workspace_components.ex) | Reviewed in the preceding review; rediscover current code | Overlapping inventory/review/inspector, table columns, detail/action rendering, scope controls. |
| R10 | [app/lib/triage/workspace.ex](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/lib/triage/workspace.ex) | Reviewed in the preceding review; rediscover current code | CVE-row projection, exact placement targets, application-side priority, evidence/history. |
| R11 | [app/lib/triage/decisions.ex](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/lib/triage/decisions.ex) | Source-map reference; agent must inspect | Chronological effective decision, global/scoped precedence and expiry semantics. |
| R12 | [app/OWNED_DB_VERIFICATION.md](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/OWNED_DB_VERIFICATION.md) | Referenced by freshly read runtime guidance; agent must inspect | Owned disposable database lifecycle, identity checks, cleanup limitations. |
| R13 | [app/lib/triage_web/router.ex](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/lib/triage_web/router.ex) | Source-map reference; agent must inspect | Current routes and LiveView mounts. |
| R14 | [app/lib/triage_web/controllers/workspace_redirect_controller.ex](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/lib/triage_web/controllers/workspace_redirect_controller.ex) | Source-map reference; agent must inspect | Compatibility redirects from older screens. |
| R15 | [app/docs/DOMAIN_API.md](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/docs/DOMAIN_API.md) | Referenced by freshly read workspace guidance; agent must inspect | Retained case/exception/domain APIs; do not assume interchangeability. |
| R16 | [app/docs/UI_UX_REVIEW.md](https://github.com/asx8678/triagee/blob/33bc06f2dc46932a69b1e07ea35ffd87b223756a/app/docs/UI_UX_REVIEW.md) | Visible in the freshly read baseline commit response | Earlier UI changes and historical self-reported test results, not fresh certification. |

## Source-based observations carried into the plan

The current product has already consolidated old routes into a workspace, while retaining Overview, Vulnerabilities, Review, Timeline, and News as everyday destinations in the documented UI. The recommendation is to reduce remaining overlapping surfaces, not pretend all historical URLs are still separate active apps. [R02, R03]

The current SQL default explicitly orders severity before priority, and uses a 50-CVE page with OFFSET. The redesign changes this ordering deliberately and preserves bounded hydration. Full evidence for one CVE can still be large; a 50-row table does not make all reads cheap. [R07, R03]

The current commit module supports more action labels than the simplified three-action UI documentation emphasizes, including investigation and verification requests. Its validation has looser requirements for accepted_risk/fixed/create_ticket than for other work actions. Reuse and harden existing paths rather than blindly adding parallel actions. [R05, R06]

Authenticated web saves authorize the principal and derive the actor from the authenticated user. A separate trusted/legacy overload remains self-declared. Older wording about “Local workspace” in review-actions documentation must not cause the agent to remove current authentication. [R06; compare R02/R05]

The current code creates a durable ticket claim before the remote POST and releases the database transaction first. It preserves unknown outcomes and explicit reconciliation. This is stronger than a simplistic exactly-once claim; it must not be replaced with a client retry button. Live Azure behavior was not tested. [R06]

Current workspace decisions preserve observed evidence and target metadata. Case assessments/exceptions have their own evidence/revision bindings and must not be approximated by advisory decisions. Current workspace metadata identifies an exclusive expiry boundary while older records may retain inclusive behavior. [R06, R07, R03]

## Proposed changes, not current capabilities

Two primary workspaces; the new context-first ranking; typed not-affected workspace assessment; truly verified-remediation outcomes; stronger exception requirements; material-context invalidation extensions; the rich AI schema; shared Grafana projection; the new four-column table. These are targets to implement and test, not features proven present by this handoff.

The primary concept demonstrates appearance with mock data and no persistence. Its scope auto-selection and single-status model are intentionally not the required production semantics. See `concepts/README.md`.

## Existing unresolved acceptance obligations

Workspace guidance says old security items 81–90 cannot be closed without their original findings and evidence. It also records broader migration, legacy-history, accessibility, realistic-load, owned-resource, and live-integration acceptance gaps. Do not assert these are fixed or currently failing merely because they are listed; inspect the applicable evidence. Preserve them in the acceptance mapping until individually resolved. [R03]

Historical test counts in repository documents are attributed historical reports, not tests run here or a certification of the new implementation. [R01, R02, R03, R16]

## Design versus evidence

No external security standard is required to justify a new UI layout. The priority bands, seven-day review window, wording, and proposed schemas are explicit product choices. The implementation should document any changes rather than presenting them as mandated standards. This bundle does not claim VEX conformance, calibrated AI confidence, live deployment exploitability, or current third-party API compatibility.
