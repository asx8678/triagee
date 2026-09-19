# PTV Triage redesign — implementation report (first vertical slice)

## Result

Repository: `/Users/adam2/projects/triagee`; baseline `aba6522`; changes uncommitted.

Implemented opt-in `/workspace`: Overview, scoped vulnerability inventory, shared inspector, one-screen review and local placement-scoped decisions. Existing default route and legacy history/data tools remain. **The complete implementation plan is not yet signed off.** Remaining gates are listed in `APPROVED_WORKSPACE_EXECUTION.md`.

## Real application changes

- `lib/triage/workspace.ex`: shared `(CVE, placement)` scope, metric/queue predicates, priority and scoped history.
- `lib/triage/workspace/commit.ex`: validated atomic commits, exact evidence versions, idempotent operations, frozen evidence and inclusive UTC date boundary.
- `lib/triage/decisions.ex`: additive fields and readable work labels in the existing history store.
- `lib/triage_web/live/workspace_live.ex` and `components/workspace_components.ex`: URL/read state, drafts, selection, inspector, review and confirmation.
- `router.ex`, `components/layouts.ex`, `components/layouts/root.html.heex`, `priv/static/assets/css/workspace.css`, `priv/static/assets/js/app.js`: route seam, isolated styling and native-dialog/draft hooks.
- `priv/repo/migrations/20260919123750_extend_scoped_workspace_decisions.exs`: `work_owner`, `due_on`, `operation_id`, `metadata`, unique operation/placement index. Existing IDs/tables are retained.

Active/needs/urgent metrics count distinct CVEs; unknown-exposure counts affected targets. Team totals are not additive across shared CVEs. The same selector returns the drilldown's contributing targets. Suppression is not acceptance; disappearance is not verification. Work actions are remediation, investigation, temporary risk acceptance and verification request. All remain local and do not claim authenticated approval or verified remediation.

## Proof of the end-to-end workflow

- LiveView/domain tests verify Overview/team scope → review/inspector, exact selection, unchanged active exposure, staging still unresolved after production-only save, cancelled acceptance, draft restoration, validation/conflict and commit-before-advance.
- Browser probe verifies four inspector tabs, expansion, Escape and focus return; cancellation keeps typed fields; production-only remediation changes placement 1 while placement 2 still needs a decision; reload sees the durable result.
- A local save has no external adapter path; tests assert no `GuidedReview.Request` was created and no inventory observation/suppression state changed. No external integration success is claimed.
- The inspector provides scoped decision history; complete timeline/history parity remains outstanding.

## Quality results

| Check | Actual result / evidence |
|---|---|
| Full `mix precommit` (independent final verification) | 1040 passed, 2 skipped, zero failures; `/tmp/triage-workspace-review-precommit.log` |
| Final affected suite including review fixes | 60 passed; `/tmp/triage-workspace-review-fixes.log` |
| Strict Credo | No issues in 219 source files; `/tmp/triage-workspace-review-credo.log` |
| JS hooks / saved filters | 8 passed; `node --test test/workspace_hooks_test.cjs test/saved_queue_filters_test.cjs` |
| Owned-DB guard tests | Passed; `scripts/verify_owned_db_test.sh` |
| Package integrity | All 173 listed hashes pass; `/tmp/triage-workspace-review-package-integrity.log` |
| Application browser subset | 13 review viewports passed; `evidence/approved-workspace/geometry.json` |
| Inspector / local-save interactions | Passed; `evidence/approved-workspace/interactions.json` |
| Overview | Desktop/mobile no page overflow; `evidence/approved-workspace/overview-checks.json` |

Browser: headless Chrome 153.0.8010.48, macOS, scale factor 1. Review sizes include 1600×1000, 1920×1080, 1366×768, 1280×720, 1750/1749, 1151/1150, 851/850, 641/640 and 390×844. Desktop shell measures 52 px topbar / 46 px scopebar; inspector measures 780 px and 1240 px expanded. Long content is in scroll bodies, with persistent actions hit-tested.

Screenshots are under `evidence/approved-workspace/` (ignored local QA artifacts): `legacy-before-1600.png`, `overview-1600.png`, `overview-390.png`, `review-1600.png`, `review-scrolled-*.png`, `inspector-*-1600.png`, `acceptance-preview-1600.png`.

**Catalog sign-off:** 0/90 formally mapped and 0/32 canonical visual cases captured; the tested subset is separate real-application evidence, not a substitute for these gates. No pixel tolerance, overlay approval, real zoom, full accessibility or production-scale performance claim. Reference inspection/checksums are not counted as application tests.

Verification found and fixed serialized dirty-state handling, Save unexpectedly advancing a default-selected CVE, JSON replay normalization and CSS scoping/confirmation centering. A repeat browser probe initially assumed pristine target selection; the probe now explicitly reconciles it. One headless tab stalled on native draft-discard confirmation; final probes completed in a fresh QA tab. No passing claim relies on that stalled run.

## Independent follow-up verification and fixes

Reviewed the actual workspace after the implementation handoff, not just its summary. Two gaps were fixed:

- `Decisions.covering_decision/3` is now the shared chronological scoped/global reader. Legacy triage and guided review cannot mask a newer scoped decision with an older global acceptance, or resurrect that acceptance when scoped work expires. Regression tests cover legacy/new readers, unaffected siblings and same-second ID ordering.
- Draft dirty state now includes target-only and action-only changes. The browser guard protects input before server acknowledgement, permits only actual LiveView patches without a leave warning, and clears client dirty state only after explicit successful save/discard without newer input. Saving another CVE does not erase a dirty draft. This is **loss prevention, not durable draft storage**.

Final browser verification used a fresh owned database and isolated headless Chrome **153.0.8010.12**, macOS, DPR 1. Artifacts:

- `evidence/approved-workspace/review-check/interactions.json` — four inspector tabs, 780/1240px widths, Escape/focus return, risk-acceptance cancellation, production-only save, staging still needing a decision, reload persistence.
- `evidence/approved-workspace/review-check/geometry.json` — 13/13 review viewport checks, both save actions hit-tested after scroll, no document overflow.
- `evidence/approved-workspace/review-check/draft-guard.json` — target-only warning, cancelled real leave, confirmed discard and unacknowledged offline-input warning. No decision submitted by this probe.
- `evidence/approved-workspace/review-check/review-scrolled-1600.png` and `evidence/approved-workspace/review-check/review-scrolled-390.png` — final desktop/mobile review captures.

The first combined browser command timed out after producing successful interaction evidence, while the headless geometry readiness wait was suspended. After explicitly bringing the QA tab forward, the bounded geometry command passed 13/13. No application test failed. The graph/structural-review extension actions were unavailable in the continuation runtime; source readers/call sites and regression tests were inspected directly instead.

These checks do not waive the outstanding full-plan gates below or justify default-route cutover. Existing databases still need the additive migration before running code that reads the extended decision schema; only generated disposable databases were migrated during verification.

## Reproduce safely

From `app/`, with the pinned mise toolchain and PostgreSQL CLI available:

```sh
./scripts/verify_owned_db.sh workspace
./scripts/verify_owned_db.sh precommit
mise x -- mix credo --strict
node --test test/workspace_hooks_test.cjs test/saved_queue_filters_test.cjs
./scripts/verify_owned_db_test.sh
./scripts/verify_owned_db.sh workspace_browser
```

The browser command creates/migrates an owned empty test database and prints its loopback URL. It refuses existing/populated databases and exits after ten minutes, dropping only its generated database. If local cached BEAM files are incompatible, set `MIX_BUILD_PATH` to a new temporary directory; do not delete the user's build. Our commands used `/private/tmp/triage-workspace-build` and the PostgreSQL 18 CLI on PATH.

Connect `browser-harness-js` to an owned debugging browser and fresh tab. Set `globalThis.workspaceFixtureOrigin` to the printed origin and `globalThis.workspaceEvidenceDir` to an absolute output directory. Navigate to that origin, then run from the repository root:

```sh
browser-harness-js "$(cat app/scripts/workspace_interactions.js)"
browser-harness-js "$(cat app/scripts/workspace_geometry.js)"
browser-harness-js "$(cat app/scripts/workspace_draft_guard.js)"
```

The interaction probe writes **only the owned synthetic fixture**. The geometry probe only resizes/scrolls. The draft-guard probe edits/discards uncommitted synthetic drafts, cancels an attempted leave, and temporarily disconnects/reconnects its own LiveSocket. Never point these probes at real inventory. Bring the QA tab to the foreground before geometry checks so animation-frame readiness is not suspended.

## Delivery and rollback

The default route is unchanged; `/workspace` is opt-in. No existing development/production dataset was altered, no remote operation was invoked and approved package inputs are checksum-identical. Disposable test migrations/cleanup passed, but a representative legacy migration/rollback rehearsal has **not** been performed.

Do not run a destructive schema rollback after new decisions exist. Keep the extended schema/readers and preserve work rows when withdrawing the UI. Complete the history reconciliation and remaining A–I acceptance gates before default-route cutover or production migration. Unrelated user changes in `.DS_Store`, `.pi/*`, the provided package and `tmp/dev-server.log` are left untouched.
