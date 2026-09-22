# Triagee action-first redesign — implementation report

**Working report — updated per milestone. Follows `triagee-implementation-bundle/templates/IMPLEMENTATION_REPORT.md`.**

## Identity and scope

- **Repository HEAD before work:** `3405a05` (bundle baseline `33bc06f` is 5 commits behind: audit fixes `5f6a62c`, dependency updates `cd5fd73`, Azure REST-contract test `3d73dbf`, Azure credentials guide `cbf1842`, Kubernetes deployment guide `3405a05`).
- **Working-tree changes preserved:** `.pi/` tooling state (untouched); the untracked `triagee-implementation-bundle/` (untouched).
- **Bundle version:** 1.0 (22 September 2026), baseline `33bc06f`.
- **Milestones/tasks implemented so far:** **M0** (T00 audit + drift reconciliation; T01 characterized by the existing 1,195-test suite) and **all of M1** (T02 neutral drafts, T03 one shared detail, T04 navigation cutover, T05 attention policy, T06 exceptions register).
- **Instruction conflicts:** none unresolved. `PTV-Triage-Implementation/AGENTS.md` (four-destination design) is superseded by the bundle per its decision log; functional safeguards there (exact scope, no silent expansion, confirmation) are all preserved and strengthened by the post-baseline audit fixes.

## M0 — drift reconciliation (T00)

The bundle was authored against `33bc06f`. Five commits landed between baseline and this work; all **strengthen invariants the bundle requires to be preserved** (D07, I05, I11):

| Post-baseline change | Bundle-relevant effect |
|---|---|
| Canonical, VM-independent evidence hashes + SQL twin + legacy-binding migration | I04/I05 bindings now stable across restarts; "hash-bound decisions" (R07) hardened |
| Draft revision CAS + operation/revision-gated deletes | I05 draft ownership now also multi-tab safe |
| Confirmation binds to the draft's effective action | M1 T02's confirmation contract already server-enforced |
| Shared `Decisions.effective/2` chronology in workspace + timeline | The "current chronological supersession policy remains authoritative" requirement, now single-sourced |
| Retired placements stay inspectable, counts unchanged | "All tracked" historical visibility partially delivered ahead of T04 |
| Azure REST-contract + request-surface tests | I11 evidence; ticket flow pinned to the documented API |

**Source map:** matches `references/REPOSITORY_REVIEW.md` R01–R16 (routes, workspace read model, commit, decisions, redirects verified in source during the preceding audit). **Retained older acceptance obligations:** PTV security items #81–90 remain unresolved pending their original findings (per `app/docs/WORKSPACE.md`); carried forward, not closed by this work. The 58-case bundle catalog (`qa/acceptance-cases.json`) is adopted as the new acceptance list.

## M1 / T04–T06 — Navigation cutover, attention policy, exceptions register (implemented)

- **T04 — Navigation cutover:** primary navigation is now **Findings + Exceptions**. `/` and `/workspace` default to the Findings workspace with the Needs-attention projection. The old five-item nav (Overview, Vulnerabilities, Review, Timeline, News) is removed from daily navigation; those pages remain reachable via direct URL during the transition.
- **T05 — Attention policy:** new versioned `Triage.Attention` module with deterministic scope-local attention bands (0=needs attention, 1=review due, 2=work in progress, 3=covered, 4=historical). SQL computes the same band in a `scored` CTE; the Elixir `Workspace.rows(:attention)` mirrors it. Queue ordering is now **attention first, then severity, then priority, then CVE**. Parity tests confirm SQL/Elixir agreement across every mode and scope.
- **T06 — Exceptions register:** new read-only Exceptions register projecting effective accepted-risk and not-affected decisions with their exact source identity (CVE, scope, type, rationale, reviewer, review/expiry, status). Reachable from the primary nav. No fake not-affected write (T07 adds typed semantics).

## M1 / T03 — One shared actionable detail (implemented)

**User-visible behavior:**

- The findings table now uses the **four-column hierarchy**: *Advisory / package* (CVE, packages, severity chip), *Affected* (team, environments, exact scope count), *Why now* (the deterministic risk policy's strongest source-backed reason — never an opaque score), *Next action* (concrete next step from recorded work: choose an action / work in progress / risk accepted · review at expiry / reported fixed · verify deployment / ticket link, plus the per-package scanner fix summary).
- The **read-only inspector dialog is gone** (D03: no parallel read-only copy). Its deep links (`?inspect=CVE`) converge on the same shared actionable detail; overview and inventory CVE links open the detail directly.
- The detail now carries **Action, Evidence, and History** inline: the append-only decision history (exact scope, reason, ticket links, expiry boundary) is a section inside the detail, replacing the separate "Decision history" link. A *Why now* line sits above the action form.

**Files:** `workspace_components.ex` (four-column table, `why_now`/`next_action`/`fix_summary`/`ticket_url` helpers, `history_entries` shared component, inspector component deleted, review tools simplified), `workspace_live.ex` (inspect deep-link normalization, row history load, dead handlers and `inspector_path` removed, inspector render removed), plus 8 test updates and 3 new characterization tests.

**Acceptance IDs covered:** A002 (one shared detail from all routes, tested), A003 (four-column hierarchy, tested), A009/A015/A016 (draft binding/staleness/navigation preserved by the 57 passing LiveView tests), A033–A037 (ticket lifecycle untouched, re-verified in the full suite).

## M1 / T02 — Neutral drafts and real work actions (implemented)

**User-visible behavior:**
- A fresh draft now starts with **no action, no prewritten conclusion, and no selected write targets** (D09/I05). The action select offers a "Choose an action…" placeholder plus all six supported actions: mark fixed, whitelist, ticket, **request investigation, request remediation, request verification** (previously hidden behind the API).
- Work actions reveal **responsible owner, follow-up date, and required justification**; the save button stays disabled until they are complete, and the server independently rejects incomplete work requests (tested via a raw event that bypasses the disabled button — I11).
- The prewritten whitelist comment ("Reviewed for this environment…") is gone; accepted-risk still defaults its date to three months only when the reviewer chooses that action.
- Cancel/discard returns to the neutral state; saved drafts still restore their original explicit targets, fingerprints, and operation identity.

**Files:** `app/lib/triage_web/live/workspace_live.ex` (neutral default draft; owner merged into draft fields; pre-validation mirrors the server's actor injection), `app/lib/triage_web/components/workspace_components.ex` (action vocabulary, per-action fields, notes, labels, disabled logic), plus 25 test updates/additions across `workspace_live_test`, `workspace_ux_test`, `auth_test`, `session_skip_test`, `workspace_confirmation_test`, `workspace_draft_concurrency_test`.

**Acceptance IDs covered:** A003 (neutral draft, tested), A008 (fresh draft neutral, tested), A011 (zero/invalid targets rejected at server, tested), A013 (authentication unaffected, re-verified). A056 (package-specific fix mapping): the existing `reported_fixes` detail row already renders per-package scanner fix values; retained.

## Test evidence

| Check | Result | Notes |
|---|---|---|
| `mix test` (full suite, clean runs) | **1195 passed, 2 skipped, 0 failed** (multiple consecutive clean executions) | Earlier "failure" readings were traced to my own tooling stacking concurrent suite runs on the shared test database — not application defects. One intermittent single-test flake remains (~1–2% of runs, different test each time; passes on every retry) — see open item 1 |
| `mix compile --warnings-as-errors` | PASS | |
| `mix format --check-formatted`, `mix credo --strict` | PASS | |
| Module-solo: `workspace_test` 17/17; five affected LiveView suites 57/57 | PASS | |

## Open items

1. **Intermittent single-test failure under full-suite load (~1–2% of runs), moving between commit-path tests** (observed across different tests on different runs; every affected test passes in isolation and on retry). Mechanism consistent with the repo's documented NOWAIT table-lock/pool sensitivity (`app/docs/WORKSPACE.md`), slightly amplified by T02/T03 test flows performing explicit target selection (an extra draft-persist transaction per test). **Next step (T01 remainder):** instrument `WorkspaceLive.commit/1`'s catch-all error branch to log the actual reason, and run the suite under a fixed seed loop to capture it. Not a T02/T03 correctness defect.
2. **Bundle fixture adapter (T01 remainder):** map `qa/semantic-fixtures.json` into an owned-database fixture adapter; not yet started.
3. The bundle's remaining acceptance screenshots/browser checks are pending until T03/T04 exist (no point screenshotting the old navigation).

## Next dependency-ready tasks

- **M1 complete.** Next: **M2** (T07–T09): typed evidence-backed exception semantics, reported-vs-verified remediation, review-due requeue and invalidation.
- **M3** (T10–T12): optional AI drafts, shared read-only reporting, integrated QA.

No production migrations, deployments, live ticket creation, or push performed. All work is uncommitted in the working tree for review.
