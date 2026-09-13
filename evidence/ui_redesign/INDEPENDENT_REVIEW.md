# Independent Triage UI review

## Verdict: PASS WITH LIMITATIONS

Reviewed final source, not coordinator assertions, against all 489 lines of `UI_REDESIGN_BRIEF.md` and the complete `app/AGENTS.md`. One confirmed P2 defect was reported, fixed by the coordinator, and directly reverified. **No unresolved source defect requiring integration changes was confirmed.** This is not a WCAG conformance certification.

Reviewer writes were confined to this report and `reviewer/**`. No source edits, git mutations, agents/worktrees, dependency/config changes, DB commands, tests, application starts/restarts, assessment saves, evidence refreshes, imports, or replay execution/saves were performed by this reviewer. Browser use was exclusively the owned Chrome through private CDP port 19841, recording off, at `http://localhost:4017`.

## Confirmed finding — resolved

**P2: unknown valid display scopes silently became “All” on unrelated filter changes.** Findings and Activity originally omitted a selected URL value from their native select options. On `/findings?owner=ghost-team&environment=ghost-env`, the controls said “All” while the summary said ghost-team/ghost-env; typing `busybox` then removed both scopes. Changing Activity's environment similarly removed the unknown owner. This was a real navigation/scope defect, not a cosmetic preference.

- Affected/fixed call sites: `app/lib/triage_web/live/finding_live/index.ex:148,155`; `app/lib/triage_web/live/whats_new_live.ex:204,211`.
- Coordinator correction: `app/lib/triage_web/components/ui_components.ex:6` (`display_scope_options/3`); rendered-form regressions at `app/test/triage_web/inventory_readability_test.exs:15,26`.
- Direct original reproduction: `reviewer/scope-results.json`, `reviewer/findings-unknown-scope.png`, `reviewer/activity-unknown-scope.png`.
- Direct post-restart verification: `reviewer/scope-fixed-results.json`, `reviewer/findings-unknown-scope-fixed.png`, `reviewer/activity-unknown-scope-fixed.png`. Unknown values now remain selected; unrelated changes retain them and results remain correctly empty. Screenshots were read, not merely captured.

## Direct rendered verification

All paths below are relative to `evidence/ui_redesign/`.

| Route | Independently captured and visually read screenshots |
|---|---|
| `/` | `reviewer/overview-1366.png`, `reviewer/overview-320.png` |
| `/findings` | `reviewer/findings-1366.png`, `reviewer/findings-320.png` |
| `/findings/1` | `reviewer/finding-1366.png`, `reviewer/finding-320.png` |
| `/cases` | `reviewer/queue-1366.png`, `reviewer/queue-320.png` |
| `/cases/1` | `reviewer/case-1366.png`, `reviewer/case-320.png` |
| `/whats-new` | `reviewer/activity-1366.png`, `reviewer/activity-320.png` |
| `/imports` | `reviewer/imports-1366.png`, `reviewer/imports-320.png` |
| `/replay` | `reviewer/replay-1366.png`, `reviewer/replay-320.png` |
| `/replay/history` | `reviewer/history-1366.png`, `reviewer/history-320.png` |

`reviewer/routes-results.json` records 18 route/viewport checks at 1366×768 and 320×768. All eight LiveView routes were connected; Overview is a controller page, not a failed LiveView connection. No document overflow occurred. **Every mobile navigation menu remained collapsed after connected mount.** At desktop, case1's form began at y=419.73 and its first select ended at y=529.73, leaving identity, saved scope, evidence context and assessment visible above the fold.

Additional direct probes:

- **Keyboard/draft protection:** `reviewer/draft-results.json`. Tab/Enter/letter keys selected Unknown, Insufficient context and Investigation; synthetic rationale was entered. Reload retained all text and the original case1 revision2/snapshot1/token. Refresh confirmation was canceled and focus returned. Native dirty-navigation and save confirmations were canceled. **“Yes, discard draft” was explicitly activated**, fields cleared, and clean navigation succeeded. No assessment or snapshot was written.
- **320px copy/navigation/form:** `reviewer/final-results.json`. Mobile Navigation opened by keyboard, Tab entered its links, Escape collapsed it and returned focus. The 351-character synthetic image reference copied byte-for-character as the original string, with visible feedback. Copy and applicability controls were fully within the viewport. Read screenshots: `reviewer/case4-long-copy-320.png`, `reviewer/case4-mobile-form.png`.
- **200% text plus spacing:** `reviewer/zoom-keyboard-results.json`. All four fields were keyboard-reachable and editable; each focused control was visible. Native save confirmation was canceled with unchanged focus and scroll position; the second synthetic draft was explicitly discarded. Read `reviewer/case4-text200-spacing.png` and `reviewer/zoom-save-cancel.png`. The layout is narrow and wraps heavily under this combined stress, but the tested form remained operable without page overflow.
- **Context and semantics:** queue → case → queue retained team, environment and before=5; Activity → finding → Activity retained team, environment and before=9. Finding detail retained search and include-suppressed context. URL owner=beta did not relabel case1's saved alpha scope and produced the mismatch warning. Scoped busybox search still showed both affected packages/occurrences, rather than hiding the unmatched package.
- **Truthful states:** case2 explicitly says its fix is not reported; case3 shows its already-refreshed snapshot2 without claiming an assessment; case4 clearly says its assessment belongs to an older snapshot. Missing case, filtered-empty inventory, invalid Activity cursor and invalid history cursor were distinct, with recovery wording. History's existing synthetic receipt expands without rerunning anything (`reviewer/history-expanded.png`).
- Additional case4 layout checks at widths 1440, 1920, 768 and 390 had no document overflow. The final confirmed browser state is clean `/replay/history`, 1366×768, `dirty:false` (`reviewer/browser-final-state.log`).

## Source review conclusions

Inspected all nine route implementations, shared `layouts.ex`, `ui_components.ex`, `core_components.ex`, root template, `app.css`, `app.js`, router/import registration, and the relevant Inventory/Activity/Cases query and state paths.

- Inventory totals are authoritative global occurrence counts; advisory rows use distinct scoped SQL aggregates and the actual severity/image/CVE ordering. Package search preserves whole advisory groups.
- Activity uses descending event record IDs, separates recorded facts from joined current metadata, and retains recorded-placement-versus-event-ownership warnings. Disappearance is not presented as remediation.
- Case identity/scope comes from the saved case and displayed evidence from immutable snapshots. Dirty reload/refresh keeps original revision, snapshot and token; explicit rebind verifies the displayed revision again. Recovery/invalid-route/late-retry safeguards have focused regression coverage. Server revision/hash checks remain in the unchanged context.
- Imports retain preview/nonce/acknowledgement/apply boundaries; Replay retains separate run and explicit summary save; History only reads. Mount/navigation paths do not invoke those mutations. Missing replay telemetry is “Unavailable,” not zero. Untrusted scanner/source text is escaped HEEx text, not raw HTML.
- Runtime safety wording is grounded in listener/build configuration and does not call a writable workspace “read-only.” Routes, same-origin scripts, shared component import and CopyValue/DirtyDraft/FocusReturn registrations were mechanically confirmed.
- Final source hashes are recorded in `reviewer/REVIEWED_SOURCE.sha256`; **50/50 protected baseline hashes passed**, including backend/config/dependencies/migrations/logo (`reviewer/protected-final-check.log`). Pure `node --check app/priv/static/assets/js/app.js` passed.

## Assessed test and behavioral evidence (not reviewer executions)

- Latest applicable full guarded suite: `precommit-reviewed.log` — **527 passed, 2 skipped**, guard exit0.
- Correction-specific guarded suite: `reviewer-fix-target-2.log` — **9 passed**.
- Earlier broad target: `target-1.log` — **90 passed**. Separate guarded concurrency: `concurrency.log` — **2 passed**.
- Read the case binding regression implementations, including conflict/rebind race, refresh retention, late exact retry, invalid recovery, detached draft and explicit discard checks. The earlier `precommit-final.log` ended 525 passed/2 skipped before the two correction tests; it is superseded, not the final count.
- `reflow-final.log` / `reflow-results.json`: 45 prior route/matrix checks, no reported overflow/disconnection. `contrast.log` / `contrast-results.json`: seven sampled routes, no reported text failures or undersized sampled input/button controls. These reports are supplemental, not accessibility certification.
- Inspected keyboard, state, navigation, copy, reconnect and import/replay stage logs. Compared recorded fingerprints: browse unchanged; preview and unacknowledged import unchanged; explicit synthetic import added an image; in-memory replay unchanged; explicit summary save added one receipt; history browsing unchanged. Early failures remain in evidence and are not counted as passes.

## Limitations / evidence gaps

1. Reviewer did not execute DB-backed tests or mutations. Changed-source refresh, concurrent/recovered draft binding, successful save, import apply and replay save are supported by inspected source/tests and coordinator evidence, not independently repeated writes. A final coordinator-only fingerprint comparison after reviewer activity was requested; no reviewer DB claim substitutes for that check.
2. Before screenshots used rejected `127.0.0.1` socket origin and are SSR-only. Matched before/after comparisons precede later synthetic state fixtures and final polish. They establish visual comparison, not before-state interaction success. Independent current captures used connected `localhost:4017`.
3. Text enlargement was CSS root-font 200% plus prescribed text-spacing overrides, with separate 320px reflow—not an exhaustive browser-zoom/device/assistive-technology matrix. Native selected-value text can truncate in the narrow enlarged form. Screen readers, other browser engines, all error/hover/focus contrast combinations and all target-size exceptions were not exhaustively exercised.
4. Same-document Back/Forward protection depends on a cancelable Navigation API (`app/priv/static/assets/js/app.js:52–65`); unsupported browsers remain a known limitation. Full-document unload and clicked-link guards are present; no durable draft storage was added.
5. An extra horizontal keyboard-scroll probe could focus the named table region but did not produce scrolling through injected arrow events; a follow-up CDP wheel call timed out. Native select arrow probes also failed while letter-key selection worked. This is **unconfirmed browser/harness behavior**, not a demonstrated source defect or a passing keyboard-table claim. Failures are retained in `reviewer/safe-table-probe.log` and `reviewer/safe-table-wheel.log`. Table containment, semantic region/tabindex and absence of page overflow were verified; physical-keyboard horizontal scrolling remains an explicit gap.

Browser/daemon/profile/server were not stopped. Both reviewer-created drafts were explicitly discarded; no dirty draft was abandoned.
