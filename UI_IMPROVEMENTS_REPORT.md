# UI/UX round-2 improvements — closeout

Date: 2026-09-12. Scope: items #1–#11 and #14 from the reviewed suggestion list (`UI_IMPROVEMENTS_PLAN.md`). Deferred: #12, #13, #15, #16.

## Orchestration
Three parallel `zro/deepseek-v4.1-flash` workers (W1 foundations/Overview/Findings/Activity, W2 Case/Queue, W3 Imports/Replay/History), disjoint file ownership, all completed exit 0. Coordinator (Main) integrated the compact `technical_value` switch and worker CSS requests, ran format and both guarded suites. Independent verifier: `hypercharm/kimi-k3` — verdict **PASS** on all 12 items with safety-boundary checks (`evidence/ui_improvements/KIMI_REVIEW.md`); contrast claims recomputed exactly (7.73–9.16:1).

## Implemented
- #1 Severity ramp: distinct fill + border style/weight per level (solid-bold/solid/dashed/dotted/neutral), labels unchanged, contrast ≥7.7:1.
- #2 Overview: open/suppressed counts are deep links to `/findings` (suppressed uses the real `suppressed=1` param); recent cases show assessment state + revalidation qualifier from existing queue data.
- #3 Case: caveats consolidated into "Evidence limitations" (summary + disclosure); package/version, reported fix, stale/out-of-scope/missing notices stay visible.
- #4 Activity: one merged notice; appeared/resolved event styling; record-ID ordering statement kept.
- #5 Finding detail: breadcrumb carries the CVE ID; identity strip tightened.
- #6 Imports/Replay: branded `::file-selector-button` with the real labelled input intact; step indicators get complete/current/upcoming states + `aria-current`.
- #7 Queue image cells use compact `technical_value` (truncated mono + inline Full value/copy).
- #8 Mobile safety notice collapses to one line under 760px; full text still reachable.
- #9 Replay History: First page is a real disabled button at cursor 0; inline receipt counts (Owners/Images/Findings/Suppressed) from persisted summary only — no advisories/changes counts exist in the data, documented.
- #10 Required `*` markers + `required` attrs on all four assessment fields; sticky desktop save bar (static on mobile/reduced-motion, scroll-margin keeps fields clear).
- #11 Findings result count lives inside the filter toolbar.
- #14 Activity shows server-side relative time next to exact UTC (`relative_time/1,2`, injectable clock).

## Verification
- `mix format` + `node --check app.js`: PASS.
- Guarded `verify_owned_db.sh target`: **90 passed**, owned DB dropped.
- Guarded `verify_owned_db.sh precommit` (compile --warnings-as-errors + format + assets + full suite): **541 passed, 2 skipped** (14 new tests), owned DB dropped. The 2 skips are the opt-in concurrency tests (previously passed separately under their exact guard; unchanged code).
- Kimi source + served-HTML verification: all items PASS; hidden revision/snapshot/idempotency bindings, DirtyDraft/FocusReturn hooks, confirmations, preview/apply and run/save boundaries intact; no new routes/deps/raw-HTML.
- Fresh owned headless-Chrome captures against the live dev app (read-only): `evidence/ui_improvements/round2-{overview,case,queue,activity}-1440x900.png`, visually inspected. Browser/profile/daemon cleaned up.
- Dev server (PID 59341, 127.0.0.1:4001) hot-reloaded; all 7 top-level routes HTTP 200. No restarts, no dev-DB writes, no git staging/commits.

## Limitations
- No new full browser-interaction matrix (keyboard/zoom/reflow) was rerun for round 2; round-1 matrix remains valid for unchanged shell mechanics. New CSS was verified in rendered screenshots and source only.
- W1 note: expanding Safety details on desktop repeats the one-line caveat that the mobile-collapsed span hides (cosmetic).
- `app/` remains untracked; preservation verified by content inspection, not git diff.
