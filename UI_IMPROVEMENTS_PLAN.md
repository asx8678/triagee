# UI/UX improvements — round 2 implementation spec

Scope: suggestions #1–#11 and #14 from the reviewed improvement list. Deferred: #12 (search shortcut/autofocus), #13 (per-occurrence case count link), #15 (hover polish), #16 (receipt expiry countdown). UI-only: no backend context/schema/config/dependency changes, no new routes, no invented data, no new external assets. Preserve all safety semantics, bindings, labels' meaning and existing test intent. Keep the dev server (PID 59341, 127.0.0.1:4001) running; hot reload will pick up changes. No git staging/commit, no `.pi` edits, no DB effects by workers, no `mix` aliases/compile by workers (shared `_build` conflicts) — static `elixir`/`node --check` syntax checks only. `mise exec --` is the pinned toolchain.

## Worker's exact model
Workers: `zro/deepseek-v4.1-flash`. Verifier: `hypercharm/kimi-k3`. No substitution.

## Ownership (disjoint — do not edit files outside your list)

### Worker W1 — foundations + Overview + Findings + Activity
Owns: `app/lib/triage_web/components/ui_components.ex`, `app/lib/triage_web/components/core_components.ex`, `app/lib/triage_web/components/layouts.ex`, `app/lib/triage_web/components/layouts/root.html.heex`, `app/priv/static/assets/css/app.css`, `app/priv/static/assets/js/app.js`, `app/lib/triage_web/controllers/page_controller.ex`, `app/lib/triage_web/controllers/page_html/home.html.heex`, `app/lib/triage_web/live/finding_live/index.ex`, `app/lib/triage_web/live/finding_live/show.ex`, `app/lib/triage_web/live/whats_new_live.ex`, `app/test/triage_web/ui_components_test.exs`, `app/test/triage_web/inventory_readability_test.exs` (+ new test files you create under `app/test/triage_web/` with unique names).
Items:
- #1 Severity ramp: make CRITICAL/HIGH/MEDIUM/LOW/unknown visually distinct without relying on color alone (e.g., filled vs outlined vs dashed border, weight) in the shared severity/status badge styles. Text labels unchanged. All badge text/bg/border pairs must keep ≥4.5:1 contrast (compute and record the values in your leaf note).
- #2 Overview: make "Open occurrences" / "Suppressed occurrences" counts real links to `/findings` (and `/findings` with the existing include-suppressed filter param — check `finding_filters.ex` for the exact param name and semantics; do not invent one). Add each recent case's assessment state ("No assessment recorded" / "Assessment recorded") to the Recently opened cases list using existing case data only.
- #4 Activity: merge the two stacked prose blocks (placement-filter warning + observation-time caveat) into ONE compact notice retaining all meaning. Add event-type visual differentiation (e.g., muted treatment for "No longer observed in local inventory", subtle accent edge for first-observed) via new CSS classes; keep record-ID ordering statement.
- #5 Finding detail: breadcrumb becomes "Findings / {CVE ID}". Tighten the identity strip (consistent column gaps, remove the low-value trailing "Occurrence #N" alignment quirk if it wastes space — keep the info, integrate it sensibly).
- #11 Findings: render the "N matching advisories" result count inline in the filter toolbar row instead of a separate line below.
- #14 Activity: show relative time alongside exact timestamps (exact stays primary, e.g. `05 Aug 2026, 06:00 UTC · 5 weeks ago`). Server-side computation; no JS date libs.
- #8 Mobile safety notice: on narrow viewports collapse the environment notice to one compact line with an accessible "Safety details" disclosure (full text still reachable). Desktop unchanged.
- Also add a compact variant of `technical_value/1` (attr e.g. `variant="compact"`) for dense table cells: truncated mono value + inline "Full value" toggle, no large disclosure chrome. W2 will consume it — document the API in your leaf note.
- Update/add tests for everything you change (element/ID-based, per AGENTS.md LiveView test rules).

### Worker W2 — Review Queue + Review Case
Owns: `app/lib/triage_web/live/case_live/index.ex`, `app/lib/triage_web/live/case_live/show.ex`, `app/test/triage_web/case_readability_test.exs` (+ new uniquely-named test files).
Items:
- #3 Case: consolidate the stacked caveat paragraphs in the evidence column into one labeled "Evidence limitations" block — summary line visible, full text in an accessible disclosure. Do NOT hide: package/version, reported fix, stale-snapshot warning, assessment-vs-snapshot state — those stay always visible.
- #7 Queue: simplify the Image column using W1's compact `technical_value` variant (if not yet present when you edit, code against the documented API in `evidence/ui_improvements/leaf-w1.md` if available, else implement with the existing `technical_value/1` and note the switch for the coordinator).
- #10 Case form: visible required markers (*) on all four assessment fields (keep "All four fields are required" semantics truthful), and a sticky save action bar on desktop (position: sticky within the form column; must not cover focused fields; respect reduced-motion; on mobile it stacks normally).
- Preserve every hidden binding input (expected_revision, expected_snapshot_id, idempotency token), DirtyDraft/FocusReturn hooks, confirmation dialogs and stale-revision flows byte-for-byte in behavior. Update/add tests.

### Worker W3 — Imports + Replay + Replay History
Owns: `app/lib/triage_web/live/import_live.ex`, `app/lib/triage_web/live/replay_live.ex`, `app/lib/triage_web/live/replay_history_live.ex`, `app/test/triage_web/tools_readability_test.exs` (+ new uniquely-named test files).
Items:
- #6 Imports/Replay: style the file input to match the design system (button-styled, accessible label intact, keyboard-operable; do not break LiveView uploads — keep the real input functional, hide only visually if at all). Add current-step state to the step indicator (Select file → Preview/Run → Confirm/Review result → Apply/Save): active step emphasized, completed steps marked; purely presentational, driven by existing assigns.
- #9 Replay History: "First page" must be disabled (not just re-navigating) when already on the first page; add each receipt's key counts inline (advisories/changes counts from the existing receipt summary data — inspect the actual receipt struct first; if a count isn't in existing data, omit it and note the limitation).
- Preserve preview/nonce/acknowledgement/apply and run/save boundaries exactly. No passive writes. Update/add tests.

## Coordinator (Main) owns
Integration, `app/test/triage_web/ui_readability_boundary_test.exs` and any other existing test files broken by copy changes, final `mix format`, guarded `./scripts/verify_owned_db.sh target` and `precommit` runs, final CSS additions requested in leaf notes, Kimi verification, closeout report `UI_IMPROVEMENTS_REPORT.md`.

## Rules for all workers
- Read `app/AGENTS.md` fully (chunked) and follow Phoenix 1.8/LiveView rules (no `else if`, class lists `[...]`, `to_form`, element-ID tests, no raw HTML for untrusted text).
- Read the current file before editing; the redesign from round 1 is the baseline — build on it, don't revert it.
- No DB access, no app start/restart, no `mix test`/`mix compile`/`mix format` (shared build), no network. Static syntax checks only (`elixir --check` style via `Code.string_to_quoted` is not available — use `mise exec -- elixir -e 'Code.string_to_quoted!(File.read!("path"))'` only if it doesn't compile the app; otherwise rely on careful editing and the coordinator's compile).
- Keep prose short and truthful; never present missing data as zero/safe/fixed.
- Finish with a brief leaf note at `evidence/ui_improvements/leaf-wN.md`: what changed, class/API contracts added, CSS requests for coordinator, tests added/updated, contrast values computed (#1).
