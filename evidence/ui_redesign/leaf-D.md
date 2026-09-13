# Leaf D — implemented

Read OWNERSHIP first, then the entire brief and app/AGENTS.md in chunks. Source edits began only after reading BASELINE_READY. Disjoint ownership preserved.

## Files
- `app/lib/triage_web/live/import_live.ex`: select → preview → explicit acknowledgement/apply → result; proposed/applied semantic tables, file-provided provenance disclosure, exact fingerprint copy, pending labels and keyboard focus. Nonce, stale-preview and strict payload guards retained.
- `app/lib/triage_web/live/replay_live.ex`: select → run in memory → inspect result → optional explicit save. Neutral evidence labels, safe projected counts/diagnostics, digest disclosure, actual local save/expiry timestamps. Existing execution/save/idempotency boundaries retained.
- `app/lib/triage_web/live/replay_history_live.ex`: passive ascending-ID receipt browser, honest page counts/error/empty states, visible outcomes/save times, native receipt disclosures and unique copy IDs. No rerun/save controls or automatic refresh.
- `app/test/triage_web/tools_readability_test.exs`: six regressions covering step transitions and no passive writes; escaped/missing provenance; acknowledgement/cancel/reload boundaries; exact receipt timestamps/copy values; history pagination and recovery; unavailable telemetry; focus wiring.

## Verification / handoff
Static checks confirmed routes, imported shared components, preserved public `safe_summary/1`, `safe_digest/1`, `summary_panel/1` (optional `id`), strict nonce/ack guards, one explicit apply/run/save call site each, history-only list access, unique summary IDs, and no raw HTML/inline styles/ignored form DOM.

No DB, tests, app, browser, aliases, formatting, git mutations or cross-owner source writes executed. Runtime success and accessibility conformance are **not claimed**.

Coordinator: targeted-format the four files above, then from `app/` run:
`mix test test/triage_web/tools_readability_test.exs test/triage_web/live/import_live_test.exs test/triage_web/live/replay_live_test.exs test/triage_web/live/replay_history_live_test.exs`

Browser follow-up: keyboard preview/confirmation/result focus and cancel return; exact copy; import acknowledgement; run versus save; history/reload no writes; mobile/320px reflow. Screenshots/integration remain coordinator-owned.

## Shared contracts / limits
Only A's shared components/CSS and CopyValue hook used; built-in Phoenix JS handles focus. No outstanding CSS/JS requests. Import generation time is explicitly file-provided, not verified provenance; no invented import save timestamp or job telemetry. Unsaved replay results remain session-only and are explicitly described as discarded on reload/replacement.
