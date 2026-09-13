# Leaf B — Case workspace + Review Queue

Implemented after reading `BASELINE_READY`; exact B ownership only.

- `app/lib/triage_web/live/case_live/show.ex`: summary / assessment / details DOM; shared 60/40 workspace, saved scope and snapshot context, neutral evidence + assessment relevance, UTC timestamps, exact copy disclosures, readable append-only history, field help/validation, explicit local-save language.
- `app/lib/triage_web/live/case_live/index.ex`: semantic shared-heading table, page-only count, actual case-ID descending order, separate evidence/assessment fields, saved-snapshot relevance, validated nested queue filter/cursor return context (never case scope).
- `app/test/triage_web/case_readability_test.exs`: 16 regressions. Updated dedicated `live/case_live_test.exs` and `live/case_live_index_test.exs` presentation expectations; retained safety assertions.

## Binding trace / safeguards
`Cases.submit_review/5` validates, locks case, checks exact idempotent replay before revision/snapshot/source-hash checks, then appends review/event and bumps revision atomically. `refresh_evidence/3` appends only changed captures. Existing UI reload/recapture retained text but silently changed hidden binding; fixed.

Dirty reload, same-case patches and confirmed recapture retain all fields + original revision/snapshot/token. Explicit reviewed-evidence rebind checks for an intervening revision and rotates the token without saving. Late retries preserve newer drafts. LiveView recovery restores original checked metadata; unverified recovery blocks saves. Invalid-route patches fail closed but retain a detached session-only draft; return restores exact identity and any rebind restriction. Refresh/rebind/discard confirmed events require an opened confirmation. Discard is explicit. No backend/schema changes.

## Verification / integration handoff
Static ledger passed: summary/form/details order; four hidden binding inputs; DirtyDraft + auto-recovery; confirmation handlers; semantic queue stream; validated queue return; no inline style. `git diff --check --` owned files passed.

No tests, app, DB, browser, aliases or format executed by leaf (coordinator ownership). Coordinator: targeted-format the five owned Elixir files; run `test/triage_web/case_readability_test.exs`, `test/triage_web/live/case_live_test.exs`, `test/triage_web/live/case_live_index_test.exs`. Probe dirty navigation cancel/confirm, browser back, reconnect, save + late retry, refresh/rebind conflicts, copy exact values, keyboard focus and 1366×768/320px reflow. No runtime/visual/accessibility pass claimed.

Shared A APIs/classes used as frozen; no cross-owner CSS/JS writes. DirtyDraft covers `#review-form` and detached guard; `draft-saved` only clears after successful save/explicit discard. `#return-to-draft` has `data-draft-preserving=true`. Transient confirmations use FocusReturn. A notes unsupported Navigation API same-document history as remaining browser limitation; no history trap or browser storage. Draft retention is session-only, not durable across a closed/reloaded browser.
