# Triage UI/UX redesign — implementation report

## Delivered
All nine existing routes are implemented in Phoenix/LiveView; URLs, Triage name and logo are unchanged. Four exact `openai-codex/gpt-6-astra` implementation leaves ran with high thinking, nonrecursive, shared cwd and no worktrees; all were awaited. Coordinator integrated and tested their work. Ownership and model handles: `evidence/ui_redesign/OWNERSHIP.md`, `BASELINE.md`, `leaf-A.md`–`leaf-D.md`.

### Important implementation files
- Shell, runtime-grounded safety notice, grouped desktop/mobile navigation: `app/lib/triage_web/components/layouts.ex`, `layouts/root.html.heex`.
- Shared `UIComponents.page_header/1`, `status_badge/1`, `technical_value/1`, `timestamp/1`, `notice/1`, `empty_state/1`, `display_scope_options/3`; registration in `app/lib/triage_web.ex`; accessible inputs/errors/tables in `components/core_components.ex`.
- Tokens/responsive layouts: `app/priv/static/assets/css/app.css`. Same-origin client hooks `CopyValue`, `DirtyDraft`, `FocusReturn`, mobile disclosure and connectivity feedback: `app/priv/static/assets/js/app.js` plus layout LiveView JS.
- Overview: `controllers/page_controller.ex`, `controllers/page_html/home.html.heex` — working `q` search, queue entry, authoritative occurrence counts, recent saved cases, no invented totals.
- Findings index/detail and Activity: `live/finding_live/{index,show}.ex`, `live/whats_new_live.ex` — aggregate units, scope/search semantics, return context, current inventory versus saved evidence, recorded facts versus current metadata.
- Review Queue/Case: `live/case_live/{index,show}.ex` — shared-heading queue; summary/form/details workspace; separate evidence/assessment states; original hidden revision/snapshot/token retained across dirty reload, refresh, recovery and conflict; explicit reviewed-evidence rebind/discard; local append-only save.
- Imports/Replay/History: `live/{import_live,replay_live,replay_history_live}.ex` — explicit select/preview/confirm/apply and run/result/optional-save stages, safe provenance, unavailable values and passive history.
- Five new regression files in `app/test/triage_web/`: `ui_components_test.exs`, `case_readability_test.exs`, `inventory_readability_test.exs`, `tools_readability_test.exs`, `ui_readability_boundary_test.exs`. Existing dedicated case/activity and shared navigation/home tests updated without removing safety assertions.

## Verification
Commands ran from `app/` with the pinned `mise exec --` toolchain. PostgreSQL CLI PATH was `/opt/homebrew/opt/postgresql@18/bin`. Each DB wrapper verified absent generated identity, exact configuration/current_database, and exact non-force cleanup.

| Check | Final result | Evidence under `evidence/ui_redesign/` |
|---|---|---|
| Existing fail-closed guard self-test | PASS | `guard-selftest.log` |
| `./scripts/verify_owned_db.sh target` | 90 passed | `target-1.log` |
| `./scripts/verify_owned_db.sh precommit` | **527 passed, 2 skipped**; compile warnings-as-errors, format, pinned assets, tests passed | `precommit-reviewed.log` |
| Reviewer-found unknown-scope regression | 9 focused tests passed; independent browser recheck preserved both scopes during unrelated changes | `reviewer-fix-target-2.log`, `reviewer/scope-fixed-results.json` |
| `./scripts/verify_owned_db.sh concurrency` | The 2 separately opted-in concurrency tests passed | `concurrency.log` |
| `mise exec -- mix format --check-formatted`; `node --check priv/static/assets/js/app.js` | PASS | `format-final.log`; coordinator tool result |
| Nine-route read-only mount/filter fingerprints and immutable case scope | PASS | `app/test/triage_web/ui_readability_boundary_test.exs`; full suite |
| Real keyboard review, skip link, dirty navigation cancel, confirmed save, focus retained, revision advanced | PASS | `keyboard-review-results.json`, `keyboard_review.js` |
| Browser Back cancel, Overview search and aggregate/deep-link context | PASS | `navigation-results.json`, `navigation_probe.js` |
| Dirty refresh keeps old binding/text; explicit rebind rotates token; confirmation focus/return | PASS | `state-browser-results.json`, `state_browser.js` |
| Actual file import preview and missing acknowledgement write nothing; explicit apply preserves human case records | PASS | `import-preview.log`, `import-validation.log`, `import-apply-2.log`, `db-*.txt` |
| Actual replay run writes nothing; explicit save changes only replay receipts; history reload does not rerun/save | PASS | `replay-run.log`, `replay-save.log`, `history-probe.json`, `db-*.txt` |
| Exact long-value clipboard copy; mobile disclosure/Escape/form keyboard focus; connection interruption/recovery | PASS | `copy-probe.log`, `mobile-keyboard.log`, `connection-probe.log` |
| Nine routes at 1366×768, 1440×900; 1920×1080, 768×1024, 390×844, 320×800, 200% text plus spacing | PASS for rendered probes; no page-level overflow in final 45-check matrix | `final-rendered.json`, `reflow-results.json`, `reflow-final.log` |
| Case form begins above fold at 1366×768 | PASS; measured form top ≈420px | browser probe; `final/case-1366x768.png` |
| Contrast and targets | 754 sampled text nodes: minimum 5.57:1, no sampled failures; input border 3.91:1, focus 6.98:1, navigation focus 9.60:1; no sampled controls below 24×24 | `contrast-results.json`, `contrast-summary.json` |
| Protected sources/logo/config/dependencies and index entries | PASS: 50 protected hashes equal; index entries identical; no source removed | `SOURCE.before.sha256`, `SOURCE.final.sha256`, `PROTECTED.before.sha256`, `protected-final.log`, `reviewed-source-check.log`, `index.before`, `index.after` |
| User-requested service retained | PASS: all seven top-level routes HTTP 200 on loopback port 4001; no restart of user service | `dev4001-final-http.log` |
| Fresh independent Astra review | **PASS WITH LIMITATIONS**; confirmed P2 fixed and independently reverified; no remaining confirmed source blocker | `INDEPENDENT_REVIEW.md`, `reviewer/` |
| Reviewer browsing and canceled writes | All nine table fingerprints unchanged versus post-history state | `db-after-reviewer.txt`, `db-after-history.txt` |
| Keyboard horizontal table scroll follow-up | Tab entered region; native ArrowRight moved scrollLeft 0→40 with focus retained and no page overflow | `table-keyboard-verified.json`, `table_keyboard_probe.js` |
| Owned browser/test-service/database/profile/daemon cleanup | PASS: exact browser DB and all 12 recorded test DB identities absent; Chrome/profile, private daemon19841, renderer4017 and creator wrapper absent; user4001 retained | `browser-close.log`, `daemon-stop.log`, `cleanup-verified.log`, `test-cleanup-verified.log` |

### Screenshots
- Matching same-database, pre-mutation pairs for all nine routes: `before/{overview,findings,finding,cases,case,activity,imports,replay,history}-{1366x768,1440x900}.png` and corresponding `after/` files.
- Final desktop captures after explicit synthetic behavioral probes: `final/` with the same route/viewport filenames. The subsequent unknown-scope fix is captured separately in `reviewer/*-unknown-scope-fixed.png`.
- Mobile/tablet/wide/200%-text captures: `after/*-320x800.png`, `*-390x844.png`, `*-768x1024.png`, `*-1920x1080.png`, `*-1366x768-text200-spacing.png`.
- Actual workflow states: `after/case-keyboard-saved-1366x768.png`, `case-stale-1366x768.png`, `case-refreshed-draft-unrebound-1366x768.png`, `case-older-assessment-1366x768.png`, `case-long-image-320x800.png`, `case-full-value-copy-1440x900.png`, `import-{preview,validation,applied}-1440x900.png`, `replay-{result-unsaved,saved}-1440x900.png`, `history-saved-1440x900.png`, `connection-interrupted-1366x768.png`.
- Screenshots were opened with `pi.read`, not merely captured. A real mobile connected-mount disclosure defect and queue action wrapping were found visually and corrected. Original mobile failure retained at `failures/mobile-nav-initial.png`.

## Independent verdict and follow-through
The fresh reviewer read the full contract, source and all nine desktop/mobile routes; independently checked dirty drafts, exact copy, context round trips, unavailable/older states and 200% text keyboard operation. It found a real P2: unknown Team/Environment URL values were omitted from two native selects, causing unrelated input to widen scope to All. Shared `display_scope_options/3` and real-form regressions corrected this; the reviewer directly reproduced the fix before issuing **PASS WITH LIMITATIONS**. Source hashes still match its reviewed source.

The durable report and `review-complete` mesh verdict were emitted before the reviewer transport recorded an oversized-event failure (exit143). The coordinator subsequently also returned a failed transport status (exit143, oversized event) after writing this closeout and its final response. Neither is a clean harness exit; the implementation, completed independent report, direct artifacts and verdict are preserved. All four implementation leaves completed exit0 and were awaited; the reviewer and coordinator have terminated. No replacement model was used. Two reviewer evidence gaps were closed by the coordinator without source changes: unchanged post-review DB fingerprints and real native-key horizontal table scrolling. Screen-reader/cross-browser/physical-device limitations remain.

Main's subsequent closeout independently confirmed all 50 protected hashes and all 27 reviewer-recorded source hashes still match, JS syntax passes, the index is unstaged, and all seven top-level routes plus CSS/JS return HTTP200 on the original loopback service (PID59341, port4001). Main read the final 527-passed/2-skipped precommit log including successful owned drop, cleanup reports, and visually inspected final desktop Case/Findings and the reviewer's 320px assessment screenshot. These checks corroborate the saved evidence; they do not relabel the failed transports as successful agent runs.

## Honest limitations and preserved boundaries
- This targets WCAG 2.2 AA; it is **not a conformance claim**. Rendered/keyboard/contrast checks used owned headless Chrome, not a full screen-reader audit or a cross-browser/device lab. A forced database outage and every possible backend error were not browser-tested; invalid/missing/empty, validation, stale/older-assessment, unavailable telemetry and disconnected states were covered by focused tests/probes.
- Drafts remain session-only, with no browser storage. Explicitly accepting a full-page leave/reload can discard them. Clicked navigation/full-document unload are guarded; same-document Back/Forward interception depends on a cancelable Navigation API, so older browsers have a documented limitation.
- Before screenshots were current-run SSR captures: the initial `127.0.0.1` origin rejected LiveView sockets. All interactive probes used the correct `localhost:4017` origin. Matching pairs precede final small provenance/connectivity/queue polish and behavioral mutations; `final/` and the subsequent reviewer scope-fix captures show the implemented UI/current state, not falsely claimed to be the original data state.
- Initial compiler/test-helper/text mismatches and CDP/harness failures are retained in numbered logs. The browser harness initially used a sandbox pool unsuitable for long-lived HTTP sessions; it was corrected to a normal pool **only inside the guarded disposable runner**, with the same owned database. Production/runtime configuration was not changed. Native selects needed actual keyboard type-ahead and Enter text in CDP; the completed keyboard probe used those real events.
- Native horizontal table scrolling initially failed with the injected key driver. Coordinator follow-up used focused-page emulation and real macOS native key codes (Tab48, ArrowRight124), verified Tab entry and 0→40 horizontal scrolling, and visually read `after/findings-keyboard-scroll-390x844.png`. The reviewer’s original gap is retained honestly in its report; this later coordinator evidence closes the CDP check, not a physical-device audit.
- Ordinary full-suite output retains a pre-existing warning in the skipped opt-in concurrency test; both concurrency tests passed separately under their exact guard. No backend safety code was weakened to remove that warning.
- No backend contexts, schemas, migrations, source collection, runtime/production configuration, dependencies, lockfile, logo bytes, authentication or deployment changed. No dev DB writes, live-source calls, external fonts/CDNs, worktrees, staging, commits, resets, pushes or `.pi` edits. Existing untracked app and unrelated user changes remain in place.
