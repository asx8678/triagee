# UI acceptance ledger

## Third pass: Timeline colors + workflow trace + project-wide label audit (current)

### Timeline colors (user request: different colors, more understandable)
- [x] Distinct marker hues: open `#15803d` green, ended `#64748b` slate/hollow white dot, reopened `#b45309` amber, suppressed `#7c3aed` violet (previously 3 near-identical darks + brown). Hollow-ended mirrored in the marker legend.
- [x] Severity chips saturated: C `#b42318`, H `#ea580c`, M `#eab308`, L `#2563eb`, ? `#64748b` with readable letters (was 5 near-identical pastels).
- [x] Added the missing **Severity chips** legend group ("Scanner severity is not assessed impact.") — the C/H/M/L chips previously had no key anywhere.
- [x] Markers enlarged (dot r 4→4.5, halo 6.5→7); `tl-band-judged` `#fbfcfd`→`#f2f7f4`; `tl-cell-high` white-on-`#5a7ab5` for real contrast.
- [x] Marker legend text now names marker shape ("filled marker" / "hollow marker").

### Triage critical-advisory workflow trace (browser, live app)
- [x] Traced: `/triage` intake lane → "Review scope" → `/findings/:id?owner&environment` (h1 = CVE id, "Review this occurrence" panel) → "Open case …" (confirm) → `/cases/:id` review form. Pages are honest and ordered; artifact `/tmp/triage-workflow-trace.json`, screenshots `/tmp/triage-walk-triage.png`, `/tmp/triage-walk-finding.png`.
- [x] No redundant steps eligible for removal: case opening from a finding is an invariant (evidence capture), and the confirm dialog explains the write.

### Project-wide label audit (all 8 pages surveyed; structure dump `/tmp/review-notes.json`)
- [x] Triage: "Affected in active scopes" → "Present in active scopes" (presence ≠ judged affected); lane "Reviewed · nothing says affected" → "Handled — reviewed, nothing says affected" (matches the filter's own vocabulary).
- [x] Findings: "Affected in scope" → "Present in scope" (same presence/affected confusion).
- [x] What’s New: h1 “Activity” → “What’s New” and the browser tab title (`:page_title` assign) to match `/whats-new` and the module name (test updated).
- [x] Timeline day bands + drawer: opaque "Advisory page" → "CVE detail" (destination `/cves/:id`, consistent with Triage's CVE links).
- [x] Filter selects: `:has(select)` flex-basis 9→12.5rem — the Sort option "Severity (highest first)" no longer truncates on Findings; no layout regression at 375px (fields still wrap).

### Verification
- [x] Guarded targeted suites: 100 passed (`/tmp/triage-ui-timeline-color.log`, `/tmp/triage-ui-labels.log`, `/tmp/triage-ui-streamline.log`; owned DBs dropped, exit 0).
- [x] Guarded full `mix precommit`: **753 passed, 2 skipped** twice (`/tmp/triage-ui-precommit-labels.log`, final in `/tmp/triage-ui-streamline.log`). Skips remain the two pre-existing opt-in import concurrency tests.
- [x] Chrome: 6/6 label+color checks (`/tmp/triage-ui-labels-results.json`, rewritten with probe-element technique after a stale empty-suppressed-marker check), 7/7 streamline checks (`/tmp/triage-ui-streamline-results.json`; one failure was a probe bug — `#groups` is tbody — re-verified with thead selector).
- [x] Screenshots: `/tmp/triage-ui-timeline-colors-{1440,legend}.png`, `/tmp/review-{overview,triage,findings,timeline,whats-new,imports,replay,intel}.png`.
- [x] No behavior, route, schema, or permission changes; all edits are labels/legend/CSS with matching test updates.

## Follow-up: simplify the Overview panel (complete)

User feedback: the inventory status heading, review CTA and two observation modes did not form a clear task. Supersedes the first pass's Overview tabs below.

- [x] One “Recent findings” panel, ordered by last local observation, with one “View all findings” link (sort=last_seen).
- [x] Removed the two observation tabs and misplaced critical-review CTA; review stays in Triage navigation; `.overview-tabs` CSS removed.
- [x] Preserved the five-row bound, counts, empty/error states and local-only meaning; `/?view=recent|newest` bookmarks redirect to the canonical `/`; invalid/nested `view` values return a visible 400.
- [x] Guarded owned-DB `mix precommit`: **753 passed, 2 skipped**, exit 0 (`/tmp/triage-ui-precommit-simplify2.log`; owned DB dropped; two existing opt-in import concurrency tests remain opt-in). An intermediate run failed one stale link assertion, fixed before the final gate.
- [x] Chrome: 17/17 checks at 1440/375px — one panel/list, clear order label, View-all link, no tabs/CTA, no document overflow, bookmark redirects, visible 400. Screenshots `/tmp/triage-ui-overview-simplified-{1440,375}.png`; results `/tmp/triage-ui-simplify-results.json`.
- Real inventory reads only (`active_now_cve_groups`, counts); browsing writes nothing. Interruption note: one edit batch resumed via continuity handoff; all four intended edits were verified present afterward (template, controller, CSS, ledger) before testing.

## Original first pass (historical)


Scope: compact page headers, expose explicit scoped Triage review actions, repair timeline fit/axis readability, and replace duplicate Overview rails with one URL-selected list. No inventory/review/schema changes, automatic case creation, collection, or authorization changes.

## Execution paths
- `Layouts.app/1` → shared environment banner / CSS.
- `PageController.home/2` → inventory read APIs → `home.html.heex`.
- `TriageLive.render/1` → saved per-scope work items → scoped Finding/Case links.
- `FindingLive.Index.render/1` → filter/count explanations.
- `TimelineLive.render/1` → `Chart.lane_chart/1` → SVG geometry and stylesheet.

## Checks
- [x] Compact environment and page introductions retain safety and count semantics; useful content moves up.
- [x] Single-scope Triage actions visible without expanding; multiple scopes require explicit selection; links preserve owner/environment; browsing writes nothing.
- [x] Overview renders exactly one bounded list; Recent/Newly discovered links restore selection via URL; both orders, empty states and unknown selection handled.
- [x] Timeline fit has no desktop nested horizontal overflow; today/date labels do not overlap; detail retains scroll; marker/line meanings and cap remain discoverable without changing observations.
- [x] Targeted regressions and owned-DB `mix precommit` pass; shared DBs untouched by test setup.
- [x] Browser checks desktop and narrow viewport, Overview selection, Triage scope links, timeline scales, disclosure access and document overflow.

Initial tree changes: `.pi/fabric.json`, `.pi/fabric/mesh/state.json` (preexisting, not part of this patch).

## Verification results

- Final guarded `mix precommit`: **754 passed, 2 skipped**, exit 0; `/tmp/triage-ui-precommit-final.log`. The two existing opt-in import concurrency tests were not enabled. Owned database `triage_test_ab_20260916053115_49832_precommit` was dropped successfully. An earlier full precommit also passed; only the final run is the final-patch gate.
- Initial targeted run: 95/101 passed. Updated old layout assertions, corrected URL-order-sensitive test comparisons, retained a scoped impact-evidence hook, and verified the new multi-scope navigation test in the final full suite. Targeted DB dropped. No setup/seeding/migrations were run against dev/shared databases.
- Chrome: Overview, Findings, Triage, Timeline at 1440/1024/375/320px; no document overflow. Desktop Fit has no nested horizontal overflow, and 4/8/12-week fit/detail axes have no today/date collisions. Narrow charts intentionally retain a readable horizontally scrollable region with explanatory text. Detail retains its daily labels and scrolling.
- Browser interaction checks cover selected Overview URL, reload/Back restoration, one rendered list, visible single-scope actions, and navigation to the exact scoped finding without opening a case.
- Initial browser matrix: 39 passing assertions and one incorrectly synthesized Enter-key assertion; corrected raw-key Enter dispatch passed. `/tmp/triage-ui-browser-results.json` retains that initial history. The optional manual LiveSocket-disconnect probe stalled; the owned tab was reloaded and genuine connected state verified. Final five checks all passed (connection, hidden-flash spacing, visible-notice CSS, content position, keyboard disclosure): `/tmp/triage-ui-browser-final.json`. Visible-notice CSS was tested by toggling its hidden attribute, not claimed as an end-to-end offline/reconnect test.
- At 1440px, the Findings table starts at y=301px vs baseline y=427px (126px higher). Safety details remain keyboard-operable, and visible notices retain spacing.
- Screenshots: `/tmp/triage-ui-{overview,findings,triage,timeline}-{1440,375}.png`; final Findings capture: `/tmp/triage-ui-findings-final.png`.
- Manual source review and `git diff --check` passed. Contour reported no supported changed JS/TS source and explicitly lacks coverage for these Elixir/HEEx/CSS edits; it is not correctness evidence.
- No new dependencies, public route registrations, database schemas, collectors, or authorization behavior. Existing root, Triage, Findings, Case, and Timeline routes remain in use. The only added URL option is the validated Overview `view=recent|newest` selection.
- App remains running on `http://127.0.0.1:4000`. Preexisting `.pi` changes were not edited as part of the UI patch.
