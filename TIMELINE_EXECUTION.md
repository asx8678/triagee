# Timeline — execution plan

Scope approved by "plan implementing it and implement". Decisions taken from the six blocking questions, using the
recommended defaults stated in the review:

| Decision | Value | Consequence |
|---|---|---|
| What counts as handled | A saved review (`review_reviews`) | The only completion marker is a *recorded assessment*, labelled as an assessment. No remediation claim |
| Whitelist | The scanner's imported `suppressed` flag | Rendered as current imported state, with the missing date/author stated in the UI |
| "By whom" | Left as the constant `local-operator` | Shown verbatim and labelled as the local operator identity |
| Default window | 8 weeks, selectable 4 / 8 / 12 | Bounded; never "all time" |
| Click behaviour | In-page drawer | URL-addressable as `?cve=`, patch-navigated, no full reload |
| Day order | Newest first | Matches `/whats-new`; the grid states its own older-to-newer direction |

## Acceptance ledger

| # | Criterion | How it is checked |
|---|---|---|
| 1 | `/timeline` renders for a real dataset | `timeline_live_test.exs` renders and asserts `#tl-bands`, `#tl-grid`, `#tl-summary` |
| 2 | Days are on the vertical axis, newest first, and empty days appear explicitly | Assert `#tl-band-empty-<date>` exists for a day with no event |
| 3 | A CVE is a forward arrow through the days it was observed, joined vertically | Assert `.tl-connector` count > 0 for a CVE observed on adjacent days; assert `#tl-row-*` ids |
| 4 | Weekday x week grid counts newly recorded CVEs | Assert 7 rows, N week columns, and a specific cell count |
| 5 | Per-CVE lane with judgments, case history and lifecycle | Assert drawer `#tl-drawer`, judgment label, case-event labels |
| 6 | Judgment history reuses the case timeline ordering | Drawer entries come from `CaseLive.Format.timeline_entries/1` (no second ordering definition) |
| 7 | Honest labels | Readability test asserts: no "remediated", "verified", "fixed", "approved"; suppression labelled imported; a missing date/author stated |
| 8 | Observation vs scan time is not conflated | UI says "recorded observation time"; no "scan completed" claim |
| 9 | Read-only | `/timeline` added to `read_only_requests_test.exs` whole-database fingerprint |
| 10 | Navigation | `navigation_test.exs` covers the 8th link and `aria-current` |
| 11 | Bounded queries | Per-day row cap, event cap, lane cap, case cap; `truncated?` surfaced |
| 12 | Invalid input is rejected before any query | `timeline_test.exs` unit tests for every invalid shape |
| 13 | Index decision is evidenced, not assumed | `EXPLAIN` recorded below |
| 14 | Full gate | `mix ci` (compile + format check + unused deps + credo --strict + tests + dialyzer) |

## Files

New:

| File | Role |
|---|---|
| `app/lib/triage/timeline.ex` | Read model: window validation, day bands, weekday grid, lanes, one-CVE detail |
| `app/lib/triage_web/timeline_filters.ex` | URL/event parameter contract for `owner`, `environment`, `weeks`, `cve` |
| `app/lib/triage_web/live/timeline_live.ex` | LiveView: mount, handle_params, filter event, composition |
| `app/lib/triage_web/live/timeline_live/bands.ex` | Day-band waterfall component |
| `app/lib/triage_web/live/timeline_live/grid.ex` | Weekday x week grid component |
| `app/lib/triage_web/live/timeline_live/drawer.ex` | Per-CVE detail drawer component |
| `app/test/triage/timeline_test.exs` | Read-model unit tests |
| `app/test/triage_web/live/timeline_live_test.exs` | Render, drawer, filters, empty window |
| `app/test/triage_web/timeline_readability_test.exs` | Honesty-label and structure assertions |

Changed: `router.ex` (route), `components/layouts.ex` (nav entry), `priv/static/assets/css/app.css` (`.tl-*`),
`test/triage_web/navigation_test.exs` (8 links), `test/triage_web/read_only_requests_test.exs` (`/timeline`).

## Data contract (honesty rules)

* A day band row exists because a `finding_events` row exists that day. Absence of a row is *no recorded
  observation*, never "clean".
* Arrow terminators: `appeared` = first recorded observation, `resolved` = no longer observed in an eligible
  collection, `reopened` = observed again. `suppressed` is a current imported flag, not an action.
* A vertical connector means the same CVE has a recorded observation on the adjacent day. It is a rendering of
  recorded observations, never a claim of continuous presence.
* A judged marker means a saved assessment exists. It never means approved, mitigated or resolved.

## Index decision (criterion 13)

Run before writing code, on the development database, for the two range scans: `finding_events` filtered and
ordered by `occurred_at`, and `findings` by `first_seen`. Existing coverage is `findings(cve)`,
`findings_open_cve_index (cve) WHERE resolved_at IS NULL`, `finding_events(finding_id)`, `review_case_events(case_id)`,
`review_reviews(case_id)`. Result recorded in the implementation report; a migration is added **only** if the plan
shows an indexable scan that an index actually changes at the real table size.

## Order of work

1. Read model + unit tests (no UI).
2. Parameter contract.
3. LiveView + three components.
4. Route, nav, CSS.
5. LiveView, readability and read-only tests; navigation update.
6. `mix ci`; then a live render against the development database.

## Non-goals

No write path, no import change, no schema change, no new dependency, no replacement of `/cves/:id`,
`/cases/:id` or `/whats-new`.

---

## Result

Implemented and verified. One deviation from the file list above: the lane table needed its own component
(`live/timeline_live/lanes.ex`), so the page has four components rather than three.

### Acceptance ledger outcome

| # | Criterion | Evidence |
|---|---|---|
| 1 | `/timeline` renders for a real dataset | Live probe against the development database: HTTP 200, 56 day bands, 41 lane rows |
| 2 | Days vertical, newest first, empty days explicit | Live: newest band is Sun 13 Sep 2026, rendered as an empty band; 21 of 56 bands empty; test asserts `#tl-band-<today>.tl-band-observed` and `#tl-band-empty-<date>` |
| 3 | Forward arrows joined vertically | Live: 64 row arrows (exactly the 64 recorded `finding_events` rows) and 2 connectors; tests assert `continues?`/`continued_from?` in both directions and their absence for a single-day CVE |
| 4 | Weekday x week grid | Live: 9 column headers (Day + 8 weeks), 7 weekday rows, a caption, and a per-cell text equivalent ("20 Jul 2026: no new CVE recorded") |
| 5 | Per-CVE lane, judgments, case history, lifecycle | Live drawer for `CVE-2024-2002`: `#tl-drawer`, `#tl-drawer-lane`, `#tl-drawer-events`, `#tl-drawer-cases`; tests cover the case and saved-assessment path |
| 6 | Judgment history reuses the case ordering | Drawer entries are produced by `CaseLive.Format.timeline_entries/1`; no second ordering definition exists |
| 7 | Honest labels | Readability test forbids 13 unsupported claims (for example "added to the whitelist", "remediation complete", "approved by", "last scanned"); live page contains "it is not remediation", "not a clean day", "not verified production coverage" |
| 8 | Observation time is not scan time | Rows say "recorded observation time"; the banner denies scan-completion, publication and approval semantics |
| 9 | Read-only | `/timeline` added to the whole-database fingerprint test in `read_only_requests_test.exs` |
| 10 | Navigation | `#nav-timeline` with `aria-current="page"`; `navigation_test.exs` and `ui_components_test.exs` updated for the eighth link |
| 11 | Bounded queries | 25 rows per day band, 2000 events, 50 lanes, 10 cases per CVE, each with visible truncation text |
| 12 | Invalid input rejected before any query | 27 read-model assertions covering request shapes, window range and type, scope and CVE value contracts |
| 13 | Index decision is evidenced | `EXPLAIN (ANALYZE, BUFFERS)` on 64 events / 44 findings / 1 review: every plan a one-page `Seq Scan` in at most 0.12 ms, so an index would be speculative. No migration was added |
| 14 | Full gate | `mix ci` passed: compile with warnings as errors, format check, unused deps, `credo --strict` with 0 issues, 690 passed / 2 skipped, dialyzer 0 errors |

### Defects found and fixed while implementing (all surfaced by tests)

1. `severity_rank/1` was inverted: because `CRITICAL` is first in `Triage.Inventory.severity_order/0`, the
   index-plus-one rank made `LOW` the highest, so lanes sorted backwards.
2. The weekday grid counted `Enum.frequencies/1` of `{date, cve}` tuples and then looked cells up by `date`,
   so every cell rendered 0.
3. `Enum.sort/1`, `Enum.min/1` and `Enum.max/1` were applied to `Date`/`DateTime` structs, which are maps: term
   ordering compares their fields (day, then month, then year) rather than chronological order. They now use the
   `Date` and `DateTime` module sorters.
4. `as: :finding` was attached to the `Image` join in `load_cve/1`, so the scope subquery asked the image for
   `image_id`. The alias now names the findings join, exactly as `fetch_events/1` does.
5. `lane/4` never set `resolved_at`, which the drawer reads. It is now set only when every recorded occurrence
   is currently resolved, so a partly open CVE reports no single disappearance time.
6. `limit: ^(@event_limit + 1)` is an escaped expression that a full `mix compile` expands but the running
   server's in-process reloader could not, producing an `Ecto.Query.LimitExpr` expansion error. It is now a
   pinned variable (`limit: ^fetch_limit`), matching the existing idiom in `Triage.Activity`.
7. Three gate tests hard-coded the old navigation link count of seven.

### Operational note on the mid-implementation 500

The 500 response seen while the app was running was **not** a code defect. Running `mix compile` externally
while the dev server was live made the server's own reloader compile the same `_build` directory concurrently:
that produced the `Ecto.Query.LimitExpr` expansion error and then a protocol-consolidation `MatchError`. Once
the server was stopped, the tree compiled cleanly, and the server was restarted, `/timeline` served 200 with
zero `[error]` lines in the server log. Live development reloading is still unable to compile this module while
another process compiles the same build directory.

### Shared fixtures

The relative-date inventory helpers moved into `test/support/fixtures.ex`, so the read-model test and the
LiveView test share one definition of an image, placement, finding, event and review payload instead of two
copies.

---

## Verification round 2 — a real browser (headless Chrome 153 over CDP)

Run after the first commit, because structural tests cannot see layout. It found one real defect.

| Check | Result |
|---|---|
| Desktop 1440x900 | `scrollWidth == clientWidth == 1440`, no horizontal overflow; 56 bands, 21 empty, 41 lanes, 64 arrows, 64 text equivalents, 2 connectors with real geometry (2px x 10px, `rgb(116,130,150)`) |
| Mobile 390x844 and 320x800 | **DEFECT FOUND AND FIXED**: the page scrolled horizontally (411px against a 320px viewport). Now `scrollWidth == clientWidth` at both widths |
| Cross-route control | `/`, `/findings`, `/cases`, `/whats-new`, `/imports` were already overflow-free at 320px; `/timeline` now matches them |
| Accessibility tree | 2 tables, 50 rows, 16 column headers, 48 row headers, 1 caption, 6 regions — table semantics intact |
| Keyboard | The scroll region is focusable, and a lane's detail link is reachable with the label "Timeline detail" |
| Interactivity | A real client-side click on the lane link patched to `/timeline?cve=CVE-2024-2002`, rendered `#tl-drawer`, and populated the lifecycle list |
| Colour contrast | All 11 new colour pairs pass WCAG AA (lowest text ratio 5.79:1; non-text 3.91:1 against a 3:1 requirement) |
| Screenshots | `evidence/timeline/timeline-desktop-1440x900.png`, `timeline-drawer-1440x900.png`, `timeline-mobile-390x844.png` |

### The reflow defect and its fix

Two wide tables were wrapped in a hand-written `.tl-table-scroll` region. That region clipped and scrolled
correctly, but it was `position: static`, so the absolutely positioned `.sr-only` text equivalents inside its
cells took the initial containing block instead of the region: they escaped the clipping and extended the
document's scroll width to 411px. A DOM-ancestry scan for overflow can miss this, because the escaping
elements still look like descendants of the scroll container.

The fix was two changes:

1. Give the wrapper `position: relative`, so it is the containing block for its absolutely positioned
   descendants, and add a `:focus-visible` ring to the shared class.
2. Stop inventing a parallel class: the two tables now use the existing app-wide `.table-region` wrapper
   (`core_components.ex`'s `table` component and seven other call sites already use it), so the timeline
   follows the house pattern instead of duplicating it.

The stated pagination and honesty wording did not change; only layout and the wrapper class did.

## Verification round 3 — gate re-run after the fix

`mix ci` passes on the final tree (warnings-as-errors, format check, unused deps, `credo --strict`,
tests, dialyzer 0 errors), and the live page has served 200 with zero `[error]` lines since.

### Operational note on dev-server build corruption

A second 500 appeared while the browser was driving the page, this time as a full in-process rebuild of 75
modules ending in `** (RuntimeError) found error while checking types for Triage.Collection.Client.query/3` —
pre-existing PR6 code that a clean external compile handles fine. The running node had decided to rebuild
the whole application and hit Elixir 1.20's type checker with the already-loaded module graph. The repair is
the same one that worked earlier: stop the server, compile externally, restart. The durable lesson is not
just "do not compile while the server runs" but "a crashed in-node compile leaves `_build/dev` needing an
external recompile before live reloading is trustworthy again".

---

## Verification round 4 - the connected chart

### What was added

`TriageWeb.TimelineLive.Chart` (`app/lib/triage_web/live/timeline_live/chart.ex`), fed by a new `:chart`
field on `Triage.Timeline.list_timeline/1` (`build_chart/3`), built from the same recorded events the day
bands and lane table use, bounded to the 12 most severe lanes.

The complaint was concrete and correct: the timeline showed no lines and nothing was connected. Per recorded
observation the page drew one unicode glyph (`>`, `||`, `o`, `/`) in a 1.25rem column, and the only "line"
was a 2px x 8-10px vertical stub (`.tl-connector`) between two adjacent day rows. No line spanned a day, so a
CVE's history could not be read across the window at all.

### Why SVG rather than a JavaScript charting library

The request was to use a library. This app has no asset bundler: no `package.json`, no esbuild/tailwind build
step, and `priv/static/assets` holds hand-vendored files (phoenix.js, phoenix_live_view.js). Adding
vis-timeline, Chart.js or ApexCharts would mean vendoring a minified bundle plus a LiveView JS hook, and
giving up server-side rendering and ExUnit coverage of the markup - the two things that make this view's
honesty rules testable. Inline SVG is the browser's own vector graphics: real `line`/`circle`/`marker`
elements, generated server-side, asserted directly in tests, and rendered without JavaScript.

### Honesty rules the geometry obeys

| Geometry | Meaning | Where it is stated |
|---|---|---|
| solid segment with arrowhead | two adjacent days with a recorded observation for this CVE | legend and the segment's own title |
| dashed segment with arrowhead | two recorded days with no recorded observation in between | legend, the segment title, and the section copy |
| dashed grey entry tick | also recorded before this window (the finding's own `first_seen`) | legend |
| pin, no segment | a single recorded day in this window | legend |
| no line at all | nothing implied | caption: a missing line is not a claim that nothing existed |

### Verification (real browser, real development data)

| Check | Result |
|---|---|
| Full gate | `mix ci` on the final tree: **696 passed, 2 skipped**, credo `--strict` clean, dialyzer **0 errors** |
| Chart drawn from real records | 12 tracks, 1 solid segment, 2 dashed segments, 15 markers, 4 arrowhead definitions, 1 today line, 56 weekday labels, 9 week labels (8 week starts plus the CVE gutter label) |
| Every segment arrowed | 3 segments, 3 marker-end references, three distinct state arrowheads (open/ended/reopened) |
| Solid vs dashed is real | the reopened lane computes `stroke-dasharray: none`; the two gap lanes compute `4px, 4px` |
| Hover descriptions | "Wed 05 Aug 2026 and Thu 06 Aug 2026 are adjacent days this CVE is recorded on." and "... the days in between have none recorded." |
| Colour contrast | dots and strokes 6.46-9.84:1, CVE label 15.41:1, week labels 6.32:1, severity chip text on its chip 8.6:1 - all pass AA. The weekday letters measured **3.47:1** and were darkened to `var(--triage-muted)` (now 6.32:1) |
| Reflow | `scrollWidth == clientWidth` at 1440/390/320; the 1616px chart scrolls inside its region (1624 -> 1406/364/294) and the page never scrolls sideways; the other five routes stay clean at 320 |
| Accessibility tree | the chart's SVG subtree is `ignored: true, role: none` - zero nodes; the page still exposes 2 tables, 50 rows, 16 column headers, 48 row headers, 1 caption and 8 regions |
| Screenshots | `evidence/timeline/timeline-chart-desktop-1440x900.png` (166,354 B), `timeline-chart-mobile-390x844.png` (251,698 B) |

### Defects found while building the chart

1. `segment_class/1` never emitted an explicit solid class (solid was implicit in CSS), so solid and dashed
   segments were indistinguishable to a test - and the legend's own key had the same gap.
2. Three of my own assertions used `length/1`, `hd/1` and `List.first/1` on `LazyHTML.query/2`, which returns
   a struct rather than a list, and counted the legend's key shapes as chart marks. Both are now scoped.
3. The chart's layout points initially dropped the `date` and `label` they needed for adjacency and hover text.
4. The weekday letter colour failed AA (3.47:1) - only a browser could have found this one.

