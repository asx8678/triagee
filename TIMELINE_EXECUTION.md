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
