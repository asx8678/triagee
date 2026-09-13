# Timeline — scope of work

Status: **scope only, nothing implemented.** Route, context, LiveView, CSS, migration and tests below are a plan in the order they would be built.

Every concrete claim in this document was checked against the tree at commit `3ce3e92`; §8 lists what was verified.

---

## 1. What I inspected

| Source | What it establishes |
|---|---|
| `priv/repo/migrations/20260101000000_create_inventory.exs` | `images`, `image_placements` (owner/environment/namespace/active/first_seen/last_seen), `findings` (first_seen, last_seen, resolved_at, suppressed, reopen_count), `finding_events` (finding_id, event, occurred_at, note) |
| `lib/triage/inventory.ex` | Event vocabulary is fixed: `appeared \| resolved \| reopened`. Suppression and disappearance are observations, never remediation |
| `lib/triage/activity.ex` | Existing read-only feed over `finding_events`; the conventions a Timeline read model must follow (bounded pages, deterministic order, no writes, honest labelling) |
| `lib/triage/cases.ex`, `cases/case_event.ex` | Append-only case audit: `case_opened \| evidence_captured \| review_saved`, each with `actor`, `case_revision`, `snapshot_id` |
| `lib/triage/cases/review.ex` | The recorded *judgment*: `applicability` (affected / not_affected_with_evidence / unknown), `priority`, `next_action` (incl. `exception_proposal`), `rationale` (≤2000 chars), `actor`. No accepted/rejected outcome field exists |
| `lib/triage_web/live/case_live/format.ex`, `case_live/show.ex`, `case_live/sections.ex` | **A case-level timeline already exists**: `CaseLive.Format.timeline_entries/1` merges case events and reviews into one uniform entry shape, newest first with a stable tie-break, streamed as `:timeline` and rendered at `#case-timeline`. This is the reuse target for the CVE drawer |
| `priv/repo/migrations/20260910093411_create_review_cases.exs` | `review_cases`, `review_evidence_snapshots` (frozen payload + hash), `review_reviews`, `review_case_events` |
| `lib/triage_web/router.ex`, `components/layouts.ex` | `/cves/:id` and `/cases/:id` already exist as click-through targets; nav is data-driven via `navigation_groups/0` with `id={"nav-#{key}"}` and `active_page` |
| `lib/triage_web/live/cve_live/show.ex` | Per-CVE page already renders occurrences, placements, exposure, priority and lifecycle observations |
| `lib/triage_web/components/ui_components.ex` | Reusable pieces that exist today: `page_header/1`, `status_badge/1`, `timestamp/1`, `notice/1`, `empty_state/1`, `relative_time/2`, `display_scope_options/3`, `display_value/2` |
| Live development database | The real volume below |

### Measured data (dev database, read-only)

```
findings=44   distinct_cves=41   placements=10   teams=8
finding_events: appeared=44  resolved=14  reopened=6      over 35 distinct days
event range: 2026-08-01 -> 2026-09-10 (41-day span, 6 days with no events)
new CVEs/day: mostly 1; 2026-08-01=2, 2026-09-09=4, 2026-09-10=6
by weekday (new CVEs): Thu=10 Wed=8 Sat=6 Mon=5 Tue=5 Fri=4 Sun=4
severity: CRITICAL=8 HIGH=15 MEDIUM=13 LOW=8
finding state: resolved=8  reopened=6  suppressed=6
review_cases=9  review_case_events: case_opened=9 review_saved=1 evidence_captured=0
review_reviews=1  actor=local-operator  (affected / normal_review / investigation)
review_evidence_snapshots=9   intel_refresh_receipts=0   news_items=0   exposure_evidences=0
```

Two consequences drive the whole design: **the history is sparse but continuous** (one observation most days, a spike at the end), and **the triage history is very thin** (one review, one actor, nine case opens).

---

## 2. What the data can and cannot honestly say

This is the part that decides the feature's honesty. Each requested element maps to a recorded fact or to a gap.

| You asked for | Recorded today? | Honest treatment |
|---|---|---|
| When a CVE **appeared** | Yes — `finding_events.event='appeared'` + `findings.first_seen` | Show directly |
| **When it was scanned** | Partly. Observation times come from the imported snapshot's own `occurred_at`/`first_seen`; they can be backdated | Label as "recorded observation time", not "scan time". Import runs are **not persisted** (no import-run table; only `replay_runs` for synthetic replays, expiring after 30 days) |
| Still observed / **no longer observed** | Yes — `resolved` event + `findings.resolved_at` | Say "no longer observed in an eligible collection". Never "fixed" or "remediated" |
| **Reopened** | Yes — `reopened` event + `reopen_count` | Show directly |
| **Who handled it** | Only a constant. `lib/triage/cases.ex:27` sets `@actor "local-operator"`; there is no login system | Display the recorded actor verbatim and label it as the local operator identity. **It currently carries no real attribution** |
| **How it was judged** | Yes — `review_reviews`: applicability, priority, next_action, rationale, bound to a frozen snapshot | Show in full, with the snapshot/revision it was judged against |
| **How it was handled** | Only as an *assessment*, plus `next_action` and evidence refreshes. There is no "mitigation completed" event, by design | Show `next_action` + `rationale`; do not render them as completion |
| **Added to the whitelist** | Only the current `findings.suppressed` boolean, imported from the scanner. **No timestamp, no actor, no event** | Show as **current imported state only**. A real "whitelisted on … by …" claim needs new history (see Gaps) |
| Days of the week | Derivable from the above | Show directly |

### Gaps that a view cannot close

1. **Whitelist/suppression transitions are not events.** The event vocabulary is `appeared|resolved|reopened`; a suppression flip is invisible. Adding `suppressed|unsuppressed` events would require an import-contract change, a migration, and — critically — **there is no backfill**: only the current value is known, so history would start at the cutover date.
2. **"By whom" is one constant.** Making it meaningful is a small code change (config/`TRIAGE_OPERATOR`) but a real decision, because `actor` is written into an append-only, trigger-protected audit row and participates in the local-operator model the review request hash is built around.
3. **No import/scan run record.** True scan times need a persisted run row; today the only persisted run-like table is `replay_runs` (synthetic, 30-day expiry).

---

## 3. Proposed design

Your description has two axes that need to become one coherent picture. The reading that fits both your words and the data:

> **Time flows left → right. Days stack top → bottom. A CVE is an arrow pointing forward through the days it was observed. Vertical connectors join an arrow from one day to the next.**

### 3.1 The day-band waterfall (the spine)

```
            Mon 24 Aug        Tue 25 Aug        Wed 26 Aug          (x = time within the day)
                    |                 |                |
   ┌──────────┬──────────────────────────────┐
   │ Mon 24   │  CVE-2026-1111  ▶▶▶▶▶▶▶▶▶▶  →  open, CRITICAL
   │          │  CVE-2026-2222  ▶▶●─╢        →  no longer observed (26 Aug)
   ├──────────┼──────────────────────────────┤
   │ Tue 25   │  CVE-2026-3333  ▶▶◆▶▶▶▶▶▶▶  →  reviewed 26 Aug by local-operator
   │          │      ▲                     ▲
   ├──────────┼──────┼─────────────────────┼──┐
   │ Wed 26   │  CVE-2026-2222  ⊘ suppressed (imported)  │
   │          │  CVE-2026-4444  ▶▶▶▶▶▶▶▶▶▶▶▶  →  open, HIGH
   └──────────┴──────────────────────────────┘
```

- **Left column** = the vertical axis: one row per day, date + weekday, newest-first by default, with an explicit "no recorded observation" row for empty days (there are 6 in the current window — showing them is the honest version of "every day is on the timeline").
- **Track** = the horizontal axis. Each arrow starts at the moment its CVE was first recorded that day.
- **Arrowhead vocabulary** (shape *and* colour, never colour alone):
  - `▶` open, still observed — arrowhead pointing forward
  - `╢` no longer observed — flat terminator at the date it stopped
  - `⊘` suppressed as reported by the scanner — hollow terminator
  - `◆` review recorded (judged), `▤` evidence captured, `↺` reopened
- **Vertical connectors** between adjacent day rows for CVEs that continue — this is the "line going up and down" you described, and it is what makes a multi-day CVE legible as one thing.

### 3.2 The weekday × week grid (the "super cool graph")

The literal answer to "days of the week and when there is a new CVE":

```
              W31   W32   W33   W34   W35   W36   W37
   Mon          ·     ·     ·     ░     ░     ░     ▓
   Tue          ·     ·     ·     ░     ░     ░     ▓
   Wed          ·     ·     ·     ░     ░     ░     █
   Thu          ·     ·     ·     ░     ░     ░     ██
   Fri          ·     ·     ·     ░     ░     ░     ░
   Sat          ·     ·     ·     ░     ░     ░     ▓
   Sun          ·     ·     ·     ░     ░     ░     ░
```

- 7 rows × N week columns; cell intensity = number of CVEs first recorded that day; hover/focus shows the exact count and the CVEs.
- Weekends visually separated (they carry real signal in the current data: Sat=6, Sun=4).
- Cells are links into the day band below; the whole grid is one `<table>` with a proper caption, so it is accessible and copy-pastable rather than a decorative blob.

### 3.3 Per-CVE lane (the click-through)

Clicking a CVE arrow opens an in-page drawer (no navigation away) showing the lane across the whole window plus the recorded history:

```
  CVE-2026-3333  CRITICAL  libssl 3.0.1 -> fix 3.0.2        8 teams, 10 images
  ├──●──────────────◆───┬─────────────────────────────────────▶ open
 appear 10 Aug     judged 26 Aug            today

  Judgments (1)
    26 Aug · local-operator · affected / normal_review / investigation
      rationale: "to be fixed"            snapshot rev 2 · hash 3f9a…
  Case history (2)
    10 Aug · case_opened        revision 1 · local-operator
    26 Aug · review_saved       revision 1 · review 1 · local-operator
  Lifecycle (3)
    10 Aug appeared · 14 Aug resolved · 16 Aug reopened
  Whitelist       suppressed as reported by the scanner (imported; no recorded date or author)
```

The judgment and case-history blocks **reuse `CaseLive.Format.timeline_entries/1`** rather than re-deriving the ordering, so the drawer and the case page can never disagree about what happened. Every drawer also links out to the existing `/cves/:id` and `/cases/:id` pages — the Timeline adds the time dimension, it does not replace them.

### 3.4 Why this shape

- It satisfies "horizontal for the CVE and its history, vertical for days and weeks" literally, and the up/down connectors make multi-day CVEs followable.
- It scales down to sparse data (6 empty days out of 41 render as honest gaps) and up to dense data (a day with 20 CVEs becomes a sub-track).
- It needs **no new dependency**: `mix.exs` has no chart library, and the app's existing severity bar is already CSS-only. Arrows and connectors are CSS grid + a small inline `<svg>` layer.
- It reuses the existing nav, page shell, `page_header`, `notice`, `status_badge`, `timestamp`, `empty_state` components, the `finding_filters` convention, and the existing case timeline ordering.

---

## 4. Architecture

### New files

| File | Purpose |
|---|---|
| `lib/triage/timeline.ex` | Read model. `window/1` (default 8 weeks, hard cap), `day_bands/2`, `weekday_grid/2`, `cve_lanes/2`, `cve_history/1`. Every function rejects invalid input **before** any query and writes nothing |
| `lib/triage_web/live/timeline_live.ex` | `mount`/`handle_params` only, mirroring `Activity` |
| `lib/triage_web/live/timeline_live/` `band.ex`, `arrow.ex`, `heat_grid.ex`, `drawer.ex` | Function components (matching the `case_live/` split of `format.ex` + `sections.ex`) |
| `lib/triage_web/timeline_filters.ex` | Window + owner/environment/severity parsing, mirroring `finding_filters.ex` / `activity_filters.ex` |
| `test/triage/timeline_test.exs` | Read-model unit tests, incl. invalid input and empty windows |
| `test/triage_web/live/timeline_live_test.exs` | Render, click-through, filters, sparse/empty windows |
| `test/triage_web/timeline_readability_test.exs` | Honesty-label and structure assertions, following the existing per-page convention (`overview_`, `inventory_`, `activity_`, `case_`, `tools_readability_test.exs`, `ui_readability_boundary_test.exs`) |

**DOM id prefix `tl-`.** The case detail page already owns `timeline-*` stream ids and `#case-timeline`; the new page must not collide with them.

### Changed files

| File | Change |
|---|---|
| `lib/triage_web/router.ex` | `live "/timeline", TimelineLive` in the existing browser scope |
| `lib/triage_web/components/layouts.ex` | Add `{"timeline", "Timeline", ~p"/timeline"}` to the **"Workspace"** group in `navigation_groups/0` — the tab. The nav renders `id={"nav-timeline"}` and `aria-current` automatically; pages set `active_page="timeline"` (existing values: `home`, `findings`, `cases`, `whats-new`, `imports`, `replay`, `replay-history`) |
| `priv/static/assets/css/app.css` | `.tl-*` classes on the existing tokens (`--triage-*`, `--triage-radius`) + `prefers-reduced-motion` |
| `test/triage_web/read_only_requests_test.exs` | Cover `/timeline` as a read-only GET |
| `test/triage_web/navigation_test.exs` | Assert `#nav-timeline` exists and sets `aria-current` |

### Queries (one per view, no N+1)

- **Day bands**: `finding_events` joined to `findings`, grouped by `date(occurred_at)`, bounded by the window, capped like `Activity` (page size 25 + sentinel row).
- **Weekday grid**: a single `GROUP BY date_trunc('week', …)` / `to_char(…, 'Dy')` aggregate over `findings.first_seen`.
- **Lanes**: one aggregate over `findings` grouped by `cve`, plus one batched read of case events/reviews for the CVEs on screen (never per-CVE), feeding `CaseLive.Format.timeline_entries/1`.
- **Indexes — a migration is probably required, and `EXPLAIN` should decide.** Existing coverage is `findings(cve)`, the partial `findings_open_cve_index (cve) WHERE resolved_at IS NULL`, `finding_events(finding_id)`, `review_case_events(case_id)` and `review_reviews(case_id)`. **Nothing indexes `finding_events(occurred_at)` or `findings(first_seen)`**, which are exactly the two range scans the timeline runs. P1 should run `EXPLAIN` on the dev database first, then add only the indexes it proves.

### Non-negotiables inherited from this codebase

- Read-only: no write on GET/mount/handle_params; the page appears in the read-only request test.
- Deterministic ordering with an explicit tie-break; the ordering rule is stated in the UI (as `Activity` does).
- Bounded windows and pages; no unbounded "all time" query.
- Honest labels, and an `sr-only` text equivalent for every arrow/connector so the picture is never the only carrier of meaning.
- WCAG 2.2 AA: shapes plus text, 24×24px minimum targets, keyboard-reachable arrows, no motion-only meaning.
- The `ci` gate is `compile --warnings-as-errors`, `format --check-formatted`, `deps.unlock --check-unused`, `credo --strict`, `assets.setup`, `test`, `dialyzer`.

---

## 5. Phases and effort

| Phase | Deliverable | Effort |
|---|---|---|
| **P0** | This scope + your decisions on §6 | done |
| **P1** | `Triage.Timeline` read model + `EXPLAIN` verdict on indexes + unit tests, no UI | ~1 session |
| **P2** | `/timeline` route, nav tab, day-band waterfall with arrows and connectors | ~1–2 sessions |
| **P3** | Weekday × week grid, per-CVE lane, click drawer (reusing `timeline_entries/1`) | ~1–2 sessions |
| **P4** | Filters, empty/sparse states, a11y table fallback, keyboard pass, readability + read-only tests, full `mix ci` | ~1 session |
| **P5** (separate approval) | Truth upgrades: operator identity, suppression/whitelist transition events, persisted import-run times | ~2–3 sessions + migration and import-contract risk |

**P1–P4 are a self-contained, read-only feature: roughly 4–6 focused sessions, no schema change beyond a possible index, no new dependency, no change to any existing write path.** P5 is the only part that touches the audit contract and should be its own PR with its own review.

### Main risks

1. **Over-claiming.** The strongest guardrail needed is wording: no "handled by X" when the actor is a constant, no "whitelisted on …" when only the current flag exists, no "remediated" for a disappearance.
2. **Sparse data.** 41 CVEs over 41 days means the first render will be sparse; the design must look deliberate when empty rather than broken.
3. **Density.** A day with 20+ CVEs must degrade to a sub-track rather than 20 overlapping arrows.
4. **Attention cost.** A timeline is easy to make pretty and unreadable; the arrow vocabulary must stay at four or five shapes, with a legend and a table fallback.

---

## 6. Decisions I need from you

1. **What counts as "handled"?** A saved review (the only thing actually recorded), a `resolved`/disappearance event (which this app deliberately refuses to call remediation), or a suppressed flag (scanner-reported)? This decides what the arrowhead terminator means, and it is the single most important choice.
2. **"Whitelist" — is that the scanner's `suppressed` flag, or do you want a real local exception workflow** (request → approver → expiry) with its own records? The first is a label; the second is a new domain feature, and the Timeline would then show genuine "whitelisted on … by …" history.
3. **"By whom" — should we make the actor real?** Today every review and case event is the constant `local-operator`. A config-backed operator name is small but changes what the audit trail means going forward (already-written rows can never be re-attributed).
4. **How far back does the timeline open, and what is the default window** — 4 weeks, 8 weeks, or "everything recorded"? Current data spans 41 days with 6 empty days.
5. **Click behaviour** — in-page drawer (my recommendation) or jump straight to the existing `/cves/:id`?
6. **Do you want the day bands newest-first or oldest-first?** I would default to newest-first to match `/whats-new`, with a toggle.

---

## 7. Explicit non-goals for P1–P4

- No new tables, no migration unless `EXPLAIN` proves an index is needed.
- No new runtime dependency, no JavaScript charting library.
- No changes to `Triage.Import`, `Triage.Cases`, `Triage.Inventory` or any write path.
- No claim of remediation, mitigation, approval or completeness anywhere in the UI.
- No replacement of `/cves/:id`, `/cases/:id` or `/whats-new` — the Timeline is an additional view over the same records.

---

## 8. Verified against the tree (`3ce3e92`)

| Claim | Verification |
|---|---|
| No `Timeline` module, route or nav entry exists yet | `grep -rn 'timeline\|Timeline' lib config test` returns only the **case-level** feature (`case_live/format.ex`, `case_live/show.ex` `stream(:timeline, …)`), plus one `seeds.ex` comment |
| Nav shape and insertion point | `navigation_groups/0` returns `{"Workspace", [...]}` then `{"Data tools", [...]}`; the Timeline entry joins the Workspace group |
| Routes the drawer links to | `live "/cves/:id", CveLive.Show` and `live "/cases/:id", CaseLive.Show` exist in the browser scope |
| Components reused | `page_header/1`, `status_badge/1`, `timestamp/1`, `notice/1`, `empty_state/1`, `relative_time/2` all exist in `ui_components.ex` |
| CSS tokens | `--triage-bg/surface/text/muted/border/control-border/header/accent/focus/brand` and `--triage-radius: 4px` are defined in `app.css` |
| Index coverage | Confirmed by reading all five migrations: no index on `finding_events(occurred_at)` or `findings(first_seen)` |
| Case timeline reuse | `CaseLive.Format.timeline_entries/1` returns a single uniform entry shape for events *and* reviews, sorted `{-time_key(at), key}`, and is rendered at `#case-timeline` with existing test coverage in `case_live_test.exs` and `case_live_sections_test.exs` |
| Test-file conventions | Per-page readability tests exist (`overview_`, `inventory_`, `activity_`, `case_`, `tools_readability_test.exs`, `ui_readability_boundary_test.exs`); `navigation_test.exs` and `read_only_requests_test.exs` already exist and are the right files to extend |
| Gate | The `ci` alias is exactly `compile --warnings-as-errors`, `format --check-formatted`, `deps.unlock --check-unused`, `credo --strict`, `assets.setup`, `test`, `dialyzer` |
