# Historical README and verification reports

This archive preserves the previous README verbatim below. Its dated verdicts,
process IDs, database names, fixture counts and `/tmp/` evidence references are
historical, may no longer exist, and are **not verification of the current tree**.
Use [README.md](README.md) for current setup, workflows and quality commands.

---

# Triage — local review, replay and historical import

## Real CVE reference dataset

Development setup now loads **95 real NVD advisories: 30 critical, 40 high, 20 medium, 5 low**
from `priv/reference/nvd-cves.json`, offline. The `public-reference / not-a-deployment`
scope is reference data, not a scan or proof your systems are affected. Source links,
CVSS scores and provenance are shown on CVE details. Existing databases require an
explicit preview/apply; saved assessments and unrelated inventory are preserved.
See [REAL_CVES.md](REAL_CVES.md) for validation, download and safe replacement commands.


## Current independent UI verdict — PASS within bounded local coverage

Actual owned headless Chrome verified 1440/375/320px navigation, six homepage
cards, exact titles/active links, keyboard focus and skip-to-main, scoped finding
and case pages, real file uploads, replay Save/history, and historical import
preview/review/Apply. Browser-discovered native button `value=""` handling,
confirmation/digest/table overflow, and skip focus were corrected only in UI,
CSS and layout, with regressions. Final affected tests: **23 passed**; independent
malformed-state/public-route/static probes: **4 passed**. Browser ledger retains
**105 passing assertions and 4 historical failed assertions** (two layout failures
fixed; two probe mistakes diagnosed), not a rewritten all-green history.

Read-only preview and duplicate/stale rejection preserved full owned DB dumps;
explicit import changed only expected inventory, preserving nonempty case history.
All **1,152 protected file hashes** and full dev/shared schema+row dumps match.
Owned test DB, endpoint, Chrome/profile and private daemon were removed; **Triage
remains stopped**, ports 4000/4001 and existing daemons untouched. No new full-suite
or concurrency claim: earlier 473/2-skipped and 3 backend probes remain historical.
27 screenshots, browser scripts and logs: `/tmp/ui-browser-evidence/`;
verdict, exact limits and handoff: `/tmp/ui-astra-final.md`.

## Historical UI integration — backend gates passed; browser pending at handoff

The branded homepage and all pages share seven visible wrapping navigation links:
Home, Findings, Review Queue, What's New, Replay, Replay History, Imports. Active
links use `aria-current`; document titles now end in Triage. This integration is
separate from the historical PR7 backend verification recorded below.

**Trusted local operators only: no authentication or authorization.** Keep the app
on loopback. Filters and confirmation nonces are not access control. No live
source calls, Oban, scheduling, or automatic approval are introduced. The Triage
app was intentionally left stopped; do not start it or use another project's
port 4000 as part of verification. Browser review was pending at integration handoff; see the current verdict above.

### Local workflow usage

- `/replay`: download `/assets/examples/replay.json` (the genuine complete synthetic
  fixture), select that local JSON file, then **Run synthetic replay**. Uploads
  are limited to one file and 1,000,000 bytes. Only server-provided upload temp
  paths are read, at most limit + 1 bytes. Results are faithful safe counts,
  completeness, allowlisted diagnostics and SHA-256—not source descriptions,
  filenames or identifiers. Replay changes no inventory and saves nothing until
  **Save summary to local history**. Reload/new input/cancel discards unsaved state.
- `/replay/history`: read-only browsing of up to 25 unexpired receipts, ascending
  ID (oldest retained first), with truthful **Next** and **First page** links.
  Invalid queries clear prior rows; expired receipts disappear when reloaded.
  There is no polling, purge button, or replay/apply action in history.
- `/imports`: select an **approved historical** `triage.snapshot` version-1 JSON
  export (contract below), then **Preview without writing**. This is not a replay
  conversion or a fabricated current snapshot; no historical import example is
  presented as approved evidence. Preview enforces 1,000,000 bytes and lexical
  nesting depth 32. **Review & confirm**, acknowledge the local inventory change,
  then **Apply historical snapshot** with the exact server nonce. Apply rechecks
  the full report and affected inventory fingerprint under the existing Import
  advisory lock and calls unchanged `Import.write!/1` in one transaction. Changed
  metadata is stale even if IDs and action counts are identical: re-upload to
  preview again, never silently rebase. Duplicate UI applies do not write again.
  Confirmed imports may stale existing review evidence, but never rewrite cases,
  frozen evidence, reviews, case events or replay history. No exceptions activate.

Malformed events, new uploads, cancellation and errors clear prior save/apply
bindings. Public helper prepared values are server state, not a durable nonce
registry or an authentication API. Errors shown in these workflows are static;
raw source paths/descriptions and database exception details are not rendered.

Verification: affected replay/import tests **20 passed**; navigation/controllers
and affected old/new LiveViews **109 passed**; one full `mix precommit` **473 passed,
2 skipped** (the existing exact-owned-DB opt-in Import concurrency tests; their
existing nil-opt-in compiler warning remains). A separate owned-DB probe passed
**3/3**: Import blocks Flow then stale rejection, Flow blocks Import then no
second creation, and late event-insert failure rolls back all inventory. Mechanical
checks passed for seven titles/labels/links/active states, public APIs, route
registrations, eight static paths and faithful example counts. Real LiveView file
uploads and ordinary form submission—not special mock submit payloads—are tested.

Fresh partition `triage_test_ui_integrate_0911a` was verified ABSENT before creation,
configured/current DB checked, and dropped after use (ABSENT; all nine application
tables empty). Current-startup full `triage_dev`/`triage_test` dumps match before/after,
stripping only pg_dump restrict nonces; protected sources/deps/migrations match.
No browser, listener, user-process stop, harness edit, nested agent or commit.
See [acceptance ledger](UI_WORKFLOWS_PLAN.md), `/tmp/ui-integration.md`, and
`/tmp/ui-integration-evidence/`. Historical verification below is not new UI signoff.

## Current PR7 status

PR7 integrates pure versioned synthetic JSON replay, `mix triage.replay --file PATH`
(exit 0 complete / 2 incomplete / 1 invalid), and an explicit summary-only Runs API.
No scheduler, raw snapshots, lifecycle inference, live collection, or UI is added.
See [PR7 contract](PR7_PLAN.md), [CLI](PR7_CLI.md), and [receipt ledger](PR7_HISTORY.md).
The CLI starts neither the app nor Repo and needs no production runtime DB secrets.
Ledger writes require an explicitly started Repo; immutable receipts expire after
30 days, hide from reads, and consume the 1000-row quota until explicit purge.
## Current bounded independent PR7 recheck — PASS

All three repaired acceptance defects independently pass on the final tree:
genuine stage-specific Query metrics preserve open/suppressed Normalize parity;
unknown inventory evidence cannot complete; lexical 5000 aggregate array-value,
64 object-field-occurrence and depth-32 bounds precede Jason decoding.
Fresh unchanged adversarial checks: **4/4**. Fresh targeted tests: **105/105**
(11 Replay, 6 CLI, 8 history, 80 Collection), exit 0. Fresh actual CLI exits:
complete/suppressed/incomplete/invalid **0/0/2/1**, with asserted JSON. Four additional
actual-task probes with refused DB port 1 produced identical JSON and verified
Repo/Endpoint absent and triage not started at output, including nonzero exits.

Protected PR6 and CLI/ledger/migration hashes and read-only full dev/shared-test
row/schema dumps matched before/after. The absent-before disposable partition
`triage_test_pr7close_0911c` was dropped and verified absent; final owned counts
were 0/0/0. Current Phoenix PID **64795** was unchanged and untouched.
Prior separate-backend concurrency and rollback/remigrate evidence was inspected
and is **inherited**, not rerun. No new production build or full precommit result
is claimed. This PASS closes exactly the three fixes, not a new full-scope audit.
Prior BLOCKED and repair-pending records below are retained as history, superseded
only for this bounded acceptance. Details, hashes, cleanup and limits:
`/tmp/pr7-astra-closeout.md`; fresh evidence: `/tmp/pr7-closeout-evidence/`.

## Previous repair verdict — independent recheck pending (historical)

The three independently reproduced replay blockers are repaired in PR7-only code:
Query-shaped detail counts preserve open/suppressed findings; closed stage-specific
image/metrics schemas reject unknown evidence as incomplete; lexical array-element
(5000) and object-field (64) budgets run before Jason decoding. Genuine fixtures
and same-process unchanged Normalize parity are covered. The retained adversarial
suite passed 4/4 unchanged after its baseline 1/4 (three failures). Affected tests
passed 105 (11 Replay, 6 CLI, 8 history, 80 Collection); final-fixture Replay and
fresh CLI complete/suppressed/incomplete/invalid checks are recorded in
`/tmp/pr7-replay-repair.md`. No new full precommit, production build, or unchanged
ledger concurrency rerun. Independent acceptance remains pending; previous
verification and PR6 history below are retained, not new signoff.


## Offline foundation (PR1–PR6 history)

A Phoenix LiveView application showing a synthetic, team-scoped CVE inventory.
PR 1 is deliberately offline: fixtures only, no security-API connections, no AI,
no suppression writes. PR 2 adds scoped local review cases with frozen evidence
snapshots and unauthenticated local-operator assessments.

## Stack

- Elixir 1.20.4 / Erlang/OTP 27 (pinned in `.mise.toml`)
- Phoenix 1.8 LiveView, Ecto, PostgreSQL (local Homebrew `postgresql@18`)

## Setup

```bash
brew services start postgresql@18   # if not already running
cd app
mise x -- mix setup                 # deps.get + ecto.create + migrate + offline real NVD reference seed
```

The dev database is `triage_dev`; tests use the sandboxed `triage_test`. The local
`postgres` superuser uses trust auth (no password) — do not expose this setup.

## Run

```bash
mise x -- mix phx.server
# http://127.0.0.1:4000/findings
```

## Test

```bash
mise x -- mix test
```

The real-commit importer concurrency tests are **skipped by default**. They must
never run on shared/dev data. After verifying a unique test partition database
was absent, creating/migrating it, and confirming it is yours and empty, opt in
using its exact name on the same invocation:

```bash
MIX_ENV=test MIX_TEST_PARTITION=_YOUR_UNIQUE_NONCE \
TRIAGE_IMPORT_CONCURRENCY_DB=triage_test_YOUR_UNIQUE_NONCE \
mise x -- mix test test/triage/import_test.exs test/triage/import_concurrency_test.exs
```

The guard refuses mismatched targets and preexisting application rows before
switching to real commits. Cleanup truncates that owned empty-at-start DB;
drop only your own database afterwards. The opt-in is not permission to reuse
someone else's empty partition.
## Assets

The browser client is real Phoenix + Phoenix LiveView JavaScript, and the
stylesheet is built by Tailwind CSS. Everything is served same-origin; there is
no bundler, no CDN and no runtime JavaScript dependency.

- `priv/static/assets/js/app.js` (tracked) is the bootstrap: it reads the
  `csrf-token` meta tag, builds `new LiveView.LiveSocket("/live",
  Phoenix.Socket, {params: {_csrf_token: ...}})`, exposes
  `window.liveSocket`, and connects it. All `phx-*` controls, live
  navigation, forms, flash and WebSocket reconnection flow through this.
- `priv/static/assets/vendor/{phoenix.js, phoenix_html.js,
  phoenix_live_view.js}` (generated, git-ignored) are the exact shipped
  browser distributions of the Hex packages pinned in `mix.lock`
  (phoenix.js defines the `Phoenix` global, phoenix_live_view.js the
  `LiveView` global; phoenix_html.js adds link/submit helpers). The root
  layout loads them as deferred scripts before the bootstrap.
- `priv/static/assets/css/tailwind.css` (generated, git-ignored) is compiled from
  the source entrypoint `assets/css/tailwind.css` (tracked: the build has no
  fallback, so `mix tailwind triage` exits non-zero when that source is absent
  and the whole asset step fails with it). `priv/static/assets/css/app.css`
  (tracked, hand-written) holds this application's semantic classes and design
  tokens and is loaded *after* Tailwind, so it stays authoritative.

Generated assets come from two sources, and the difference matters:

```bash
mise x -- mix assets.setup   # builds Tailwind, then copies the pinned dists
```

- The **vendor scripts** are copied from the already-fetched deps — never
  committed and never downloaded.
- The **Tailwind CLI is a downloaded standalone binary**, fetched once into
  `_build` by `mix tailwind.install --if-missing` and pinned to an exact version
  in `config/config.exs`. This is the project's one build-time network fetch: it
  is cached after the first run, needs no Node/npm, and ships nothing to the
  browser. `--if-missing` keeps re-runs offline.

`mix setup`, `mix test`, `mix precommit` and `mix ci` run this automatically, so
a clean checkout has the files after the documented commands. If a page ever
logs `[triage] Phoenix client scripts are missing`, run `mix assets.setup`
and reload.

### Tailwind CSS

- Source `assets/css/tailwind.css`; build `mix tailwind triage` (or
  `mix assets.setup`); output `priv/static/assets/css/tailwind.css`.
- The build is deterministic — the same sources and pinned version produce the
  same bytes — and is git-ignored output regenerated by `mix assets.setup`,
  exactly like the vendor scripts.
- Nothing here is digest-aware yet: this repository configures no
  `cache_static_manifest`, no `assets.deploy` step and no release target, so a
  future deploy path has to run `mix assets.setup` (plus its own digest step)
  before packaging, or it will ship without the generated sheet.
- `@import "tailwindcss" source(none)` disables Tailwind's automatic
  project-wide scan, so only `lib/` contributes classes and `deps/`, `_build/`
  and the evidence notes cannot.
- `config/dev.exs` runs the CLI with `--watch`, so edits under `lib/` rebuild
  the stylesheet without restarting the server.
- The `@theme` block maps the two scale names the generated Phoenix components
  use onto this application's own tokens, so a utility cannot introduce a
  colour the rest of the stylesheet does not define.
- daisyUI is **not** used. The former `priv/static/assets/default.css` was a
  frozen Tailwind v4.0.9 + daisyUI artifact with no build behind it; it has been
  removed, and the classes it uniquely supplied are now either emitted by the
  Tailwind build or defined in `app.css` — including the `hero-*` icon masks
  `CoreComponents.icon/1` renders, which are inlined in `app.css` because this
  project has no Node plugin that could extract them from `deps/heroicons`.
  `test/triage_web/assets_test.exs` covers the wiring: stylesheet order in the
  root layout, that the served stylesheet is byte-identical to the generated
  file, that a rebuild is byte-stable, that the CLI version and the `:triage`
  profile match the configured source and output, that the dev watcher runs that
  same profile, that `@source` is exactly `lib/` (one live directive, comments
  excluded), and that every icon rendered from a literal `name="hero-..."` has
  its own `mask-image` artwork. A clean-checkout build is covered by the
  `assets.setup` step of the `test` and `ci` aliases rather than by a test;
  `scripts/tailwind_assets_probe.exs` adds a DB-free fresh-destination build and a
  synthetic `.heex` scan witness.

## What PR 1 covers

- Advisory list grouped by CVE with team/environment filters and URL-restorable state.
- Finding detail: source facts, deployment scope, lifecycle history (appeared /
  resolved / reopened), other occurrences of the same advisory.
- Image identity by immutable digest; unknown deployment context stays unknown.
- Suppressed findings hidden by default and labelled when included — suppression
  is not mitigation evidence. Resolved findings never render as active.
- Safe rendering of hostile third-party text (auto-escaping in HEEx).

## What PR 2 adds — scoped local cases and manual reviews

- `live "/cases/:id"` (`TriageWeb.CaseLive.Show`): a case is opened **only** from a
  finding detail whose team and environment are both explicitly selected; a team
  is never guessed from placements.
- Opening a case captures a **frozen evidence snapshot** (plain string-keyed JSON
  payload with a deterministic content hash) of the synthetic local inventory for
  that exact owner/environment. One stable case per finding occurrence and
  explicit scope — repeated opens converge on the same case.
- The case page renders the frozen snapshot (never a live preload), a manual
  assessment form (applicability / priority / next action / rationale), and an
  append-only history of case events, snapshots and reviews. Older snapshots stay
  inspectable; reviews tied to older evidence are labelled as needing revalidation.
- Reviews are recorded by the server-owned `local-operator` identity — explicitly
  unauthenticated. Saving a review approves nothing, activates no suppression and
  claims no remediation; an exception proposal is only a proposal.
- Review submission is idempotent per token: a queued double click replays the
  original review instead of writing a second one; a reused token with different
  content is rejected. Stale tabs conflict with the draft and original binding
  preserved — never a silent rebase.
- Evidence refresh is explicit and two-click confirmed, appending a new snapshot
  only when the captured content actually changed; older evidence and reviews
  are never modified (PostgreSQL triggers reject UPDATE/DELETE on snapshots,
  reviews and events).
- Malformed case ids, scope parameters and event bodies fail visibly with no
  writes.

## What PR 3 adds — read-only Review Queue

- `live "/cases"` (`TriageWeb.CaseLive.Index`): a read-only queue of **saved**
  review cases, one row per `(finding, owner, environment)` case, ordered
  **newest opened first** (`id DESC`, fixed page size 25). Browsing never opens,
  writes or approves anything; there is no polling or automatic mutation, only
  an explicit **Reload queue** button.
- **Filters**: team and environment combine with AND; **All** is a read-only
  aggregate view, never an unscoped writable case. Options come from saved case
  scopes (retired teams/environments stay selectable). A valid-but-unknown scope
  shows an honest empty result, never a silently broadened scope. Changing the
  scope resets the cursor to the newest page.
- **Pagination**: keyset cursor in the URL (`?before=<case id>`), with
  **Older cases** / **Newest cases** controls. No page totals; browser Back
  restores earlier cursor URLs.
- **Badges** (not filters or sort keys): each row shows a review badge
  (*Awaiting review* / *Current review* / *Needs revalidation*) and an evidence
  badge (*Current* / *Changed* / *Source out of scope* / *Source missing*).
  These are honest local statements only: *Current* means the captured snapshot
  hash still matches the **local** source facts — not production freshness;
  *Current review* is not an approval, exception or remediation claim; a
  historical review's priority is not a recomputed queue priority.
- **Navigation**: the shared header links Findings and Review Queue; the home
  page has a queue CTA; every row links to its case detail carrying the row's
  **saved** scope, and the case detail links back to the queue scoped to the
  case's saved scope. Full rationale, evidence payloads and history stay on the
  existing case detail page.
- Malformed scope values, cursors, wrappers and event bodies fail visibly with
  no rows from a previous valid state, no widened scope and no writes.

## What PR 4 adds — local lifecycle feed

- `live "/whats-new"` (`TriageWeb.WhatsNewLive`): a read-only, inventory-wide feed
  of recorded `finding_events` lifecycle entries ("What's New"), one row per
  event, ordered by record id (newest first), fixed page size 25 with Older /
  Newest cursor controls and an explicit **Reload**.
- Labels are deliberately literal: *First observed locally* / *No longer observed
  locally* / *Observed again locally*. The finding and image values shown are the
  **current** local metadata joined to an existing event, not frozen history;
  where the row says *Recorded observation time* it is the event's `occurred_at`.
- Optional team/environment filters combine with AND on the **same** recorded
  placement and are display scoping only — never historical attribution, and not
  an authorization boundary. Invalid URL parameters or event bodies clear every
  row, link and pagination control instead of widening to All.
- There is no timer, polling, notification or write in this slice; suppression is
  not mitigation and absence is not remediation.

## The Timeline tab — recorded history over time

- `live "/timeline"` (`TriageWeb.TimelineLive`): a read-only history view over the same append-only
  `finding_events` records. Days stack newest first, a CVE reads as an arrow across the days it was
  recorded on, and a connector joins an arrow wherever two adjacent days both have a recorded
  observation. Selecting a CVE opens a drawer with paged lifecycle events, full-history aggregate
  counts, saved cases and recent assessment/audit previews. Full case records remain linked.
- A weekday-by-week grid (`#tl-grid-table`) counts the CVEs whose **first recorded observation** falls on
  each day, oldest week on the left. It is a real table with a caption and a text equivalent per cell, so
  the picture is never the only carrier of meaning.
- A connected chart (`#tl-chart`, `live/timeline_live/chart.ex`) draws one SVG track per CVE across the
  window's days: a labelled axis with week starts, weekday letters and a *today* line; a severity chip and
  CVE label per track; one marker per recorded day; a solid arrowed segment for two adjacent recorded days;
  a dashed arrowed segment for two recorded days with **no recorded observation in between**; a dashed entry
  tick when the CVE was also recorded before the window; and a pin, never a line, for a lane with a single
  recorded day. Every segment and marker carries a hover description in the same literal vocabulary as the
  day bands.
- The chart is plain inline SVG rendered server-side, with one arrowhead `<marker>` per state. This app has
  no asset bundler, so a JavaScript charting library would mean vendoring a minified bundle and a LiveView
  hook while giving up server-side rendering and ExUnit coverage of the markup. It is bounded to the 12 most
  severe lanes with the bound stated on the page, and it is `aria-hidden` with a caption that says so: every
  marker it draws is already listed as text in the day bands and counted per CVE in the lane table.

- Wording is deliberately literal, and matches the What's New vocabulary: *no longer observed in local
  inventory* (never remediation), *Assessment recorded* (never approval), and a suppression flag shown as
  **imported scanner state with no recorded date or author**. Event rows carry the **current** local
  metadata joined to an existing event, and a day with no row says exactly that.
- Assessment counts use each case's own owner/environment, not another team's placement on a shared
  image. SQL groups windowed assessment counts by UTC day. Day-band lifecycle counts cover all loaded
  events before the 25-row display cap, and event database IDs keep same-day rows and links distinct.
- Judgment and case history are ordered by `TriageWeb.CaseLive.Format.timeline_entries/1`, the same
  definition the full case page uses. Drawer previews load at most 25 assessments and 25 audit events
  per case in three batched queries, without snapshot payloads or idempotency tokens. A visible notice
  and **Open case** link preserve access to the complete record when a preview is truncated.
- Window rendering is bounded to 25 rows per day band, 2000 events, 50 lanes and 10 case previews per
  CVE. Aggregate case/review totals are independent of those preview limits. A 4/8/12-week window is
  offered by the UI; invalid parameters render an error rather than a widened view.
- The drawer pages lifecycle events in chronological `(occurred_at, id)` order, 50 at a time, and
  saved cases by ascending ID, 10 at a time. **Next page** and **First page** links retain owner,
  environment and window. The `events_after` and `cases_after` URL parameters are positive bigint
  record IDs belonging to the selected scoped history; selecting a CVE, closing the drawer or changing
  filters resets them. The same options are accepted by `Triage.Timeline.cve_detail/2`, not
  `list_timeline/1`. Detail lanes return scalar `observed_day_count` instead of every historical date;
  totals cover the full recorded history, not merely the selected page.
- These bounds apply to history reads and projections, not every inventory cardinality: the detail
  header still loads matching occurrence metadata, and the full case page retains its existing full
  history contract. Nothing on a timeline read path writes.

## Historical snapshot import (`mix triage.import`)

Approved historical exports can be reconciled offline with the local inventory.
The command is **dry-run by default**; nothing is written without `--apply`:

```bash
mise x -- mix triage.import --file priv/snapshots/legacy-export.json
mise x -- mix triage.import --file priv/snapshots/legacy-export.json --apply
```

- **Format** (`"format": "triage.snapshot"`, `"version": 1`): `images[]` with
  `digest`, optional `repository`/`tag`/`description`, `placements[]`
  (`namespace`, `owner`, `environment`, optional `active`, `first_seen`,
  `last_seen`) and `findings[]` (`cve`, `package_name`, `package_version`,
  optional `severity`/`fix`/`url`/`description`/`suppressed`/`resolved_at`,
  required `first_seen`/`last_seen`, and `events[]` of
  `{event: appeared|resolved|reopened, occurred_at, note}`).
- **Strict parsing**: unknown keys, wrong format/version, malformed timestamps,
  blank/unsafe text, unknown severity or lifecycle names, duplicates at every
  identity level and explicit document/record/string budgets are all reported
  with a JSON path — every problem, not just the first — and exit non-zero
  without writing. Blank optional text normalizes to `nil`, and imported
  placement `owner`/`environment` obey the same 120-character scope contract as
  the UI filters.
- **Read-only reconciliation** (`Triage.Import.dry_run/1`) reports per record
  `create` / `update` / `unchanged` (events also `existing`), uses a fixed
  number of SELECTs regardless of snapshot size, and emits the same
  resolution-preservation warning (with the real indexed path) that an apply
  would emit.
- **Atomic apply** (`Triage.Import.import_snapshot/1`): the whole snapshot is
  written in one transaction; any failure rolls everything back. Every writer
  re-validates a normalized snapshot and takes a transaction-scoped PostgreSQL
  advisory lock before re-reading the inventory, so concurrent imports converge
  instead of duplicating lifecycle rows. Identity is the same as the rest of the
  application (images by digest, placements by `(namespace, owner,
  environment)`, findings by CVE/package/version, events by `(event,
  occurred_at)`), so reimporting the same snapshot is a no-op and reimports only
  rewrite rows whose metadata actually differs.
- **Stale snapshots are rejected conservatively**: a snapshot that would move a
  recorded `last_seen` earlier or `first_seen` later is refused before any write
  with an indexed path. `generated_at` is not treated as authoritative source
  ordering (no source history is persisted); same-time metadata overwrite is the
  documented policy.
- **Human work is never touched**: imports create/update inventory and lifecycle
  rows only. Review cases, evidence snapshots, reviews and case events are never
  updated or deleted, and an omitted `resolved_at` is never treated as resolution
  — the recorded local value is preserved and a warning is printed instead.
- The command reads a local file only: no network, no collector, no credentials.

## Current PR4/PR5 verification status

Independent affected-path recheck (2026-09-10): **PASS for the synthetic/local
contract**, after fixing residual public-map validation, bounded-input and stale
preview/CLI failures plus the destructive concurrency-test default. One fresh
full `mix precommit`: **337 passed**; six independent direct probes passed,
including multi-connection lock contention, warning parity, late-failure atomicity
and complete review-row preservation. Seven actual CLI runs verified success/
repeat and controlled stale/oversize/obsolete-flag errors. Dev/shared full-row
and schema hashes were unchanged; the sole owned DB was dropped.

`validate/1`, `dry_run/1` and `apply/1` accept the plain atom-keyed normalized
snapshot returned by `parse/1`, not raw string-keyed maps. Unknown atom/string
keys and malformed shapes are rejected before DB work. Shape/record/aggregate
byte budgets precede conversion; oversized/control-only whitespace is rejected,
while small space-only optional fields normalize to nil. Stale dry runs return
indexed errors matching apply, which the CLI prints with a nonzero exit.

PR4's earlier **29/29 browser** and query-telemetry evidence is retained because
protected UI/assets/Inventory/Cases/config/migrations match its verified manifest;
the browser journey was not rerun. **BLOCKED:** historical original-baseline proof
and import of a real approved export (neither is available). No legacy credentials
or data were accessed. Details: `PR5_PLAN.md`, `PR4_PLAN.md` and temporary evidence
`/tmp/triage-import-final-recheck.md`. No commits.
## Offline collection adapter (`Triage.Collection`, PR6)

A read-only adapter that can crawl the security GraphQL source and produce a
normalized report. It is **disabled by default** and performs no network access:
there is no default endpoint and no default credential.

- `Triage.Collection.run/1` returns `{:error, %DisabledError{}}` unless an
  operator supplies an explicit `Triage.Collection.Config` **and** an explicit
  transport. Plain `http` is accepted only for a test-only loopback endpoint.
- Two-stage read: owners -> image inventory, then per-image findings with the
  mandatory engine. The status marker is observational only, never a freshness
  cursor, and no pagination is invented.
- Identity is the immutable image digest (never the rotating API id); placements
  aggregate across owners with an explicit environment; findings key on
  `(digest, advisory, package, version)`.
- Claimed counts are compared against raw open + suppressed **before** dedupe.
  A positive claimed count with an empty result is a failure; other drift is an
  explicit incomplete warning. Malformed/null/missing identities never imply
  completeness, and conflicting duplicates never silently pick a severity or
  suppression state.
- Measurements are not historical snapshots: `first_seen`/lifecycle history is
  never synthesized. A snapshot preview is offered only when the mapping is
  lossless; otherwise blockers are returned for UNKNOWN/NEGLIGIBLE/unsupported
  metadata (never mapped to LOW and never dropped). The normalized report is
  preferred over a misleading importable snapshot.
- `Req` built-in retries and redirects are disabled: 3xx/401/403 are terminal
  sanitized auth/redirect failures and `Location` is never followed; GraphQL
  errors are terminal. Transient statuses retry within explicit bounds and a
  total deadline. Response bytes are bounded before decode via streaming.
- No inventory writes, no jobs/schedules/run tables, no UI, and no
  `Triage.Repo` reference in production collection. Scheduling/interval floors
  are deliberately deferred to PR7 (no persistence yet).

Collection is not scheduling or remediation: completeness within the requested
scope is never authority to resolve absence.

## Boundaries

- **Synthetic demo data only** (`lib/triage/seeds.ex`). Nothing here touches the
  legacy collector, a security API, or production systems.
- **Unauthenticated demo** — bind to loopback; team filtering is not authorization.
- Re-running seeds is idempotent and never invents lifecycle history.
- `mix triage.import` reads a local snapshot file and is dry-run by default;
  `--apply` writes inventory/lifecycle rows only and never review data.
- PR 2 adds local case review only (see above); authentication, shared deployment,
  AI and remediation stay in later PRs per `../IMPLEMENTATION_ROADMAP.md`. The
  source inventory remains read-only.


## PR6 integration (2026-09-11) — two-way fanout integrated

Confirmed: compile --warnings-as-errors exit 0; `test/triage/collection/ --seed 0` 66 passed
(targeted_final.log); ONE `mix precommit` 401 passed, 2 skipped, exit 0. Guarded owned DB
`triage_test_pr6_integ_final` (literal, absent before create) with explicit
`MIX_ENV=test MIX_TEST_PARTITION=_pr6_integ_final` on every Mix/DB step. Protected
`triage_dev`/shared `triage_test` full-row+schema hashes unchanged
(`5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`); protected source
manifest unchanged vs predecessor. Integration fixes: struct-literal `@defaults`, list `++`,
dead-clause/`inspect` removal, `map_size/1`, compile-time `Mix.env() == :test` transport/entry
gates, detail reconciliation ignores rotating id + owner-scoped `usedInNamespaces`, and a new
`Config.max_payload_depth` so the client envelope-depth guard is decoupled from the normalize
record `max_depth` budget. Prior FAIL/verification history above is preserved; the earlier
3-way fanout failure is not rewritten. See /tmp/triage-pr6-integration-final/INTEGRATION_SUMMARY.md.



## PR6 integration closure (2026-09-11, partition `_pr6_integ_final`)

Post-doc verification added after the integration section above:

- Direct contract probes (`/tmp/triage-pr6-integ-final/probe2.exs`, `probe2.log`): **15/15 PASS,
  PROBE2_EXIT=0**. Covers controlled `run(%{})`/`run(config: nil)`, no-endpoint/https/localhost
  rejection, arbitrary-transport rejection, forged `Transport.Req` state (post and poisoned `new/1`)
  rejection, `Preview.build_snapshot/1` absent, provenance blocker, non-actionable default report,
  incomplete => not complete, Bearer/token-KV sanitization.
- Probe-found defect fixed: `Report` list fields default to `[]` and `Preview.blockers/1` guards
  `findings/suppressed/images`, so `Preview.to_snapshot/1` no longer crashes (`:erlang.++(nil, nil)`)
  on a minimally-constructed `%Report{}`.
- Final re-verify (`/tmp/triage-pr6-integ-final/final_verify.log`): compile `--warnings-as-errors`
  COMPILE_EXIT=0; `mix test test/triage/collection/ --seed 0` **66 passed**, TEST_EXIT=0; ONE
  `mix precommit` **401 passed, 2 skipped**, PRECOMMIT_EXIT=0; owned DB dropped (`DROP DATABASE`,
  ABSENT_AFTER=[]).
- Baselines (`/tmp/triage-pr6-integ-final/compare.log`): own protected-after manifest equals
  predecessor before AND after (`PROTECTED_MATCH_BEFORE`/`PROTECTED_MATCH_AFTER`); dev/test full-row
  hashes equal predecessor before (`DEV_ROWS_MATCH`, `TEST_ROWS_MATCH`); dev/test schema sha
  `5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`; 0 `triage_test_pr6%`
  databases remain.
- Pre-existing unrelated warning retained: `test/triage/import_concurrency_test.exs:63`
  `dynamic(false)` type warning (protected test scope, unchanged).



## Independent final Astra recheck (2026-09-11) — **FAIL**

Fresh serialized pass, own literal guard: partition `_pr6_astra_final_r82`, owned DB
`triage_test_pr6_astra_final_r82` (confirmed absent before `ecto.create`; explicit
`MIX_ENV=test MIX_TEST_PARTITION=_pr6_astra_final_r82` on every Mix/DB step; guard
`GUARD_OK=triage_test_pr6_astra_final_r82`; `CONNECTED_OK`; owned DB dropped,
`0` `triage_test_pr6%` databases remain). `app/config/test.exs:12` literal and the
runtime `current_database()` were checked before each effect. No dev/shared writes.

- `mix compile --warnings-as-errors` → exit 0. Owned `ecto.create`/`ecto.migrate` → exit 0.
- `mix run --no-start --no-compile -e 'Mix.Tasks.Test.run(["test/triage/collection/", "--seed", "0", "--no-compile"])'` → **66 passed**.
- Direct fake-loopback probe `/tmp/triage-pr6-astra-final-r82/probe_final.exs` (real Bandit on `127.0.0.1`, no external/live source) → **29 checks: 20 passed, 9 failed**.
- Fresh **compile-time non-test gate**: with `Mix.env(:prod)`, `Code.compile_file` of `collection.ex`/`transport.ex` then `Collection.run(config+transport)`, direct `Transport.Req.post/3` and `Collection.run([])` all returned `DisabledError` with **0 loopback requests** (`NONTEST_GATE=PASS`).
- Protected `triage_dev`/`triage_test` full-row + schema hashes unchanged
  (`5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`); 114-file source
  manifest identical before/after (`ALL_PROTECTED_IDENTICAL`); predecessor 50-file
  protected manifest `PREDECESSOR_50_IDENTICAL`. Prior FAIL/verification history above is
  retained unchanged; the earlier 3-way fanout failure is not rewritten.

**Reproduced residual FAILs (9):** forged `Transport.Req` `Authorization: Bearer
SYNTHETIC_SECRET` header sent on the wire; poisoned `.error` returned verbatim with
`token=SYNTHETIC_SECRET`; actual **inflight cancellation** not honoured (returned `CancelledError` only
after 401 ms when the response arrived, despite cancellation flipping mid-request); stalling signal exceeded the
20 ms total deadline (returned at 251 ms); **aggregate** text budget not enforced (50x100 B
under a 200 B budget reported `complete: true`); `max_images: 1` issued **2** detail
requests (bounds digests, not API ids); `Errors.sanitize_message({:token,"SYNTHETIC_SECRET"})`
leaked; injected transport `reason` leaked `{:token,"SYNTHETIC_SECRET"}`; malformed image id
`not-a-uuid-SYNTHETIC_SECRET` landed in `report.failures`. Separately observed:
`Report.actionable?(%Report{historical_provenance: true})` is `true` on a forged boolean
while `Preview.to_snapshot/1` refuses the same report as malformed provenance. The raw
harness counted that weak conjunction assertion as a pass; under the requested
no-forged-actionability contract it is a failure. Contract evaluation of the same
29 recorded observations is therefore **19 passed / 10 failed** (raw harness
**20 passed / 9 failed** retained; no rerun). The 114-file identical manifest was
captured before these three authorized verdict-document edits.

Per the bounded-review instruction, no remediation was attempted: extensive residual
safety failure ⇒ **FAIL**, not endless work. The integrator's inherited 66 tests / 15 probes
/ 401 passed + 2 skipped full run is **not** independent signoff. No commits; repo HEAD
`dc4843141b94aa8f9a040eec6aa0ea61978784cc`; `app/` untracked. Full artifact:
`/tmp/triage-pr6-final-astra.md`.


<!-- PR6 closeout 2026-09-11 -->
## PR6 closeout 2026-09-11 — independent Astra re-verification: PASS (limited offline contract)

Fresh guarded run, partition `_pr6_astra_close_q7` (owned disposable DB, MIX_ENV=test/MIX_TEST_PARTITION explicit on every Mix call). Results: compile/create/migrate/drop exit 0; collection suite exit 0; focused probe 3/3 PASS; adapted 29-check probe 29/29 PASS; format exit 0; protected dev/shared DB full-row+schema and protected source manifest unchanged. Call sites local: `app/lib/triage/collection/crawl.ex:79` (`Client.new/4`), `:131/:155/:200/:399` (`Client.query/3`). Bounded offline contract only; no full precommit; no commits. Full record: `/tmp/pr6-astra-closeout.md`.

<!-- PR6 closeout correction 2026-09-11 -->
Correction: the PASS verdict above is amended to **bounded FAIL**. Independent probe
`/tmp/pr6-astra-boundary-probe.exs` (partition `_pr6_astra_close_ind2`) shows a forged client whose
`budget` is a valid `:atomics.new(1, ...)` reference passes `valid_atomics?/1` and then raises
`ArgumentError` (slot 2 out of range) out of `Client.query/3` instead of a controlled error; no
transport call is made. The 80-test collection suite, 3/3 focused probe and 29/29 adapted probe
still pass; only the forged wrong-sized-atomics invalid-state boundary is open. Not repaired per the
bounded instruction. Full record: `/tmp/pr6-astra-closeout.md`.

<!-- PR6 closeout final 2026-09-11 -->
Final: the forged wrong-sized-atomics budget boundary is fixed (`Client.valid_budget?/1` reads atomics
slots 1 and 2) and residual test (13) covers it. Post-fix partition `_pr6_astra_close_ind3` with explicit
MIX_ENV=test/MIX_TEST_PARTITION: compile/format exit 0; `mix test test/triage/collection/ --seed 0` ->
**80 passed, 0 failed**; focused probe 3/3; adapted probe 29/29; owned DB dropped, `triage_test_pr6%` = 0.
Final `client.ex` sha256 `944b8d8320e2a3b75afbac5eaa5186eb01908af1e0f5663951bf8269b3addc0c`,
`residual_test.exs` `f22a8ab500232e9d206fb6c528c9e17010300186834355ddd088cc59d2201d30`.
Verdict **PASS (limited offline contract)**. Full record: `/tmp/pr6-astra-closeout.md`.

