# KEV intelligence coverage — execution record

Slice: make the cached known-exploited signal actually usable and stop the UI from
presenting an empty cache as evidence of safety. Same working tree, no commit, no
staged-index change: this delta is unstaged on top of the staged stylesheet
checkpoint, whose index still verifies (see Acceptance ledger).

## Defects found and fixed

1. **The KEV cache held a 50-row prefix of the feed.** `lib/triage/intel/client.ex`
   parsed the CISA feed through `Enum.take(50)` before the rows were cached, so
   `Intel.cached_kev/1` could only ever match 50 advisories. `Triage.Risk.classify/1`
   escalates on `known_exploited`, so for every advisory outside that prefix the
   policy's top branch was unreachable while the page printed "No cached entry".
   Fixed: every feed entry is parsed and cached.
2. **KEV's actionable fields were dropped at ingest.** Only `cveID`,
   `shortDescription` and `dateAdded` were read, so `requiredAction`, `dueDate` and
   `knownRansomwareCampaignUse` — the part that says what to do and by when — never
   reached the cache or the page. Fixed: the three fields are parsed, persisted
   (nullable columns) and rendered per advisory.
3. **The response bound would fail the feed closed, not truncate it.** `@max_response_bytes`
   was 2,000,000 and an oversized body is refused with `{:response_too_large, n}`;
   the KEV feed is a single growing multi-megabyte document. Fixed: the bound is
   8,000,000 and still enforced before decode.
4. **The byte bound was only enforced inside the real transport.** `req_get/1` checked
   size, so an injected fake (already documented as the testing path) bypassed it
   entirely. Fixed: `get/2` interprets a transport result in one place — status
   first, then the bound — and a non-200 or redirect result never carries its body
   forward. This is what made the bound testable.
5. **The documented transport shape was not accepted.** The moduledoc specified
   `req_fun.(url) -> {:ok, %{status, body}}` while `get/2` passed its result straight
   to a parser; the first payload-bearing fake returned
   `{:error, {:unexpected_body, :other}}`. Fixed: both documented shapes are accepted
   and five transport outcomes are pinned by test.
6. **"No cached entry" was indistinguishable from "cache never refreshed".** The panel
   showed one caveat sentence and no row count or refresh outcome. Fixed: the panel
   reports rows stored and the last refresh receipt per source, explains an empty
   cache as a cache fact (never an advisory fact), and renders the banner as a
   **warning** whenever the KEV cache is empty.

## Files

| Path | Change |
| --- | --- |
| `app/lib/triage/intel/client.ex` | full-feed KEV parse, actionability fields, 8 MB bound, single-point transport interpretation |
| `app/lib/triage/intel.ex` | three new advisory fields + cast list |
| `app/priv/repo/migrations/20260915103805_add_kev_actionability_to_intel_advisories.exs` | nullable `required_action`, `due_date`, `known_ransomware` columns |
| `app/lib/triage_web/live/cve_live/show.ex` | cache-status assigns/helpers, warning banner, per-row required action, due date and ransomware state |
| `app/test/triage/intel_client_test.exs` | new: full-feed parse, actionability, hostile text, transport outcomes, oversized refusal, malformed feed |
| `app/test/triage/intel_cache_test.exs` | actionability round-trip (KEV vs NVD rows) |
| `app/test/triage_web/live/cve_live_test.exs` | populated-cache panel, empty-cache warning panel, wording sync |

## Acceptance ledger

| Check | Result |
| --- | --- |
| `mix test` (focused: intel_client, intel_cache, cve_live, read_only_requests) | **30 passed, 0 failures** |
| `mix test` (full suite) | **705/712 passed, 2 skipped, 7 failed** — the identical seven pre-existing Timeline window tests (baseline 696/703, +9 new tests, no regressions) |
| `mix compile --warnings-as-errors` (test) | exit 0 |
| `mix format --check-formatted` | exit 0 |
| `mix credo --strict` | exit 0 — 1792 mods/funs, no issues |
| `mix dialyzer` (`MIX_ENV=test`) | exit 0 — `Total errors: 0, Skipped: 0, Unnecessary Skips: 0` |
| migration on the local PostgreSQL 16 cluster | applied: `alter table intel_advisories` |
| staged checkpoint integrity | 224/224 manifest paths still match their **staged** blobs (0 mismatches); this slice is unstaged and does not touch that index |
| live CISA feed | **not fetched** — see Limits |

## CLI and call-site consistency

- `mix triage.intel --kev` prints `kev: N advisories cached (M rows)`; with the cap
  gone `N == M`, and the oversize error message (`response exceeded #{max} bytes`)
  follows the new bound automatically.
- The panel's KEV wording now matches the flag the overview already documents
  (`mix triage.intel --kev --receipts` exists in the task's `OptionParser`), and the
  receipt vocabulary ("refreshed …", "last refresh failed …") mirrors the overview's
  `OK/FAILED · <relative>` receipt rows.
- `read_only_requests_test.exs` still asserts `Intel.Client.fetch(:kev) ==
  {:error, :intel_disabled}`: the default-off posture is unchanged; no request-time
  download was added and the page performs database reads only.

## Limits

- **The live feed was never fetched.** Ingestion is default-off and no network call
  was made, so "the real feed fits in 8 MB and every entry is cached" is verified
  against a synthetic 80-entry feed, not CISA's current document. Run the operator
  task with approval to confirm the real row count and size.
- **A stale cache still asserts exploitation.** The panel now shows how many rows are
  cached and whether the last refresh succeeded, but it does not judge freshness and
  does not damp an escalation that a stale KEV row produced.
- **NVD stays per-advisory.** There is still no bulk refresh, so NVD coverage depends
  on an operator running the task once per CVE; the panel says so.
- **The exposure input still has no producer** (only `priv/repo/seeds.exs` calls
  `Triage.Exposure.record/4`), so the policy's internet-exposed branches remain
  unreachable in a real deployment. Tracked as P1, not addressed here.
- **The case queue still filters by team/environment only**; CVE/severity/staleness
  filters and the CVE ↔ finding ↔ case cross-links are P1, not addressed here.
- Details-page interaction was verified through LiveView tests, not a browser: no
  browser session was started in this slice.

## Review follow-up (2026-09-15, same working tree, unstaged)

A review of this delta found three defects and closed two test gaps. Every fix is
unstaged; the staged Tailwind checkpoint is untouched (see ledger).

1. **The timeline lanes never received the KEV index.** `TimelineLive` computed
   `Intel.kev_index/1` and assigned `:kev`, but the single `<Lanes.lane_table>`
   call site did not pass it, so the component's `attr :kev, default: %{}` meant
   no lane could ever render a marker: the query was dead work and the fifth of
   the five marker surfaces was silently absent. Fixed in
   `lib/triage_web/live/timeline_live.ex`.
2. **No test covered any of the five marker surfaces.** `kev_marker/1`,
   `kev_note/1` and the findings, queue, case, overview and lanes call sites had
   zero assertions. Six tests were added: timeline lanes (with a no-cache
   negative control), findings list, finding detail (marker and copy control),
   queue row, case header (recorded action, due date, ransomware flag) and the
   overview critical table (with a no-cache negative control). The lanes test
   fails at `timeline_live_test.exs:159` when the pass-through is reverted, so it
   is a real regression test rather than a mirror of the current render.
3. **`lib/triage/intel.ex` was not formatter-clean** (one extra blank line after
   `kev_index/1`), so `mix format --check-formatted` — and therefore `mix ci` —
   failed on the tree. Fixed.

Also added: a context test for the batched `Intel.kev_index/1` read (dedup, blank
and non-binary ids dropped, a missing key means no marker, an empty cache reads
`%{}`).

| Check | Result |
| --- | --- |
| `mix test` (focused: intel_client, intel_cache, cve_live, timeline_live, finding_live, case_live_index, case_live, overview_readability, read_only_requests) | **124 passed, 0 failures** |
| lanes regression test with the pass-through reverted | fails at `timeline_live_test.exs:159` |
| `mix test` (full suite, local PostgreSQL 16) | **721 passed, 2 skipped, 0 failures** — the seven Timeline window tests now pass under the `window_span/1` contract |
| `mix format --check-formatted` | exit 0 |
| `mix compile --warnings-as-errors` | exit 0 |
| `mix credo --strict` | exit 0 — 139 files, 1827 mods/funs, no issues |
| `mix dialyzer` (`MIX_ENV=test`) | exit 0 — `Total errors: 0, Skipped: 0, Unnecessary Skips: 0` |
| staged checkpoint integrity (`git show :<path>` against `evidence/checkpoint/MANIFEST.sha256`) | 224/224 staged blobs match, 0 mismatches |
