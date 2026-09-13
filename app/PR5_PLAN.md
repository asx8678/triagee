# PR 5 — approved historical snapshot import

Status: IMPLEMENTED; independent affected-path recheck PASS (2026-09-10).
The eight reported fixes were inspected and re-executed, with concrete residual
validation/preview/test-safety failures narrowly fixed and covered (record below).
PR4 browser/telemetry evidence is retained by unchanged protected source hashes,
not claimed newly executed. Historical original-baseline proof and a real approved
legacy export remain explicitly BLOCKED. No commits or external PRs.

## Product choices

- Import is **local-file only**: no network, no collector, no credentials, no
  schema or migration change. The legacy collector stays untouched.
- **Dry run is the default.** Writing requires an explicit `--apply`.
- Identity matches the rest of the application, so reimport is idempotent by
  construction: images by `digest`, placements by
  `(image_id, namespace, owner, environment)`, findings by
  `(image_id, cve, package_name, package_version)`, events by
  `(finding_id, event, occurred_at)`.
- Duplicate records inside one snapshot are rejected at parse time rather than
  silently collapsed or merged.
- **Resolution is never inferred.** A snapshot that omits `resolved_at` never
  clears a recorded local value; the local value is preserved and a warning is
  reported. Absent stays absent.
- Imports touch inventory and lifecycle rows only. Review cases, evidence
  snapshots, reviews and case events are never created, updated or deleted.
- `reopen_count` (a local counter) is never overwritten from an import.
- Strict parsing reports **every** problem with a JSON path, not just the first.
- **Concurrent imports serialize**: every writer takes a transaction-scoped
  `pg_advisory_xact_lock` before re-reading the inventory, so overlapping
  imports converge on `:existing`/`:unchanged` instead of duplicating lifecycle
  identities or failing a unique constraint.
- **Stale observations are rejected conservatively**: a snapshot that provably
  regresses a recorded `last_seen` (earlier) or `first_seen` (later) is rejected
  before any write with the exact indexed JSON path. `generated_at` is parsed
  but never treated as authoritative source ordering, because no source baseline
  is persisted. Same-time metadata overwrite is the documented policy.
- **Explicit budgets** bound the document, nested record counts, collection
  sizes and text bytes before decode/decode-bounded work, and collection
  construction is linear (prepend/reverse).

## Public contract

`Triage.Import` (`app/lib/triage/import.ex`):

- `parse/1` -> `{:ok, snapshot} | {:error, [%{path: String.t, message: String.t}]}`.
  Pure; rejects non-strings, documents over 5,000,000 bytes, invalid JSON,
  non-object documents, unknown keys at every level, wrong `format`/`version`,
  non-ISO timestamps, blank/unsafe text (raw NUL/C0/DEL, invalid UTF-8, >1024
  graphemes or >4096 bytes), unknown severity or lifecycle names, duplicates at
  every identity level, more than 1000 images / 500 placements per image / 500
  findings per image / 200 events per finding / 10,000 total records, and
  placement `owner`/`environment` outside the 120-character UI scope contract.
  Blank optional text (including whitespace-only) normalizes to `nil`; timestamps
  truncate to seconds.
- `validate/1` -> `{:ok, snapshot} | {:error, errors}`. Pure re-validation of a
  normalized snapshot through the same strict parser, so every public write
  boundary re-checks format, enums, text, identities and budgets instead of
  trusting a mutable map. Only plain normalized atom-keyed maps are accepted;
  unknown atom/string keys, aliases and non-map records are rejected, not dropped.
  Shape, collection/total-record and aggregate string-byte budgets are checked
  before normalized-map conversion; JSON callers use `parse/1`. Shape/budget
  rejection may stop early rather than enumerate unbounded errors.
- `dry_run/1` -> `{:ok, %{summary: counts, images: rows, warnings: warnings}}`
  or `{:error, errors}` for invalid/stale snapshots. Read-only, at most four
  SELECTs (four with populated matching inventory; empty lookups skip queries). It shares the
  resolution-preservation warning builder with `apply/1`, including the real
  indexed path `$.images[i].findings[j].resolved_at`.
- `import_snapshot/1` -> `{:ok, report} | {:error, errors}`. Parse + apply.
- `apply/1` -> `{:ok, report} | {:error, errors}`. One `Repo.transaction/1`;
  any failure rolls the whole snapshot back and the error is returned, not
  raised. Returns the transaction's own `{:ok, report}` without re-wrapping.
- `write!/1` -> report. Public so a caller can compose it inside its own
  transaction (used by the atomicity test). It raises `ArgumentError` outside a
  `Repo.transaction/1` **before any query or write**, re-validates the snapshot,
  takes the advisory lock and re-reads the inventory; a provable time regression
  calls `Repo.rollback({:import_rejected, errors})`. The caller transaction
  receives that tagged error; invalid normalized maps raise `ArgumentError`.

`mix triage.import` (`app/lib/mix/tasks/triage.import.ex`):

- `--file <path>` (required), `--apply` (optional; absent means dry run).
- Rejects invalid options, unexpected arguments and missing files before any
  database work. The file size is bounded (5,000,000 bytes) from `File.stat!`
  before `File.read!` and again by `parse/1`. Validation failures print every
  JSON path and exit non-zero without writing.

## Acceptance ledger

- [x] Strict parsing with per-problem JSON paths, including duplicates at image,
  placement, finding and event level — `app/test/triage/import_test.exs`.
- [x] Dry run classifies `create`/`update`/`unchanged` (events also `existing`)
  and writes nothing (row counts unchanged) — `import_test.exs`.
- [x] Fixed SELECT budget (<= 4) at both minimal and large snapshot sizes —
  `import_test.exs` telemetry counter.
- [x] Create on an empty inventory, then reimport is a no-op (counts stable) —
  `import_test.exs` write-path tests.
- [x] Reimport updates only changed metadata and leaves review cases, evidence
  snapshots, reviews and case events untouched (counts equal, case revision and
  current snapshot id unchanged) — `import_test.exs`.
- [x] An omitted `resolved_at` is preserved and reported, never cleared —
  `import_test.exs`.
- [x] A parse failure writes nothing; `apply/1` validates before touching the
  database; `write!/1` inside a caller transaction leaves no partial rows when
  the caller fails — `import_test.exs`. (The older "forced mid-write failure"
  assertion was replaced because the fix now rejects that malformed map at the
  boundary; the caller-transaction rollback regression is retained.)
- [x] Environment-guarded seeding so test setup/reset can never be repopulated
  by synthetic seeds — `mix.exs`, `app/test/triage/test_environment_test.exs`.
- [x] Full suite, compile-warnings-as-errors, formatting and assets —
  `MIX_ENV=test MIX_TEST_PARTITION=_pr5d mise x -- mix precommit` = **315 passed**.
- [x] Real CLI wiring against the development database, read-only: dry run
  reported `create=1` for images/placements/findings/events and left all four
  table counts identical (`PROBE_WROTE_ANYTHING=false`). Invalid snapshot exited
  non-zero with `$.version: unsupported version 2`.
- [x] Public write boundary re-validates normalized snapshots: a mutated
  `version`/control-character/unknown-severity map is rejected with paths and no
  rows — `import_test.exs`.
- [x] `write!/1` outside a transaction raises before any query (0 SELECTs) —
  `import_test.exs` telemetry counter.
- [x] Advisory lock is acquired before the first inventory SELECT —
  `import_test.exs` query-order telemetry.
- [x] Real separate-connection concurrency: two tasks on their own connections
  produce one event row and one image row, both reporting success —
  `app/test/triage/import_concurrency_test.exs`. The current regression requires
  an exact owned-empty-DB opt-in and two distinct PostgreSQL lock waiters behind
  a third connection; ordinary invocations skip it. The earlier lock-disabled
  red check belongs to the historical implementer evidence below.
- [x] Dry run and apply emit the same indexed resolution-preservation warning —
  `import_test.exs`.
- [x] Imported `owner`/`environment` beyond the 120-character UI scope limit are
  rejected with a path; 120 characters are accepted — `import_test.exs`.
- [x] Blank optional text normalizes to `nil` and a reimport is `unchanged` —
  `import_test.exs`.
- [x] Documents, record counts and string bytes are bounded; boundary tests use
  small inputs and no stress probes — `import_test.exs`.
- [x] A snapshot that regresses recorded `last_seen`/`first_seen` is rejected
  before writes with the exact indexed path and leaves rows unchanged —
  `import_test.exs`.
- [x] Independent affected-path recheck of the fixed write path, including
  narrowly repaired failures and regression tests — final record below.
- [x] Imported rows visible in Inventory and What's New: retained prior 29/29
  browser evidence, not rerun; protected UI/assets/Inventory/Cases source hashes
  still match that verified manifest.
- [ ] Import of a real approved legacy export (no approved export exists yet).

## Evidence (2026-09-10)

- `MIX_ENV=test MIX_TEST_PARTITION=_pr5c mise x -- mix test test/triage/import_test.exs test/triage/test_environment_test.exs --seed 0`
  -> **26 passed**.
- `MIX_ENV=test MIX_TEST_PARTITION=_pr5b mise x -- mix precommit` -> **309 passed**
  (before the write-path tests were added); `_pr5d` -> **315 passed** with them.
- CLI dry run: `PROBE_DB=triage_dev`,
  `PROBE_COUNTS_BEFORE/[_AFTER]=[{Image, 9}, {Finding, 44}, {ImagePlacement, 10}, {FindingEvent, 64}]`,
  `PROBE_WROTE_ANYTHING=false`; task exit status 1 for the invalid document.
- Probe artifacts: `/tmp/triage-snapshot-probe.json`,
  `/tmp/triage-snapshot-bad.json`, `/tmp/triage_cli_probe.exs`, `/tmp/bad.log`.
- Disposable test databases used and abandoned by name:
  `triage_test_pr5a`, `triage_test_pr5b`, `triage_test_pr5c`, `triage_test_pr5d`.
  `triage_dev` was never written to, reset, seeded or migrated.

## Independent verification (continuation, 2026-09-10)

Re-verified from the workspace by a fresh run rather than by trusting the
implementation report:

- `MIX_ENV=test MIX_TEST_PARTITION=_pr5f mise x -- mix precommit` -> **315 passed**
  (compile `--warnings-as-errors`, `deps.unlock --unused`, format, assets and
  the whole ExUnit suite).
- End-to-end CLI probe on the disposable partition `triage_test_pr5cli`:
  dry run reported `create=1` for images/placements/findings/events; `--apply`
  committed exactly one of each and **zero** review cases; a second `--apply`
  reported `unchanged=1` / `existing=1` (idempotent); a following dry run
  stayed `unchanged`/`existing`.
- Failure exits: invalid document dropped through to
  `$.version: unsupported version 2` with exit status **1**; a missing file also
  exited **1**. No partial rows in either case.
- Snapshot used: `/tmp/triage-pr5-verify.json`; invalid document:
  `/tmp/triage-pr5-bad.json`.
- All disposable partitions created for these checks
  (`triage_test_pr5a`, `triage_test_pr5cli`, `triage_test_pr5f`) were dropped
  after use. `triage_dev` and the shared `triage_test` were never written to,
  reset, seeded, migrated or dropped.
- `.pi/fabric.json` `prewalk.alwaysRearm` is now `false`, which stopped the
  repeated `Fabric agent depth limit reached (4)` handoff failures.

At that historical checkpoint, independent adversarial verification and browser
confirmation were outstanding. Both are addressed by later evidence below; an
actual approved legacy export remains unavailable and BLOCKED.

## Remaining-review fixes (2026-09-10, continuation)



Scoped fixes for the eight findings in `/tmp/triage-astra-remaining-review.md`.
No migration was edited; no UI, asset, Inventory, Cases or legacy path changed.
No approved export exists, so no real data was imported. Historical failure
evidence from the review is preserved above and untouched; the fixed evidence is
recorded separately here.



Changed files (exact):

- `app/lib/triage/import.ex` — the bulk of the fix.
- `app/lib/mix/tasks/triage.import.ex` — file-size bound before `File.read!`.
- `app/test/triage/import_test.exs` — boundary/regression tests.
- `app/test/triage/import_concurrency_test.exs` — new real separate-connection
  concurrency regression.
- `app/PR5_PLAN.md`, `app/README.md`, `IMPLEMENTATION_ROADMAP.md`,
  `app/PR4_PLAN.md` — documentation/ledger updates only.

Finding-by-finding:

1. **Concurrent duplicate lifecycle identities (HIGH)** — every writer acquires
   `pg_advisory_xact_lock(7433921021337)` before re-reading the inventory.
   `do_write!/1` re-reads after the lock, so the second import sees the first
   commit and reports `:existing`/`:unchanged`. Real multi-connection red/green:
   with the lock disabled the new concurrency test fails with 2 event rows and
   one image unique-constraint error; with the lock both pass with 1 row each.
   Probe `/tmp/triage-import-fixes/probe.json` also shows `event_rows: 1`,
   `image_rows: 1`, both tasks success.
2. **Public `apply/1` bypassed parser validation (HIGH)** — new pure
   `validate/1` re-runs the strict parser over a normalized snapshot; `apply/1`,
   `dry_run/1` and `write!/1` all funnel through it. A mutated `version`,
   control-character description and unknown severity are rejected with paths
   and zero rows.
3. **Public `write!/1` partial commit outside a transaction (MEDIUM)** —
   `write!/1` raises `ArgumentError` when `Repo.in_transaction?()` is false,
   before any query (regression asserts 0 SELECTs).
4. **Dry run hid the resolution warning / wrong path (MEDIUM)** — a single
   `resolution_warnings/3` builder is shared by dry run and apply and reports
   `$.images[i].findings[j].resolved_at`.
5. **Offered owner outside the filter contract (MEDIUM)** — imported
   `owner`/`environment` are validated with the same 120-character/480-byte
   scope contract as `Triage.Activity`; 121 characters are rejected with a path.
6. **Blank optional metadata (LOW)** — blank (including whitespace-only)
   optional text normalizes to `nil`, so a reimport reports `unchanged`.
7. **Stale snapshot overwrite (MEDIUM policy)** — the writer rejects provable
   `last_seen`/`first_seen` regressions with indexed paths before writing, and
   does **not** treat `generated_at` as authoritative source ordering. The
   same-time metadata overwrite policy and the remaining provenance limit (no
   persisted source history) are documented in the `Triage.Import` moduledoc.
8. **Unbounded document/collections/work (MEDIUM)** — document byte cap before
   decode, per-collection and total record caps, text byte caps, linear
   collection construction. Limits are documented in the moduledoc; boundary
   tests stay small.

Commands and counts (all with `MIX_ENV=test MIX_TEST_PARTITION=_pr5fix_7f3a`,
DB `triage_test_pr5fix_7f3a`, verified absent before `ecto.create`):

- `mix test test/triage/import_test.exs test/triage/import_concurrency_test.exs --seed 0`
  -> **34 passed**; red check with the lock disabled -> **0/2 passed** (both
  concurrency tests fail as reproduced).
- **One** `mise x -- mix precommit` (compile `--warnings-as-errors`,
  `deps.unlock --unused`, format, `assets.setup`, full ExUnit) -> **328 passed**.
- Direct probe `mix run --no-start /tmp/triage-import-fixes/probe.exs` ->
  `event_rows: 1`, `image_rows: 1`, `write_outside_transaction_queries: 0`,
  `rollback_result: "raised"`, `rows_after_rollback: 0`.
- Source change set versus the reviewed baseline manifest
  (`/tmp/triage-astra-wave-20260910-r9/source.before.sha256`) is exactly 8 files:
  `app/lib/triage/import.ex` (reviewed hash
  `cdd12acd20c5f4891e33b460bdff8c368a6355ece0b12e250f43f5d92c4a43dc` ->
  `9d5dd3ea980ca272d53956fdb54df7190ec7dfb3caf25cc69d3e0d94da94f103`),
  `app/lib/mix/tasks/triage.import.ex`, `app/test/triage/import_test.exs`, new
  `app/test/triage/import_concurrency_test.exs`, plus `app/README.md`,
  `app/PR5_PLAN.md`, `app/PR4_PLAN.md` and `IMPLEMENTATION_ROADMAP.md`. No UI,
  asset, Inventory, Cases or migration file differs. The final 178-file source
  manifest is retained outside the repository at
  `/tmp/triage-import-fixes/source.final.sha256`; its SHA-256 is recorded in the
  handoff report `/tmp/triage-import-fixes-report.md` (the manifest is not
  embedded here to avoid a self-referential hash).

Cleanup/limits: the disposable database `triage_test_pr5fix_7f3a` was created
from absent, used for every Mix/test/probe operation and then dropped, with zero
remaining connections. `triage_dev` and the shared `triage_test` were read-only
hashed before/after: row hashes identical (`triage_dev` 8-table artifact
`0de53409182fe40a0515c7518ed4e1c6cf635ec7ab3ddd32631ad7e8f9edd3a9`, counts
9/10/44/64/9/9/1/10; `triage_test`
`a9be8ca6e9240512189f0740c514629a51e795e1364c4c6032552bda25d44978`, counts
3/4/8/11/0/0/0/0) and both normalized schema dumps
`5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`. No
approved export exists, so no real data was imported. This was implementer
evidence, not an independent pass; the subsequent independent findings and
recheck below supersede its pending status.



`apply/1` originally wrapped the transaction result as
`{:ok, Repo.transaction(...)}`. `Repo.transaction/1` already returns
`{:ok, report}`, so callers received `{:ok, {:ok, report}}`. The write-path tests
caught it; `apply/1` now returns the transaction result directly and the
regression is covered by the new tests.

## Independent final affected-path recheck (2026-09-10)

Independent session, no nested agents; user/runner-configured identity
`openai-codex/gpt-6-astra`, with no assertion about unseen backend routing.
Actual source was checked rather than accepting the timed-out handoff as proof.

**Residual failures found and fixed:** normalized validation silently discarded
unknown atom/string keys and crashed on non-map inputs; conversion ran before
collection budgets; oversized/control-only whitespace bypassed text checks;
stale dry runs advertised an applicable update and the CLI assumed success.
Nine added importer regressions cover these boundaries, nested malformed records
and DateTimes, every collection/total/aggregate-byte budget, and composable writes.
The CLI now prints controlled indexed stale-preview errors rather than matching
only `{:ok, report}`. Valid small space-only optional text still becomes `nil`.

**Critical test safety correction:** the previous real-commit concurrency module
unconditionally enabled sandbox `:auto` and truncated all eight tables. Now an
ordinary invocation skips those two tests. Explicit `TRIAGE_IMPORT_CONCURRENCY_DB`
must equal both the configured and connected nondefault `triage_test_<partition>`
DB; setup refuses any preexisting application rows BEFORE auto mode/cleanup is
registered. Use only a fresh, absent-before-create, verifier-owned empty DB.
A sentinel-backed ordinary importer+concurrency invocation preserved all eight
full-row hashes (**38 passed, 2 skipped**, before the last three added tests).
Mismatched opt-in and correct-but-populated opt-in each refused both tests
(exit 2), also preserving the sentinel and every hash. The strengthened race
regression requires two distinct PostgreSQL lock waiters on a held third-session
lock; tasks are supervised. These refusal probes are retained in
`/tmp/triage-import-final-c82e/safety-regression.sh` and its named logs.

**Fresh checks, serialized on `triage_test_final_astra_c82e`:**
- Importer + concurrency targeted run: **40 passed** before the final three
  added boundary tests; strengthened concurrency rerun: **2 passed**.
- ONE full `mix precommit`: **337 passed**, including the final **43** importer/
  concurrency tests; compile warnings-as-errors, format, dependency-lock and
  shipped-assets steps completed. Full suite justified by the global sandbox
  mode change, not repeated after success.
- **6/6 independent direct probe tests:** separate real connections show two
  lock waiters and success/one image/one event for both absent-image and existing-
  finding cases, mixing `apply/1` and composable `write!/1`; malformed APIs and
  outside-transaction writes issue **0 queries**; dry/apply warnings match exact
  indexed paths; blank reimport is unchanged; 120-character scope works in
  Activity and 121 is rejected; populated dry runs use **4/4 queries** at 1/55
  findings. Real late DB failure (9 queries, after earlier inserts) and caller
  abort restore all eight full-row hashes. Metadata changes preserve every
  column of **1 case / 1 evidence / 1 review / 2 case-event** rows.
- **7 actual CLI executions:** dry/apply/repeat exit 0 (create 1 image/placement/
  finding/event, then unchanged/existing); stale dry/apply, oversized file and
  obsolete `--dry_run` flag exit 1 with controlled errors. Dry/repeat/failures
  preserve all eight full-row hashes. No approved real export was used.

**Protection/cleanup:** readonly dev/shared rows and normalized schemas unchanged
before/after; counts **9/10/44/64/9/9/1/10** and **3/4/8/11/0/0/0/0**. Owned DB
was dropped and verified absent with zero connections; the probe-only constraint
was removed. No browser/server/daemon/listener was created or stopped; unrelated
preexisting processes were preserved. Exactly eight repository files changed in
this recheck: importer, CLI, their two test files, and PR5/PR4/README/roadmap docs.
Protected UI/assets/Inventory/Cases/config/migrations remain byte-identical to
the prior verified manifest, so the earlier 29/29 browser journey was not rerun.

Final source hashes and compact independent evidence are outside the repository:
`/tmp/triage-import-final-c82e/source.final.sha256` and
`/tmp/triage-import-final-recheck.md`. These documents do not embed their own
manifest hash. Historical original-baseline proof and a real approved export
remain BLOCKED. Advisory serialization covers cooperating import writers under
the configured default transaction isolation, not arbitrary external writers;
no generated_at source-order guarantee or production-capacity claim is made.
