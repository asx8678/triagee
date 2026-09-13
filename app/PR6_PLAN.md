# PR6 — offline collection adapter (read-only)

Status: IMPLEMENTED and test-verified; independent final Astra recheck (2026-09-11) = **FAIL** (9 reproduced residual boundary failures). PR6 is NOT signed off; see the appended final-recheck section at the end of this file.

## Why not 3 parallel leaf writers

The requested fan-out to 3 nonrecursive `neuralwatt/deepseek-v4.1-flash` leaf
writers could not be honored: the Fabric prewalk re-armed on every boundary and
each handoff failed with `Fabric agent depth limit reached (4)`
(`.pi/fabric.json`: `agents.maxDepth = 4`, `prewalk.alwaysRearm = true`). Spawning
children would also be depth-blocked. Per the no-model-substitution rule, no
alternative model was used; the coordinator implemented the frozen contract
directly. The three logical workstreams are recorded here as the owned slices:

- L1 transport/config: `config.ex`, `query.ex`, `transport.ex`, `client.ex`
- L2 crawl/normalization: `crawl.ex`, `normalize.ex`, `report.ex`, `preview.ex`
- L3 fake-server/tests: `test/support/fake_source.ex`, `test/triage/collection/*`

## Scope (binding)

OFFLINE adapter + tests ONLY. No inventory writes; no jobs/schedules/run tables;
no UI; no real data, credentials or live source calls. Source API calls are
forbidden. Req is added as a compatible dependency. Existing `Bandit` is reused
for the fake HTTP server. No importer/schema/migration/Inventory/Cases/CLI
changes. Namespace is `Triage.Collection`.

## Frozen APIs

- `Triage.Collection.run/1` — default DISABLED. Requires an explicit validated
  `Config` and transport; otherwise `{:error, %DisabledError{}|%InvalidOptionsError{}}`
  before any network access. Returns `{:ok, %Report{}}` or `{:error, exception}`.
- `Triage.Collection.Config.new/1` — requires an explicit endpoint (no default),
  no default credentials, bounded integers, http permitted only for a test-only
  loopback endpoint.
- `Triage.Collection.Query` — status/owners/image-list/image-detail builders with
  validated interpolation (UUID image id, unsafe-identifier rejection).
- `Triage.Collection.Transport` — behaviour `post(state, body, opts)`;
  `Transport.Req` (redirects/retries disabled, streamed byte-bound before decode)
  and `Transport.Disabled` (always errors).
- `Triage.Collection.Client` — bounded retries, terminal 3xx/401/403/GraphQL,
  total deadline, request budget, sanitized errors.
- `Triage.Collection.Crawl` — two stage owner->images then image(id, engine).
- `Triage.Collection.Normalize` / `Report` / `Preview` — digest identity,
  aggregated placements with explicit environment, claimed-vs-raw reconciliation,
  conflicts as failures, bounded raw metadata, no lifecycle synthesis.

## Frozen errors

`Triage.Collection.Errors.{AuthError, RedirectError, GraphQLError, TransportError,
ResponseBudgetError, RequestBudgetError, CancelledError, InvalidOptionsError,
DisabledError}`. Messages are sanitized; no credential or Location echo.

## Acceptance ledger

- [x] Disabled default offline entry; injected fake transport / explicit test-only loopback path.
- [x] Two-stage owner->images->image(id, engine); status marker observational only; no invented pagination.
- [x] Digest identity; ID rotation/shared digest; aggregate placements across owners with explicit environment.
- [x] Claimed raw open+suppressed compared before dedupe; positive claimed/empty is failure; other drift explicit incomplete.
- [x] Malformed/null/missing identities cannot imply completeness; conflicting duplicates never silently pick safer severity/suppression.
- [x] Measurements are not historical snapshots; no synthesized first_seen/lifecycle history.
- [x] Bounded raw metadata; response bytes bounded before decode; request/concurrency/records/text/depth/time budgets.
- [x] Preview only when lossless; blockers for UNKNOWN/NEGLIGIBLE/unsupported metadata; never map UNKNOWN to LOW or drop.
- [x] Req retries/redirects disabled; 3xx/401/403 terminal sanitized; GraphQL errors terminal.
- [x] Invalid options controlled before network; bounded cancellation/worker cleanup; no external default endpoint/credentials.
- [x] Fake HTTP tests cover auth/no-retry/no-redirect, engine mismatch, two-stage, id rotation, suppressed/dedupe/conflict/null/partial/error, unsupported severities, budgets, sanitized errors.
- [x] Production collection references no `Triage.Repo`.
- [x] Targeted tests + direct probes then ONE precommit; protected dev/shared hashes unchanged.

## Verification record (2026-09-10)

Owned partition `triage_test_pr6_c9a4` (literal, confirmed absent before
`ecto.create`; guarded `current_database()` check before every Mix/DB step).

- `MIX_ENV=test MIX_TEST_PARTITION=_pr6_c9a4 mise x -- mix compile --warnings-as-errors` — clean.
- `mix test test/triage/collection/ --seed 0` — **37 passed, 0 failures**
  (config 8, client 9, crawl 18, preview 4 after the added budget tests).
- Direct probe (`/tmp/triage-pr6-final/probe.exs`): disabled default and nil
  config both `DisabledError`; no-endpoint and plain-http rejected; https ok;
  `Preview.to_snapshot/1` returns UNKNOWN + missing-history blockers; a report
  with any failure is not complete.
- ONE `mix precommit` — **372 passed, 2 skipped** (skips are the honest
  import-concurrency opt-in; `skip: "requires an owned empty DB opt-in"`).
- Protected `triage_dev` and shared `triage_test`: 8-table full-row hashes and
  normalized schema hash **identical** before/after
  (`triage_dev` schema `5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`).
  Protected source manifest (UI/assets/Inventory/Cases/Import/config) byte-identical.
- Fixes applied during integration (specific causes only): `Config` struct
  `@enforce_keys` default; nested `Req` shadowing (use `Elixir.Req`); stage-one
  failures/warnings were dropped in `run/4`; transport-error wrapping swallowed
  `ResponseBudgetError`; retry wrapper clause; explicit-owner empty result now a
  failure; depth-budget enforcement added; fake-source fixtures use UUID ids;
  fake source preserves nested metadata for the depth test; unique supervised
  child ids.

Changed files (exactly these 12 PR6 files plus docs):
`app/lib/triage/collection.ex`,
`app/lib/triage/collection/{errors,config,query,transport,client,crawl,normalize,report,preview}.ex`,
`app/test/support/fake_source.ex`,
`app/test/triage/collection/{config_test,client_test,crawl_test,preview_test}.exs`,
plus `app/PR6_PLAN.md`, `app/README.md`, `IMPLEMENTATION_ROADMAP.md`, `app/mix.exs`,
`app/mix.lock`. No UI, asset, Inventory, Cases, Import, CLI, migration or
harness-config change; no commits.

## Ownership / serialized integration

The coordinator exclusively owns Mix/build/DB operations after the leaf slices:
compile, targeted tests, direct probes, ONE `mix precommit`, DB guard checks,
protected-hash capture and cleanup. Leaves perform static edits only.


## Independent coordinator re-verification (2026-09-11)



Fresh, guarded re-run from the workspace (not trusting the implementation

report). Owned partition `triage_test_pr6_verify_c` (literal, confirmed absent by

psql before create). Guard: `mix run --no-start` verified `Mix.env() == :test`

and the configured `Triage.Repo` database before every Mix/DB step; the drop

step additionally verified `current_database()` was exactly the owned DB.

- `mix compile --warnings-as-errors` — clean.

- `mix test test/triage/collection/ --seed 0` — **37 passed, 0 failures**.

- Direct probe `/tmp/triage-pr6-final/probe.exs` — disabled default and `nil`

  config both `DisabledError`; no endpoint rejected; plain `http://example.com`

  rejected; `https` accepted; `Preview.to_snapshot/1` returns UNKNOWN +

  missing-history blockers; `Report.complete?/1` is false after any failure.

- ONE `mix precommit` — **372 passed, 2 skipped** (skips are the honest

  `Triage.ImportConcurrencyTest` owned-empty-DB opt-in).

- Protected `triage_dev` and shared `triage_test`: 8-table full-row hashes and

  normalized schema hash identical (schema `5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`).

  Protected source manifest (UI/assets/Inventory/Cases/Import/config)

  byte-identical. Changed-file set is exactly the PR6 files + docs/deps; the only

  `Triage.Repo` mentions in production collection are two moduledoc prose lines

  (no code reference).

- Cleanup: own `triage_test_pr6_verify_c` dropped (0 remaining). A preexisting

  `mix phx.server` (PID 28971, started 2026-09-10 16:50) holds port 4000 and was

  preserved, not started by this work. No other process/listener touched.

- Independent **Astra** verification remains PENDING (parent runs it). The 3-way

  leaf-writer fan-out remains unmet due to the Fabric depth limit; no model

  substitution was used. This is not a claim the full application is done.



## Second independent coordinator re-verification (2026-09-11, partition `_pr6_verify_x7`)



Fresh guarded run, separate owned partition `triage_test_pr6_verify_x7` (psql-confirmed

absent before create; `GUARD_OK` on the configured DB and `CONNECTED_OK` on

`current_database()`). Results, from the workspace rather than the report:



- `mix compile --warnings-as-errors` — clean.

- `mix test test/triage/collection/ --seed 0` — **37 passed, 0 failures**

  (config 8, client 9, crawl 16, preview 4).

- Direct probe — disabled default and `nil` config both `DisabledError`; no

  endpoint / plain `http://example.com` rejected; `https` accepted; UNKNOWN

  severity + missing-history preview blockers; `Report.complete?/1` false after

  any failure.

- ONE `mix precommit` — **372 passed, 2 skipped** (the two skips are the honest

  `Triage.ImportConcurrencyTest` owned-empty-DB opt-in).

- Production collection has **no code reference** to `Triage.Repo` (only two

  moduledoc prose lines).

- Protected `triage_dev` and shared `triage_test`: 8-table full-row hashes and

  normalized schema **unchanged**; protected UI/assets/Inventory/Cases/Import/

  config source manifest **unchanged** (`PROTECTED_SOURCES_UNCHANGED`).

- Cleanup: owned `triage_test_pr6_verify_x7` dropped; **0** `triage_test_pr6*`

  databases remain. Preexisting `mix phx.server` (PID 28971, port 4000) was

  preserved; no other process/listener touched.



Harness and artifacts (temporary): `/tmp/triage-pr6-coord/verify_x7.sh` and

`/tmp/triage-pr6-verify-x7/`. No commits; no schema/migration/UI/harness change.

Repository HEAD remains `dc48431` (unchanged; `app/` untracked).


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

## Independent integration re-verification (2026-09-11, partition `_pr6_vz9`)

Fresh guarded owned DB `triage_test_pr6_vz9` (absent before create, guard OK,
`current_database()` OK): `mix test test/triage/collection/ --seed 0` => **66
passed, 0 failed, 0 skipped**; Astra-derived `probe2.exs` => **15/15 PASS**.
Owned DB dropped (`ABSENT_AFTER=0`, `REMAINING_PR6=0`). The earlier "0
`triage_test_pr6%` remain" claim required dropping the executor's leftover
`triage_test_pr6_verify_me`; it is now absent. No code change by this pass. Old
FAIL/verification history above preserved.




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

