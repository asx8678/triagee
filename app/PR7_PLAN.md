# PR7 scoped replay — acceptance ledger

Historical integration status: serialized integration after all three writer handoffs stopped. Initial replay/CLI/history + collection run: 99 passed. Two additional regressions demonstrated false completeness for missing individual count claims and contradictory detail placements; PR7-only fixes made the 21 replay/CLI/history tests pass. Separate-backend concurrency and fresh-process CLI test/production probes passed. One precommit passed: 436 tests, 2 existing opt-in Import concurrency skips. A final repeated-ID placement regression then failed as expected and was fixed in Replay only; affected replay/CLI/history checks passed 22 tests (no repeated full suite). Migration rollback/remigrate passed. Protected app source and dev/shared-test full dumps matched; owned database and isolated production build removed. Independent final verification pending.

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

Exactly the three blockers below have been repaired in Replay, its tests and
fixtures. No PR6, CLI, Runs, migration, config or protected source changes.
Affected suite: 105 passed (11 Replay + 6 CLI + 8 history + 80 Collection).
Retained adversarial suite: baseline 1/4 with three failures, repaired 4/4 without
modifying its assertions. Final-fixture checks and hashes: `/tmp/pr7-replay-repair.md`.
This is repair evidence, not independent acceptance or a new full-suite signoff.

Current input policy supersedes the original shared-count requirement:
- Inventory requires nonnegative integer `vulnerabilities` and
  `vulnerabilitiesSuppressed`; detail requires `vulnerabilities` and
  `vulnerableComponents`. Missing, null or malformed required counts are incomplete.
  Detail suppressed counts are unrequested fields and rejected, not made optional.
  Normalize still reconciles inventory totals/suppressed and detail totals with
  both finding arrays. Neither required array may be dropped to gain completeness.
- Image and metrics keys are closed per unchanged Query's stage-specific selections;
  namespace objects allow only `id`/`owner`. Unknown evidence, including inventory
  finding arrays, secret/provenance flags and detail placement claims, is incomplete
  and never echoed. Finding records intentionally retain recursively bounded raw
  metadata through Normalize's duplicate/conflict checks; none grants actionability.
- Byte 1 MiB, depth 32, aggregate array values 5000, and object fields 64 are checked
  before Jason. All nonempty array values count, including null/scalars/containers;
  empty arrays add zero children, but count when themselves array elements. Object
  field occurrences include duplicate keys. Escapes/string delimiters are lexed;
  under-budget malformed grammar remains Jason's responsibility. Decoded string
  bounds (4096 bytes) and defensive decoded resource checks remain.
- `complete.json` has only Query-selected fields, without invented finding metadata.
  `suppressed.json` provides genuine excluded evidence. Both are compared in-process
  with the actual unchanged Normalize context used by Crawl; findings are preserved.

No new dependencies, full precommit, production build or unchanged history-race
rerun. Earlier 436 + 2 skipped and independent BLOCKED records remain historical.
## Previous independent bounded final verification — BLOCKED (historical)

Final-tree verification ran 102 tests (22 PR7 + 80 Collection), all passing.
The independent adversarial probe passed 1/4 tests and failed 3 (actual exit 1):
1. Genuine PR6 detail query omits `metrics.vulnerabilitiesSuppressed`; Replay
   requires it and discards the detail, returning zero findings/incomplete where
   the unchanged PR6 Normalize/Crawl context is complete with one finding. The
   current nonempty fixture invents that detail field and is not parity evidence.
2. An inventory `vulnerabilities` array with conflicting finding content is
   ignored while Replay returns complete. Unrequested evidence must be rejected
   or reconciled, not silently omitted under a completeness claim.
3. The 5000-array-element budget runs after Jason decoding, unlike the requested
   predecode record bound. Byte/depth preflight passed the independent trace.

No product repair attempted: these are multiple acceptance/contract blockers,
not a single bounded patch. Fresh CLI exits 0/2/1 and FIFO/symlink rejection,
separate-backend history races, and rollback/remigrate passed. Protected full
row/schema dumps and source baseline matched; owned DB removed; Phoenix 28971
preserved. Production trace was inspected, not rebuilt. No full precommit rerun.
Evidence and exact limitations: `/tmp/pr7-astra-final.md` and
`/tmp/pr7-astra-evidence/`. Earlier integration/writer ledgers below and above are
historical and do not supersede this BLOCKED verdict.

## Frozen contracts
- `Triage.Replay.run(json)` is pure, bounded, returns `{:ok, summary}` for complete/incomplete or a closed error atom. Synthetic only; no caller provenance accepted.
- String-key result: triage.replay.result/v1, synthetic origin, complete boolean, actionable/inventory_changed/historical_provenance false, canonical document SHA-256, numeric counts, allowlisted diagnostics. No source identifiers, metadata, blockers or exceptions emitted.
- CLI `main(argv)` returns `{exit_code, json}`; 0 complete, 2 incomplete, 1 invalid. Regular bounded local files only; no path echo, save/history, startup or Repo. Mix wrapper must exit nonzero.
- Runs `record_result(key, json)` recomputes Replay; stores only summary, never raw JSON or fake report; explicit bounded history APIs only. Parent generates migration serially.

## Input policy
Required exact envelope: format/version/origin/environment/engine/owners/inventories/details. Owners are identifier strings; inventories contain owner and raw images; details contain UUID id and raw image detail. Fixed limits documented in Replay: 1 MiB input, lexical depth 32 before Jason, 4096-byte strings, 5000 total array elements, 64 fields/object, 64 KiB output. Recursive object-key sorting; arrays preserve order. Empty root is valid zero findings. Missing/null nested evidence and conflicts cannot silently complete.

## Original writer trace and acceptance (historical; superseded above)
- [implemented, unverified] Query identity validation -> local context -> Normalize.build -> safe summary projection. No Crawl/Client transport invoked. Preview blockers never projected.
- [implemented, unverified] Envelope/enums/budgets/depth rejection before normalization.
- [implemented, unverified] Inventory coverage, duplicate owner/id/digest conflicts, missing detail, placement scope, raw count reconciliation.
- [implemented, unverified] Empty/nonempty complete/incomplete fixtures; secrets, invalid, size/depth, digest and zero-actionability tests.
- [parent integration pending] CLI exit/file behavior; Runs recomputation/idempotency/retention; generated migration and configuration registration.

## Fanout provenance and boundaries
Three-way low Astra fanout requested: replay contract writer (this handoff), CLI writer, history writer. This writer did not spawn nested agents. Sibling CLI changes were observed during work; parent owns verification of actual fanout model and completion provenance. No claim of independently verified model settings.
Replay ownership: app/lib/triage/replay.ex; app/test/triage/replay_test.exs; app/test/fixtures/replay/{empty,complete,incomplete}.json; app/PR7_PLAN.md. Other writers retain disjoint CLI/history paths.
No Mix, compile, format, build, tests, DB, migration, live API, credentials, commits, harness, existing migrations, inventory/Import/Cases/UI edits by this writer. Parent serializes runtime only after all writers stop.
