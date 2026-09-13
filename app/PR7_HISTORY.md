# PR7 summary receipt ledger

This is a local synthetic replay receipt ledger, NOT a raw observation store or
historical inventory. No first-seen times or provenance are inferred. Replay and
its CLI do not persist; only explicit API callers that already started Repo use
`Triage.Replay.Runs.record_result(key, json)`.

The API recomputes `Triage.Replay.run/1` before opening a transaction. It accepts
no report struct or arbitrary summary map. Invalid replay input returns Replay's
closed reason without SQL. Keys must be nonempty valid UTF-8, at most 128 bytes;
only their lowercase SHA256 is stored. Raw keys, JSON, file paths, identifiers,
metadata and credentials are not stored. Hashes are not encryption and can be
correlated or guessed for low-entropy inputs; restrict database access.

Stored fields: generated ID, key_hash, canonical input_sha256, safe summary,
complete/incomplete outcome, received_at and expires_at. Receipt times are local
storage timestamps, not source-asserted observation times. Summary JSON is bounded
at 64KiB in the API and in PostgreSQL's textual JSON representation (the database
bound is conservative because jsonb may add whitespace). No updates are permitted
by the new table's trigger. No existing tables or migrations are changed.

Same key and canonical digest returns the original unexpired row, with unchanged
TTL; a different digest returns `:idempotency_conflict`. Expired same-digest retries
return `:expired`. After explicit purge the key can be used anew. All insertion,
quota/dedup and purge operations use transaction advisory key 7433921021338,
distinct from Import's 7433921021337. At most 1000 physical rows can be retained by
this API; direct SQL writers are unsupported and must not bypass the context.

`get(key)` returns `{:ok, row_or_nil}`. `list(limit: 100, after_id: 0)` returns
`{:ok, rows}` in ascending ID order; limits are 1..100. Both hide expired rows.
`purge_expired!()` explicitly removes expired rows under the same lock and returns
`{:ok, count}`. There is NO automatic purge. Operators must schedule/call this API
to achieve physical retention; expired rows continue to consume quota until then.
TTL is 30 days and retry does not renew it. Backups need their own retention policy.

Closed local errors: invalid_key, invalid_result, invalid_pagination,
idempotency_conflict, expired, quota_exceeded, database_unavailable, database_error.
Connection/PostgreSQL failures are never reported as success and their raw text is
not returned. Queries disable parameter logging. Unexpected programming errors
are not swallowed. Caller authentication/authorization is outside this explicit
internal API; no route, UI, startup hook or CLI save option is added.

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

## Previous independent bounded final verification (historical)

All eight history tests passed again on the final tree within 102 passing PR7 +
Collection tests. The retained concurrency script was independently rerun with
only the owned literal DB guard changed: eight separate same-content backends,
conflicting contents, eight contenders at 999 rows, purge/insert serialization,
and unavailable Repo assertions passed. Rollback removed table/function and
remigration passed. The absent-before owned partition was dropped and verified
absent afterward; protected dev/shared-test full dumps and sources matched.
Summary-only loss is intentional, but this ledger faithfully persists Replay's
current defects: overall PR7 is **BLOCKED** by three independent replay acceptance
failures. No source fixes or full-precommit rerun. See `/tmp/pr7-astra-final.md`.
The integration and writer-era evidence below is preserved as history.

## Serialized integration evidence

Generated `20260911123348_create_replay_runs.exs` through `ecto.gen.migration`
after reading task help; draft applied and migration passed on the absent-before
owned `triage_test_pr7integration_0911` only. Eight sequential history tests pass.
Separate checked-out PostgreSQL backends demonstrated eight identical retries
produce one receipt; conflicting contents produce one receipt + one conflict;
eight contenders at 999 rows permit exactly one insert; purge/insert results
serialize legally and retry leaves one receipt. Probe cleaned all receipt rows
and stopped its Repo; unavailable Repo returns the closed error. Independent
final verification pending. The following is the retained writer-era ledger.

## Acceptance ledger / integration status

- Implemented: recomputation before SQL; key hash only; bounded safe summary.
- Implemented: atomic dedup/quota/purge, fixed TTL, hidden expiration, no renewal.
- Drafted: one new table with unique/hash/JSON/outcome/expiry constraints,
  expiry index and UPDATE rejection trigger.
- Authored sequential DataCase tests: safe persistence, canonical retry/conflict,
  incomplete result, malformed no-SQL input, expiry/purge, physical quota,
  dedup at quota, pagination, immutability, DB constraints, rollback and inventory
  snapshot equality.
- NOT RUN: all tests, formatting, compile, build, migrations, DB and concurrency
  probes. Fanout prohibition intentionally takes precedence over precommit.
- Integration must first stop all writers, read `mix help ecto.gen.migration`,
  generate a fresh `create_replay_runs` migration, then copy the reviewed draft
  from `/tmp/pr7-create-replay-runs-migration.exs` into that generated file.
- Then serialize format/compile/migrate and targeted replay/history tests. Probe
  concurrent same-key and distinct-key near-quota calls on separate connections,
  purge/insert serialization and unavailable Repo behavior with guarded local DB
  only. Never use live services or credentials.
