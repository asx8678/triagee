# PR7: local synthetic replay CLI

From `app/`, in a prepared build:

```sh
mix triage.replay --file /trusted/local/replay.json
mix triage.replay --help
```

The task runs synchronously and prints one JSON value plus a newline. It exits
**0** for complete evidence, **2** for incomplete evidence, and **1** for invalid
arguments, files, documents, or execution errors. Help is static JSON (exit 0).
The helper `Triage.Replay.CLI.main(argv)` returns `{code, json}` without printing
or halting. Only the Mix task calls `System.halt/1` for nonzero exits.

The task invokes quiet incremental compilation to load code; it never invokes
`app.start` or `app.config`. Compilation diagnostics on an unprepared or broken
build are Mix diagnostics, not replay results. Avoiding runtime configuration
also avoids unrelated production database/endpoint credential requirements.

## Safety and boundaries

- No authentication: **trusted local use only**, not a remotely exposed service.
- No socket, HTTP, Req, Repo, database, application startup, or endpoint access.
- Exactly `--file PATH`, or `--help` alone. Duplicate/unknown options, positional
  arguments, endpoint flags, save/history options, and missing paths fail closed.
  A filename beginning with `-` can be supplied with an explicit `./` prefix.
- The file must be regular and at most **1,000,000 bytes**. The opened raw
  descriptor is checked with `:file.read_file_info/1`, then read once with a
  **1,000,001-byte cap**; growth beyond the input cap is rejected. There is no
  unbounded `File.read/1` after a stat check.
- Final-component symlinks, directories, FIFOs, devices, and other nonregular
  files are rejected before opening. Parent-directory symlinks are permitted.
  The descriptor is checked again after opening. Portable OTP file opening is
  not an atomic no-follow/nonblocking sandbox: the file and ancestor directories
  must remain trusted and stable, not writable by a concurrent adversary.
- Output is at most **65,536 bytes**, excluding the task's newline. Replay owns
  summary validation/redaction. CLI error JSON uses only static classifications;
  it never interpolates filenames, source text, identifiers, OS errors, or
  exception messages. Complete does not mean actionable or historically proven.
- No output file is written. No inventory mutation or implicit persistence.

The separate explicit `Triage.Replay.Runs.record_result(idempotency_key, json)`
history API recomputes replay and stores **summary only**, never raw input. It
belongs to the persistence integration, not this command. There is intentionally
no CLI save/history option and no CLI dependency on that API or its database.

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

Final-tree CLI helper tests passed in the 102-test PR7/Collection run. Actual
fresh processes returned 0 complete, 2 incomplete, and 1 invalid/FIFO/symlink;
JSON assertions passed. The complete process independently showed no app/Repo/
Endpoint startup and zero traced TCP/TLS connect calls with runtime secrets
unset. `System.halt/1` skips `System.at_exit/1`, so the exit-0 instrumentation
is not claimed as a runtime trace of nonzero paths (their source path was read).
Prior isolated-production trace/output was inspected, not rebuilt. Trusted stable
filesystem remains a required precondition. Overall PR7 is **BLOCKED** by replay
fidelity and predecode record-budget failures, not signed off by passing CLI tests.
See `/tmp/pr7-astra-final.md`; the ledger below is historical.

## Acceptance ledger

Serialized integration verified helper and fresh-process exits 0/2/1, FIFO/device/symlink rejection, and test/isolated-production no-startup and zero TCP/TLS connect-call probes. Production needs no runtime DB/endpoint secrets. Existing PR6 production compile warnings remain on stderr. Independent final verification pending. The writer-era ledger below records original handoff obligations:

| Check | Evidence / pending verification |
| --- | --- |
| Public helper and actual Mix task | `CLI.main/1`, `Mix.Tasks.Triage.Replay.run/1` present |
| Complete/incomplete/invalid statuses | Direct helper tests cover 0/2/1; fresh-process task probes pending |
| Strict options and JSON help | Table-driven helper tests; no OptionParser ambiguity |
| Bounded regular descriptor read | lstat, descriptor stat, one max+1 read, guaranteed close |
| Symlink, directory, device rejection | Helper tests; FIFO/socket and filesystem-race probes deferred |
| Exact input cap / no extra output files | Helper tests at 1,000,000 and 1,000,001 bytes |
| Redaction and result contract | Static error literals; real Replay results tested, no fake reports |
| No services or startup | Source trace confirms no app.start/app.config/Req/Repo invocation |

No Mix, compilation, formatting, builds, tests, shell execution, migration, or DB
operations were run by the CLI writer during fanout. The default project `test`
alias performs DB setup, and `test_helper.exs` touches SQL Sandbox: the integrator
must deliberately choose and serialize the runtime harness. Verify actual fresh
process exit codes and JSON stdout, including production without credentials,
and verify the application's Repo/Endpoint are not started. Run format checks
and targeted helper tests only after all writers stop.
