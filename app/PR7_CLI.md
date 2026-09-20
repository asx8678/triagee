# Local synthetic replay CLI

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

## Replay input and result contract

[Triage.Replay.run/1](lib/triage/replay.ex) is pure and accepts a JSON string.
The exact envelope fields are format/version/origin/environment/engine/owners/
inventories/details: format `triage.replay`, version 1, origin `synthetic`.
Owners are identifier strings; inventories contain owner and raw images; details
contain UUID id and raw image detail. Use the [complete fixture](test/fixtures/replay/complete.json)
and [suppressed fixture](test/fixtures/replay/suppressed.json) as examples, never
as historical or production evidence.

The API permits 1,048,576 input bytes; the CLI's regular-file cap is the stricter
1,000,000 bytes above. Lexical depth 32, 5000 aggregate array values and 64 object
field occurrences are checked before Jason decoding, including duplicate keys.
Strings are bounded to 4096 bytes; output to 65,536 bytes. Object keys are sorted
recursively for canonical SHA-256; array order matters.

Inventory requires nonnegative integer vulnerabilities/vulnerabilitiesSuppressed
metrics; detail requires vulnerabilities/vulnerableComponents. Detail suppressed
metrics are unrequested and rejected. Image/metric keys follow stage-specific
Query selections; namespace objects allow only id/owner. Missing/null required
evidence, conflicts, unknown inventory fields and contradictory placement claims
cannot silently complete. Finding raw metadata remains recursively bounded and
cannot confer provenance or actionability.

Success is `{:ok, summary}` for complete OR incomplete evidence; invalid input
returns a closed error atom. The string-keyed `triage.replay.result` version-1
summary contains synthetic origin, completeness, canonical input hash, numeric
counts and allowlisted diagnostics. actionable, inventory_changed and
historical_provenance remain false. Source identifiers, descriptions, secrets
and raw blockers/exceptions are not output. Empty evidence may legitimately have
zero findings; completeness never means safe or approved.

Implementation: [CLI helper](lib/triage/replay/cli.ex),
[Mix task](lib/mix/tasks/triage.replay.ex). Tests:
[replay](test/triage/replay_test.exs), [CLI](test/triage/replay_cli_test.exs).
Use [owned verification](OWNED_DB_VERIFICATION.md) for database-backed suites;
ordinary test aliases may create/migrate databases. Historical PASS/FAIL receipts
are not current validation.
