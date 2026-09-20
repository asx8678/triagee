# Synthetic replay receipt API

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
by the replay_runs table's trigger. Inventory and case tables are not modified.

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
internal API. It adds no startup hook or CLI save option. The old replay UI
used explicit saving but its routes now redirect; see [README](README.md).

## Source and verification

[Runs](lib/triage/replay/runs.ex) implements the API;
[Run](lib/triage/replay/run.ex) defines the schema and
[create_replay_runs](priv/repo/migrations/20260911123348_create_replay_runs.exs)
defines the database constraints and UPDATE rejection trigger.
[History tests](test/triage/replay_runs_test.exs) cover safe persistence,
canonical retry/conflict, incomplete results, malformed no-SQL input, expiry,
purge, physical quota, pagination, immutability and rollback.

Database-backed verification must follow [OWNED_DB_VERIFICATION](OWNED_DB_VERIFICATION.md).
For concurrency-sensitive changes, probe separate connections: identical keys,
conflicting contents, distinct keys at quota, and purge/insert serialization.
Check unavailable-Repo behavior without treating raw database errors as success.
A sequential test or build alone does not establish those properties.
