# Domain and API guide

These are retained backend contracts, not mounted-screen or test-signoff claims.
See [README](../README.md) for current routes; most old screen URLs redirect to
the workspace. Source documentation and regression tests supply detailed types,
validation and error contracts.

## Cases and frozen evidence

[Triage.Cases](../lib/triage/cases.ex) provides:

- `open_case(finding_id, owner: owner, environment: environment)` returns
  `{:ok, %{case: case, snapshot: snapshot, created?: boolean}}`. Both scopes
  must be explicit, nonblank, valid UTF-8, free of raw NUL/C0/DEL and at most 120
  characters after trimming. An active matching placement is required.
  Repeated/concurrent opens converge on one `(finding, owner, environment)` case;
  opening an existing case never refreshes evidence.
- `get_case(case_id)` returns case, current snapshot, snapshots, reviews, events
  and evidence_status. Reads create nothing; retired-scope history stays readable.
  Status is current, changed, source_out_of_scope or source_missing. Current means
  a local content-hash match, not production freshness.
- `change_review(attrs)` returns a changeset for applicability, priority,
  next_action and rationale. Attrs are plain string-keyed maps; metadata is
  server-owned. Malformed attrs produce controlled validation errors.
- `submit_review(case_id, expected_revision, expected_snapshot_id, token, attrs)`
  returns `{:ok, %{case: case, review: review, replayed?: boolean}}` or an error.
  A UUID token binds normalized payload and original revision/snapshot. Exact
  retries replay even after later revisions; changed token reuse is rejected.
  Conflicts, stale evidence and retired scope fail closed. Review, revision and
  audit append commit atomically, with rollback on failure.
- `refresh_evidence(case_id, expected_revision, expected_snapshot_id)` returns
  `{:ok, %{case: case, snapshot: snapshot, changed?: boolean}}`. Explicit refresh
  appends changed content only; unchanged content causes no revision/event churn.

Snapshots, reviews and audit events are append-only with database constraints
and rejection triggers. Same-case snapshot relationships are enforced. Case
identity cannot change through review attrs. IDs are positive PostgreSQL bigints.
Saving an assessment is not approval, suppression or remediation.

[Evidence](../lib/triage/cases/evidence.ex) builds deterministic string-keyed
payloads with schema version, source, scope, finding, image, matching placements,
lifecycle events and coverage. Capture time is separate from the hash; source
timestamps remain evidence. Public-reference data is not deployment evidence.
Frozen display facts are not live preloads. Old snapshots remain inspectable;
never silently rebind drafts to another case, revision or snapshot.

[Case tests](../test/triage/cases_test.exs) and
[integrity tests](../test/triage/cases_integrity_test.exs) cover the public contract,
rollback, retries, scope separation and immutability.

### Saved-case queue and local exceptions

`Cases.list_cases(opts)` accepts only optional owner/environment/before_id keyword
options; returns `{:ok, %{rows: rows, has_more?: boolean, next_before_id: id_or_nil}}`.
Blank read filters mean unrestricted; invalid filters must never widen scope.
Order is case ID descending, 25 rows plus a sentinel, not priority/last activity.
`case_filter_options/0` reads saved scopes, including retired ones.

[Queue](../lib/triage/cases/queue.ex) batches reads, not full detail per row.
Frozen identity/latest review are separate from current source status. No review
means awaiting_review; same-snapshot review AND current source means current_review;
otherwise an existing review needs_revalidation. Recapture alone cannot revalidate.
Badges are advisory, not an atomic database snapshot or authorization. Source
histories needed for hashing remain potentially large. Regression budgets: eight
list SELECTs at both one and 25 cases, two option SELECTs.

[Triage.Exceptions](../lib/triage/exceptions.ex) is distinct from scanner flags
and advisory-wide decisions. [CVE exceptions](../CVE_EXCEPTIONS.md) retains reason,
evidence, 90-day review bounds, expiry, revocation and exact scope requirements.
Stale/expired/revoked states must remain distinguishable; reads never mutate.
Tests: [lifecycle](../test/triage/exceptions_test.exs),
[validation](../test/triage/exception_decision_test.exs).

## Activity and timeline

[Activity.list_events/1](../lib/triage/activity.ex) accepts owner/environment and
positive-bigint before_id keyword options; returns the rows/has_more?/next_before_id
shape ordered by event ID descending, with 25 displayed rows. One row is one event,
not one placement/CVE. All lifecycle kinds, resolved and suppressed findings remain.
Scope joins owner AND environment on the same recorded placement, including inactive
ones; it does not establish historical ownership. `event_filter_options/0` reads all
recorded placements. Budgets: three list SELECTs, two option SELECTs.

Appeared/resolved/reopened mean first observed locally/no longer observed locally/
observed again locally, never remediation. Recorded times may be backdated; IDs
order the feed. Invalid scope/cursors are rejected before queries. Current joined
metadata is not frozen event-time evidence. Do not synthesize missing history or
confuse mutable inventory events with append-only case evidence.

[Timeline](../lib/triage/timeline.ex) exposes `list_timeline/1`, `cve_detail/2`,
`filter_options/0` and window options. Detail events_after/cases_after cursors are
scoped positive bigint IDs, not list_timeline options.
[History](../lib/triage/timeline/history.ex) pages events chronologically by
`(occurred_at, id)` at 50 and cases by ascending ID at 10. Full-history totals and
scalar observed-day counts are separate from previews.
[Case history](../lib/triage/cases/history.ex) batches at most 25 reviews and 25 audit
events per preview; complete case reads retain full history. Day counts precede
truncation; repeated events retain unique IDs. Assessment totals use saved case
scope, not another team's shared image.

Solid chart segments connect adjacent recorded days; dashed segments span gaps.
Neither asserts continuous presence. Missing rows are not clean/quiet days.
Calendar windows align to Monday and end at today, not necessarily weeks × 7 days;
future dates must not be presented as quiet days. Scanner suppression has no
inferred date/author. Exact aggregate totals still require database work; paging
does not bound all hydration. Current chart/window limits and explicit all-data
modes are defined in source, not obsolete screenshot counts.

## Approved historical snapshot import

From `app/`, against the deliberately selected local database:

```sh
mise x -- mix triage.import --file /trusted/approved-export.json
# Only after preview and backup of the intended database:
mise x -- mix triage.import --file /trusted/approved-export.json --apply
```

This is local-file only, dry-run by default. A real approved legacy export still
requires compatibility validation; synthetic fixtures are not approval.

JSON format is `triage.snapshot`, version 1; optional root source/generated_at.
`images[]` has digest, optional repository/tag/description, placements and findings.
Placements have namespace/owner/environment, optional active/first_seen/last_seen.
Findings have cve/package_name/package_version, required first_seen/last_seen,
optional severity/fix/url/description/suppressed/resolved_at, and events of
`{event, occurred_at, note}`. Closed fields/budgets:
[Import.Contract](../lib/triage/import/contract.ex); validation:
[Import.Parse](../lib/triage/import/parse.ex).

[Triage.Import](../lib/triage/import.ex) public entry points:

- `parse(json)` and `validate(snapshot)` are pure: `{:ok, snapshot}` or indexed
  `%{path: path, message: message}` errors. Normalized inputs must be plain
  atom-keyed maps from parse, not raw JSON maps, structs or key aliases.
- `dry_run(snapshot)` returns read-only create/update/unchanged records (events
  may be existing), summary and warnings, at most four SELECTs. Stale previews
  return indexed errors, not applicable updates.
- `import_snapshot(json)` parses/applies; `apply(snapshot)` validates and writes
  one atomic transaction returning `{:ok, report}` or errors.
- `write!(snapshot)` composes inside an existing Repo transaction only; rejects
  outside-transaction use before querying, revalidates, takes the advisory lock
  and rereads inventory. Regressions roll back with `{:import_rejected, errors}`.

Identity: image digest; placement `(image, namespace, owner, environment)`;
finding `(image, CVE, package, version)`; event `(finding, event, occurred_at)`.
Within-document duplicates are rejected. Cooperating writers serialize on lock
7433921021337; arbitrary SQL writers are not protected by that convention.
Imports never rewrite cases, snapshots, reviews, case events or replay receipts;
reopen_count is not imported. Omitted resolved_at/suppressed/active preserve stored
values. Absence is not resolution. Earlier last_seen/later first_seen regressions
are rejected; same-time metadata overwrite is permitted. generated_at does not
establish persisted source order or authenticated provenance.

Limits: 5,000,000 JSON bytes; 1000 images; 500 placements/500 findings per image;
200 events per finding; 10,000 total records; text 1024 graphemes/4096 bytes;
scopes 120 characters/480 bytes. Invalid enums/timestamps, unknown keys, unsafe
text and duplicates fail with paths. Small blank optional text becomes nil.

[ImportFlow](../lib/triage/import_flow.ex) retains its helper contract despite
`/imports` redirecting: one upload, 1,000,000 bytes, lexical depth 32, server-issued
temporary path only. `prepare/1` previews without writing; `apply/3` requires the
exact server nonce and acknowledgement and rechecks report AND affected-row
fingerprint under the import lock. Stale previews require new input, not rebasing.
Prepared values are server state, not authentication. Tests:
[import](../test/triage/import_test.exs), [flow](../test/triage/import_flow_test.exs).

### Future integration guardrails

Use immutable digest, never rotating source API image ID, as image identity.
Legacy packagePath/purl may distinguish records that collapse onto the current
CVE/package/version key: reconcile ambiguity explicitly before conversion, never
silently discard conflicting evidence. Historical imports require truthful source
provenance and reviewed environment mapping; namespaces/owners alone cannot invent
an environment. Never assign import time as first observation or invent lifecycle.
Future absence-based resolution requires successful comparable **complete-scope**
coverage; partial/failed/unknown collection cannot resolve missing findings. The
current importer does not infer resolution at all.

## Offline collection and replay

[Collection.run/1](../lib/triage/collection.ex) is disabled in dev/prod builds.
Only the explicit test-loopback build flag enables fixed Req transport against a
validated literal loopback endpoint. Config alone does not authorize live access;
arbitrary transports/credentials are not a supported bypass.

The test adapter reads owners → images → detail with mandatory engine. Digest is
identity; placements need explicit environment. Raw open/suppressed counts reconcile
before deduplication. Missing identities, conflicting duplicates and positive
counts with empty evidence cannot complete. Request/response/text/depth/time budgets
and cancellation remain bounded; redirects, auth and GraphQL failures are terminal
and sanitized. Measurements cannot supply lifecycle history. Preview refuses lossy
mappings/unsupported severity rather than mapping UNKNOWN to LOW or manufacturing
provenance. No inventory writes or scheduled jobs.

[Replay CLI](../PR7_CLI.md) retains pure synthetic contracts;
[receipt API](../PR7_HISTORY.md) retains explicit summary-only persistence.
Completeness or a receipt grants neither actionability nor permission to import.
