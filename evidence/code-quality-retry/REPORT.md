# Code-quality retry

## Result

Removed **74 production lines** by reusing existing validation rather than adding functionality or another module:

| File | Before | After |
| --- | ---: | ---: |
| `app/lib/triage_web/finding_filters.ex` | 343 | 290 |
| `app/lib/triage_web/case_filters.ex` | 216 | 204 |
| `app/lib/triage_web/timeline_filters.ex` | 259 | 250 |

Finding severity, sort and checkbox parsing now reuse `FindingFilters.scope_value/1` for raw UTF-8/control-character rejection and trimming. Case/timeline wrapper checks reuse its blank-value result. Finding wrapper neutrality remains separate because unchecked checkboxes and the default sort are legitimate neutral values there.

Added three table-driven regressions in `app/test/triage_web/filter_contract_test.exs` (69 lines). No database queries, workflows, schemas, dependencies, routes or public exports changed. Existing staged work is preserved. No commit or PR was created; HEAD remains `e75375083a39070e85a7456a1d5ed48e5a994ad4`.

## Verification

- **84 affected filter tests passed**, including the three new tests. Covers Finding, Case, Activity and Timeline filters. `tests.log`.
- **109,944 baseline/current comparisons passed** across 429 boundary values and multiple input/wrapper shapes: parsed state, invalid-field lists and emitted query parameters match. Public exports also match. `parity.log`.
- Compiler with warnings as errors, format check, strict Credo and Dialyzer passed; zero Dialyzer errors/skips. `static.log` contains the final static checks.
- Exact-scope hash audit, diff whitespace and patch reverse-check passed. Only the three intended existing files changed; one test file was added. `scope-audit.log` uses `FAILED` for these three intentional checksum differences, not behavioral failures.
- **Database/precommit verification is still BLOCKED**. Retried before and after editing; the guarded wrapper stops with exit 69: `verify-owned-db: psql unavailable`. `owned-db.log`. No shared database was touched, and no DB integration pass is claimed.

The behavior comparison is extensive but not exhaustive; it does not replace database-backed integration tests. Offline checks started no Repo, HTTP request or Endpoint listener.

## Remaining priorities

1. Provide `psql` and the local database environment specified in `app/OWNED_DB_VERIFICATION.md`, then run the guarded full precommit. The earlier history-query changes still require real PostgreSQL/LiveView verification.
2. Keep larger case-workflow restructuring separate from small code-reduction passes; moving code alone is not a net simplification.
3. Treat lint as one signal: `app/.credo.exs` still globally disables nesting/complexity checks. That policy was inspected, not weakened or changed by this retry.

## Artifacts and reproduction

- Report: `evidence/code-quality-retry/REPORT.md`
- Retry-only patch: `evidence/code-quality-retry/changes.patch`
- Acceptance ledger: `evidence/code-quality-retry/ACCEPTANCE.md`
- Baseline source archive: `evidence/code-quality-retry/before-source.tar`
- Exact line accounting: `evidence/code-quality-retry/file-lines.tsv`

The patch is relative to the pre-retry working tree and is already applied. Earlier reports/patches remain historical; this retry does not overwrite them.

From `app/`:

```sh
MIX_ENV=test mise exec -- mix run --no-start ../evidence/code-quality-retry/checks.exs
MIX_ENV=test mise exec -- mix run --no-start ../evidence/code-quality-retry/parity.exs
```
