# Code-quality follow-up — implementation and verification

## Status and identifiers

The five reported correctness/performance findings are implemented through their callers and UI state. Shared severity/import-lock policies are consolidated. Pure timeline day projection and bounded history reads are extracted. **Full database/precommit verification is BLOCKED**, not green.

- Repository: `/home/adam/projects/triagee`
- Base HEAD: `e75375083a39070e85a7456a1d5ed48e5a994ad4`
- No commit, PR, issue or relay was created. Changes remain in the working tree; the existing staged patch is byte-for-byte preserved (`index.sha256`).
- Report: `evidence/code-quality-followup/REPORT.md`
- Session-only source/test/doc patch: `evidence/code-quality-followup/changes.patch`
- Exact changed-file line counts: `evidence/code-quality-followup/file-lines.tsv`
- The patch is relative to the captured **pre-follow-up working tree**, which already contained other changes, not to a clean checkout of HEAD. Its reverse application was checked against the current tree; do not apply it again to this already-modified tree.

This follows `evidence/code-quality-review/REPORT.md`; that earlier review and its logs are historical evidence, not a current list of unresolved findings.

## Acceptance ledger

| Check | Implemented path | Evidence / remaining limit |
| --- | --- | --- |
| Assessment totals follow the case's saved scope, including shared images | `app/lib/triage/timeline.ex`: assessment aggregation filters `ReviewCase.owner/environment` directly and groups by UTC day; no image-placement gate | Current-source SQL/caller probe passes; shared-image database regression added but not executed |
| Day counts remain complete before display truncation | `app/lib/triage/timeline/days.ex`: count/group all loaded rows, then take the 25-row preview | Pure >25-event regression passes; source/DOM truncation coverage added |
| Repeated same-day events have unique row/link identities | Day rows carry `FindingEvent.id`; `app/lib/triage_web/live/timeline_live/bands.ex` uses it for element/link keys | Pure identity and rendered component checks pass; existing LiveView selectors migrated |
| History does not materialize unbounded event/date/review lists or call full case detail per case | `app/lib/triage/timeline/history.ex`: SQL aggregates, 50-event chronological keyset pages, 10-case pages, SQL-limited per-CVE case metadata. `app/lib/triage/cases/history.ex`: three batched preview queries, 25 reviews + 25 audit events per case, minimal snapshot metadata | Seven current-source SQL/caller probes pass. Added real-DB query-budget, projection-parity, keyset/backdate/tie, scope, truncation and paging tests; these are compilation-only here |
| Pagination reaches the public UI without losing scope | `app/lib/triage_web/timeline_filters.ex`, `live/timeline_live.ex`, `live/timeline_live/drawer.ex`: validated scoped bigint cursors, Next/First links, resets on filters/selection/close, scalar day count and full totals | URL/reset and component tests pass. Event- and case-page LiveView regressions compile but await DB execution |
| Boolean fields behave consistently for atom/string maps | `app/lib/triage/risk.ex`: presence-based fetch keeps explicit atom-key `false`/`nil` from falling through to conflicting string keys | Risk suite passes, including false/conflicting-key regressions |
| Duplicated policies and oversized read helpers are simplified without altering command/hash protocols | `app/lib/triage/severity.ex` is shared by Risk, Inventory, CVE display and import contract; `ImportFlow` consumes `Import.Contract.lock_key/0`; pure day and bounded history modules isolate read logic | Shared-policy tests and public-export probe pass; original lock value and severity SQL/rank ordering preserved. `Cases` command workflow, canonical hashes, migrations, configuration, dependencies and global Credo policy unchanged |

The integration is intentionally complete rather than an extraction-only change: `Timeline.cve_detail/2` callers now consume `event_page`, paged `cases`, and scalar `lane.observed_day_count`. Drawer query parameters are `events_after` and `cases_after`; they are not accepted by `list_timeline/1`. Scope-invalid cursors fail closed. `/timeline` remains registered to `TriageWeb.TimelineLive`. No new configuration is required. `app/README.md` documents the new contracts and limitations.

## Verification actually run

| Gate | Result | Artifact |
| --- | --- | --- |
| Focused pure/domain/filter/render suites | **25 passed** | `evidence/code-quality-followup/pure-first.log`, runner `pure_checks.exs` |
| Actual-source Ecto planning/Postgres SQL generation with queued Repo fixtures and caller assertions | **7 passed** | `evidence/code-quality-followup/query-first.log`, runner `query_probes.exs` |
| Final compile with `--warnings-as-errors`, format check, strict Credo, Dialyzer | **PASS**, no lint issues, Dialyzer errors/skips 0 | `evidence/code-quality-followup/final-checks.log` |
| After final validator adjustment, only affected pure/API probes retried | **1 validation + 2 caller checks passed**; unchanged cases excluded | `evidence/code-quality-followup/final-checks.log` |
| Affected database/LiveView suites compile without application start | **PASS, not executed**; last added case-pagination regression also recompiled | `db-test-compile.log`, `final-checks.log` |
| Owned-database guard self-tests | **PASS** | `evidence/code-quality-followup/owned-db-gate.log` |
| Guarded full precommit | **BLOCKED: exit 69, `verify-owned-db: psql unavailable`**; stopped before database setup | `evidence/code-quality-followup/owned-db-gate.log` |
| Public exported symbols, original route and lock callers | **PASS** | `evidence/code-quality-followup/public-symbols.log`; mechanical source searches |
| Diff whitespace and session patch reverse-check | **PASS** | `changes.patch`; final scope audit |

There are 25 new permanent regression tests: 15 pure tests ran (alongside 10 existing Risk tests); 10 new database-backed tests have not run. The seven additional artifact probes use the real current-source query builders and Postgres planner/SQL renderer, but **do not execute SQL on PostgreSQL**. They are not a substitute for database integration tests. No Repo, Endpoint listener or HTTP request was started by the offline probes. No shared database was touched.

Initial compiler/lint failures were inspected and corrected; `compile-first.log` and `static-first.log` are retained as intermediate evidence, not final failures.

## Scope and code-size audit

Exactly 14 pre-existing files changed (10 production, 3 tests, 1 README), and 9 source/test files were added (4 production, 5 tests). Every other file in the source/test baseline retains its original checksum. `scope-audit.log` uses `sha256sum`'s word `FAILED` for those **14 intentional changed-file checksums**; it is not a failing behavioral test. `new-files.txt`, `before.sha256`, `after.sha256`, `before-source.tar`, `before-app.patch`, and `index.sha256` preserve the audit inputs.

`app/lib/triage/timeline.ex` shrank from **868 to 743 lines**. Across affected production files, however, the net change is **+357 lines**: bounded queries, cursor validation, and paging controls are additional functionality. Tests grew by **698 lines**, README by 14. This is a correctness/scale and responsibility-separation improvement, **not an overall LOC reduction**.

## Remaining verification / deliberately unchanged boundaries

1. Install/provide `psql` and the documented owned local PostgreSQL environment, then run the guarded targeted suites and full precommit using `app/OWNED_DB_VERIFICATION.md`. Do not bypass its identity/population/cleanup guards or run the ordinary database-creating `mix test` alias against an unowned database.
2. Actual PostgreSQL execution, query plans/timing, database-backed LiveView interactions and the full suite are still unverified in this environment.
3. Exact aggregate totals still scan matching history in the database. The CVE header still loads matching occurrence metadata, and the linked full case page retains its existing full-history contract. The change bounds timeline history results/query families, not all possible database work or all application pages.
4. A wholesale split of `app/lib/triage/cases.ex` and removal of project-wide Credo exemptions remain separate higher-risk work. They were not mixed into this correctness pass; `app/.credo.exs` was not weakened to obtain a pass.

Reproduce the offline checks from `app/` with the pinned toolchain:

```sh
MIX_ENV=test mise exec -- mix run --no-start ../evidence/code-quality-followup/pure_checks.exs
MIX_ENV=test mise exec -- mix run --no-start ../evidence/code-quality-followup/query_probes.exs
MIX_ENV=test mise exec -- mix do compile --warnings-as-errors + format --check-formatted + credo --strict + dialyzer
PATH="$HOME/.local/bin:$PATH" ./scripts/verify_owned_db_test.sh
PATH="$HOME/.local/bin:$PATH" ./scripts/verify_owned_db.sh precommit
```
