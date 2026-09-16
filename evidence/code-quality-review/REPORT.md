# Code quality fixes and simplification

## Status and identifiers

Implementation complete; database-backed verification remains blocked in this environment.

- Repository: `/home/adam/projects/triagee`
- Base/current HEAD: `e75375083a39070e85a7456a1d5ed48e5a994ad4`
- New commit: none. Changes remain unstaged/uncommitted; pre-existing staged work was preserved.
- PR: none created. Issue: none created. Relay link: none created.
- Report: `/home/adam/projects/triagee/evidence/code-quality-review/REPORT.md`
- Session-only patch: `/home/adam/projects/triagee/evidence/code-quality-review/changes.patch`
- Reproducible differential probes: `/home/adam/projects/triagee/evidence/code-quality-review/probes.exs`

## Acceptance ledger

| Check | Implementation and evidence |
| --- | --- |
| Malformed KEV/NVD data cannot become a successful partial/empty cache replacement | Shared all-or-error feed parser validates record shapes, CVE identity, optional field types, descriptions and duplicate IDs. Legitimate empty feeds still succeed. Parser regressions and archived before/after probes pass. A DB-backed preservation regression was added and compiled, not executed. |
| Selected CVE scope survives placement/exposure loading | `Inventory.load_cve_aggregate/2` reuses `apply_placement_scope/3` before loading exposures. Owner-only, environment-only, combined and unscoped regressions added. The LiveView regression supplies explicit beta/internal exposure and checks both excluded alpha rows and aggregate priority. DB-backed execution blocked. |
| Source-level KEV cache health is distinct from a CVE match | New `Triage.Intel.cached_advisory_count/1` counts actual stored source rows, not matches or receipt item counts. CVE detail uses this count while keeping match and NVD-per-CVE data separate. Empty-success wording no longer asserts that no refresh occurred. DB regressions cover populated/nonmatching CVEs, failed receipts and intentionally empty success; compiled, not executed. |
| Conflicting flat severity is rejected | Neutral-event checking compares the complete parsed state with the two allowed default states. All seven recognized flat fields are covered; blank severity/default sort remain accepted. Filter regressions and baseline differential probe pass. |
| Technical-value variants preserve functionality | One template with conditional classes replaces two duplicated bodies. IDs, full values, escaping, copy attributes, feedback targets and accessibility semantics pass component tests and 14 baseline DOM vectors. DOM comparison normalizes indentation and class-token whitespace only; other attributes remain byte-exact. |
| Shared refresh and transport paths stay consistent | Both CLI sources use one fetch/replace/receipt path and canonical source keys. Req statuses and size checks are normalized once. Redirects explicitly disabled. Approved manual refresh starts Req's Finch supervisor, which `app.config` alone does not start. Req adapter tests exercise the real pipeline without sockets. CLI database success/receipt integration remains unexecuted. |
| Existing working tree preserved | Hash comparison found changes only in the intended 13 existing source/test files, plus the new transport test. Staged diff SHA-256 remains `98e63713515eaaf83795bf28f16b17704e1fa6ae5a47544b1ba15b1a3d08c489`. Session patch passes `git apply --reverse --check`; `git diff --check` passes. No changes to routes, migrations, configuration, collection gates, locks, snapshot hashes or scratch TypeScript code. |

## Code reduction

The seven edited production files decreased from **2,715 to 2,651 lines: 64 fewer lines**, including the correctness fixes. Regression tests are additional and excluded from this production count.

| File | Before | After |
| --- | ---: | ---: |
| `app/lib/triage/intel/client.ex` | 249 | 240 |
| `app/lib/triage/intel.ex` | 293 | 300 |
| `app/lib/triage/inventory.ex` | 854 | 855 |
| `app/lib/triage_web/live/cve_live/show.ex` | 438 | 444 |
| `app/lib/triage_web/finding_filters.ex` | 351 | 343 |
| `app/lib/triage_web/components/ui_components.ex` | 350 | 313 |
| `app/lib/mix/tasks/triage.intel.ex` | 180 | 156 |

No generic filter framework or broad file splitting was introduced: distinct cursor/blank-value policies remain explicit.

## Verification outcomes and limits

- **106 unique existing/new focused tests passed across targeted runs after correcting the isolated test harness fixture.** The initial no-start run passed 102 of 103 tests; the remaining shell test required Endpoint configuration and static URL caches. Its final retry passed using in-memory configuration and Phoenix cache warmup, without starting Endpoint or Repo. Three additional Req pipeline tests passed using a module adapter (no network).
- **Four differential probe tests passed across targeted runs**, including the 14-vector technical-value DOM comparison. Three boundary/API probes passed first; the DOM probe initially treated trailing class whitespace as significant. Correcting that probe's normalization produced a passing focused retry; no production workaround was needed.
- Final `mix compile --warnings-as-errors`, `mix format --check-formatted`, `mix credo --strict`, and `mix dialyzer`: **exit 0**. Dialyzer: **0 errors**. Existing global Credo complexity/nesting exemptions were not changed.
- Offline dependency-startup probe: Req supervisor ready, default intel disabled, Repo and Endpoint absent, no HTTP requests.
- Three affected DB-backed suites compiled successfully without executing their setup or tests: `app/test/triage/inventory_scope_test.exs`, `app/test/triage/intel_cache_test.exs`, `app/test/triage_web/live/cve_live_test.exs`. They contain **seven new DB-backed regressions**.
- `app/scripts/verify_owned_db_test.sh`: passed its fake-tool guard checks.
- Required full precommit attempt through `app/scripts/verify_owned_db.sh precommit`: **blocked, exit 69, `verify-owned-db: psql unavailable`**. No owned database was created or migrated. This is not a full-suite, real-feed, browser or production deployment signoff.
- Intel HTTP body size is checked before decode, not enforced by streaming cancellation; connection/receive timeouts are not a total end-to-end deadline. The client documentation now states the implemented guarantee rather than claiming a total deadline.

### Evidence files

All paths are under `/home/adam/projects/triagee/evidence/code-quality-review/`:

- `final-checks.log`: final compiler/formatter/Credo/Dialyzer results, passing 14-vector DOM test and offline Req-startup probe.
- `transport-final-and-db-compile.log`: three passing module-adapter tests and DB-suite compilation.
- `shell-fixture-final.log`: passing isolated shell test with the required non-listening configuration fixture.
- `probes-final.log`: historical three passing probes plus the class-whitespace comparison failure, corrected in `final-checks.log`.
- `parser-transport.log`: 14 passing parser/transport tests; historical adapter deprecation warnings subsequently removed.
- `shell-fixture-retry.log`, `probes.log`: earlier harness/probe failures, retained rather than relabelled green.
- `changes.patch`: only this session's implementation and tests, relative to the pre-edit working tree (not HEAD).
- `before-app.patch`, `before-source.tar`, `before.sha256`, `after.sha256`, `index.sha256`, `before-lines.txt`, `after-lines.txt`: original work, source snapshots, scope audit and size accounting.

Re-run the standalone probes from `app/`:

```sh
MIX_ENV=test ~/.local/bin/mise exec -- mix run --no-start ../evidence/code-quality-review/probes.exs
```

Once local PostgreSQL and `psql` are available, follow `app/OWNED_DB_VERIFICATION.md` and run the coordinator-owned `./scripts/verify_owned_db.sh precommit` from `app/`. This is the remaining full database-backed verification gate; do not substitute a shared/dev database.
