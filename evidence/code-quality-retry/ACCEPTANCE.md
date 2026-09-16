# Code-quality retry acceptance ledger

1. Retry the database precommit gate without bypassing ownership guards. Result: still blocked before database setup, exit 69 (`verify-owned-db: psql unavailable`).
2. Preserve current functionality: filter parse results, defaults, invalid-field lists, nested-wrapper neutrality, enum/checkbox case rules, cursor state and URL params must match the saved pre-retry implementation.
3. Reduce production code by reusing `FindingFilters.scope_value/1` for raw UTF-8/control-character validation and trimming. Do not add a new abstraction/module or change queries, schema, workflows or routes.
4. Run the affected Finding, Case, Activity and Timeline filter suites plus focused table-driven boundary regressions. Compare current and baseline modules directly over generated boundary values and wrapper shapes.
5. Confirm compiler/formatter/strict Credo/Dialyzer, unchanged public exports, net production LOC reduction and preserved index. Report database-backed tests as blocked, not passing.

Trace: LiveView URL/events -> `parse/1` / `parse_event/1` -> finding `field_value/2` or case/timeline `blank_flat_fields?/1` -> shared `scope_value/1`. `ActivityFilters` delegates to `CaseFilters`. Finding wrapper neutrality includes checkbox/default-sort semantics and must remain distinct from the plain-blank case/timeline rule.

Before editing: source/test hashes and staged patch matched the previous pass. Snapshot: `evidence/code-quality-retry/before-source.tar`. Only the three filter modules above are in the intended production edit set. Prior reports/patches remain historical and will not be overwritten.

## Final ledger

- Check 1: BLOCKED before/after edits, exit 69; `owned-db.log`.
- Checks 2 and 4: PASS, 84 tests and 109,944 baseline/current comparisons; `tests.log`, `parity.log`.
- Check 3: PASS, 74 production lines removed across three modules; no new production module, query or workflow changes.
- Check 5: PASS, compiler/format/Credo/Dialyzer, unchanged exports, index integrity and patch checks. See `REPORT.md` and `file-lines.tsv`.
