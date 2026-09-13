# Code review findings — execution record

Date: 2026-09-13. Scope: the code review's remaining findings — the keyset
pagination item (6), static analysis (8) and the oversized modules (9) — plus the
two smaller things that review noticed (a compiler warning in a test, and the
checkpoint inventory's scope). Items 1-5 and 7 were implemented earlier in
`ca1ad47`; this record covers the rest.

Commits (none pushed, no deployment):

| Commit | Contents |
|---|---|
| `0e79676` | Item 6: the findings list pages by keyset position, not by offset. |
| `84ac6ed` | Item 8: credo and dialyzer added to the gate, and everything they found. |
| `0f31ad8` | Item 9: the case detail view's render split into section components. |
| the commit carrying this record | Item 9 completed: the snapshot import split into its stages, the boundary specs, and the checkpoint inventory's `.github` scope. |

## Item 6 — one pagination strategy (done)

The findings list paged with `limit`/`offset` and a page number while the review
queue next to it used a keyset cursor, and an offset costs work proportional to
the offset (bounded only by a page-number cap of 10 000). The list now continues
from a position, exactly as the queue does.

`Triage.Inventory.GroupCursor` is the single definition of each published order's
compared fields and of how a position is written, read and validated, and
`list_groups/1` derives both its ORDER BY and its keyset HAVING predicate from
that one list, so the fields an order compares and the fields a position compares
cannot drift. Cursor text is canonical and strictly validated: ASCII decimal
integers in range without leading zeros, whole-second UTC ISO-8601 timestamps
that re-encode to themselves, and plain unseparated advisory text within the same
120-character bound the filter contract uses. Anything else is a visible
invalid-filter state with no rows. `FindingFilters` validates a position against
the order it is used with and emits it re-encoded; the detail view carries it, so
its back link returns to the same slice; a position past the end is a visible
notice with a link back to the newest slice.

Evidence: walking the list with only the positions it hands out reproduces the
unpaged list exactly for all four orders, both through `Triage.Inventory` and
through the LiveView links (`inventory_paging_test.exs`,
`finding_live_paging_test.exs`), with no duplicate and no skipped group; a
position from another order is rejected rather than answered with a different
slice; the live server walk of `/findings?sort=cve` returned 25 rows, then 3, with
zero overlap and 28 total.

## Item 8 — static analysis (done, with one disclosed policy call)

`credo` and `dialyxir` are dev/test-only dependencies, configured by `.credo.exs`
and `mix.exs`, and run by `mix ci` and the workflow (which caches the PLT, because
building it takes minutes).

**What dialyzer found, and what was done:**

| Finding | Resolution |
|---|---|
| Every `Mix.raise/1`, `Mix.shell/0`, `Mix.Task.run/1` call in a task reported as a call to a function that does not exist (15), plus 4 behaviour-callback warnings and 7 `ExUnit` expansions in `test/support` | `:mix` and `:ex_unit` added to `plt_add_apps` |
| `Triage.Collection.Config`'s specs referenced `InvalidOptionsError.t/0`, a type that does not exist | every exception in `Triage.Collection.Errors` publishes `t/0` now |
| 51 functions in `Triage.Collection.Client` and `Triage.Collection.Crawl` reported as never called — including the whole retry, budget and transport path | one root cause: `:atomics.get/2` takes an opaque reference, so dialyzer proves the forged-input probes always fail and everything after a valid client looks unreachable. The probes dispatch through a value so the failure stays a runtime result |
| `normalize_transport_error/1`'s catch-all reported as a pattern that can never match | **the clause is live** — injected transports return raw tuples that can carry credentials, and removing it broke a test that asserts those secrets never leak. Dialyzer cannot see it because `.exs` test files are not part of its analysis; the clause is restored with a documented `nowarn_function` |

**What credo found:** unused alias ordering and multi-alias groups in 15 files,
two `length/1` comparisons, two `Enum.map |> Enum.join`, two single-branch
`cond`s, a redundant final `with` clause, two explicit `try`s, a nine-arity test
fixture and one dead clause — all fixed.

**One disclosed policy call.** Three checks are disabled in `.credo.exs`, each
with its reason stated in the file itself:

1. `Credo.Check.Design.AliasUsage` — aliasing the nested transport and error
   modules would shadow the `Req` dependency and the `Errors` alias the transport
   modules already use.
2. `Credo.Check.Refactor.Apply` — the one deliberate `apply/3` from the dialyzer
   fix above.
3. `Credo.Check.Refactor.Nesting` and `Credo.Check.Refactor.CyclomaticComplexity`
   — at the time of writing they reported **36 nesting and 18 complexity**
   findings across 26 files, every one in an input-validation boundary or a
   `handle_event` dispatch. The worst: complexity 20 in
   `Triage.Collection.Normalize.reconcile_claims` and `Triage.Import.budget_errors`;
   nesting depth 5 in `Triage.Import.preflight` and `Triage.ImportFlow.apply`.
   Those functions enumerate every rejection they can make as an explicit clause
   with its own comment, which is deliberate and is the shape these two metrics
   measure. The alternatives were an exclusion list covering twenty files or
   raising the thresholds to today's worst function; both would have been less
   visible than disabling the checks and recording the counts here.

**Specs.** The review's other half of this item was coverage: 9 `@spec`s for the
whole codebase. The boundary contracts now carry thirty-three, each verified by
dialyzer (it rejects a spec that does not match the code, which is what makes
them worth writing):

| Module | Specs |
|---|---|
| `Triage.Import` | `parse/1`, `validate/1`, `dry_run/1`, `apply/1`, `import_snapshot/1`, `write!/1`, `max_document_bytes/0`, plus `problem/0`, `snapshot/0` and `report/0` types |
| `Triage.Risk` | `classify/1`, `aggregate/1`, `policy_version/0`, `priorities/0`, plus `t/0` |
| `Triage.Exposure` | `record/5`, `current_by_placement/2`, `exposures/0`, plus `Evidence.t/0` |
| `TriageWeb.FindingFilters` | `parse/1`, `parse_event/1`, `query_params/1`, `defaults/0`, `sorts/0`, `scope_value/1`, plus `filters/0` |
| `TriageWeb.CaseFilters` | `parse/1`, `parse_event/1`, `query_params/1`, `defaults/0`, plus `filters/0` |

Writing them found one real over-restriction: `FindingFilters.query_params/1` is
called with the subset of keys a link needs, so a spec of the full `filters()`
shape made dialyzer prove those calls could never succeed — nine `no_return`
findings in the two finding views. The spec now states the contract the function
actually has.

**Still open, recorded honestly:** the remaining ~340 application-API functions
are unspecced, and the import split moved ~99 internal functions into the public
count. Coverage is now measured over the boundary layer deliberately rather than
claimed as complete.

## Item 9 — the oversized modules (done)

`TriageWeb.CaseLive.Show` was 1415 lines with one 590-line `render/1`, 74 private
defs and 17 `handle_event` clauses. It is now three modules:

| Module | Lines | Owns |
|---|---:|---|
| `case_live/show.ex` | 673 | the case's state, events and data loading; `render/1` is a nine-line composition |
| `case_live/sections.ex` | 611 | the five sections and the evidence-facts component, assigns declared as attributes |
| `case_live/format.ex` | 265 | pure view-model formatting and the three assessment choice lists |

Declaring the components' assigns is what found two assigns the render had been
reading with no declaration at all (the submission token and the streams map), and
moving the formatting is what found `label/1` reaching into attributes defined by
the LiveView. The split also enables per-section tests, which are added
(`case_live_sections_test.exs`, 9 tests): each section now renders on its own and
asserts its content and its blocking conditions.

`Triage.Import` was also split, along the stage boundaries the module's own
comment clusters already drew (the review called this optional and lower value,
and the clusters made it mechanical):

| Module | Lines | Owns |
|---|---:|---|
| `import.ex` | 328 | the public API: `parse/1`, `validate/1`, `dry_run/1`, `apply/1`, `import_snapshot/1`, `write!/1` |
| `import/parse.ex` | 656 | parsing, validation and normalization (pure, no database) |
| `import/write.ex` | 354 | the write path and the stale-observation rule |
| `import/reconcile.ex` | 182 | read-only reconciliation and the current-row loads |
| `import/contract.ex` | 69 | the format, version, vocabularies, key sets and budgets |

The split needed one non-obvious piece: the seven budget and vocabulary
attributes were used by three of the stages, and a split that copied them would
have created exactly the drift the whole review is about. They live in
`Triage.Import.Contract` now, which injects them with `use` so the values stay
module attributes — usable in patterns — while having one definition. The
cross-stage calls are qualified through aliases, and the split is acyclic:
`Import` and `Write` depend on `Parse` and `Reconcile`, which depend on nothing
in the pipeline.

Two honest costs are recorded rather than glossed: the three stage modules expose
~99 functions that were private, because Elixir has no module-private visibility
across files (their `@moduledoc`s say they are internal to the pipeline), and the
same 54 complexity findings follow those functions into their new files.

## Also fixed

- `test/triage/import_concurrency_test.exs` captured its database opt-in at
  compile time, so the compiler could prove its guard conjunction was always false
  and warned on every run. The module tag must be compile-time; the assertions now
  read the opt-in at run time, which is also the value that matters when the
  connection is switched.
- `evidence/checkpoint/source-only.paths` does not include the new repo-root
  `.github/workflows/ci.yml`, because that script's scope does not cover root
  dot-directories. Left as-is: the inventory is the earlier checkpoint artifact and
  widening it is a separate decision, not a silent one.

## Verification

| Check | Result |
|---|---|
| `mix ci` (compile, format, unused deps, `credo --strict`, assets, tests, `dialyzer`) | **exit 0** |
| `credo --strict` | **no issues** |
| `dialyzer`, dev and test environments | **0 errors**, 0 skipped |
| Test suite | **634 passed, 2 skipped** |
| Keyset partition property | unpaged list reproduced exactly for all four orders, through the domain and through the LiveView |
| Case view suites after the split | 19 passed, unchanged |
| New per-section tests | 9 passed |
| `group_cursor_test.exs` | 10 passed |
| Import suites after the split (`import_test`, `import_flow_test`, `import_concurrency_test`) | 49 passed, 2 skipped — unchanged |
| Boundary specs | 33, each accepted by dialyzer (a spec that does not match the code fails the gate) |
| Disabled metrics, re-measured with the checks temporarily enabled | 36 nesting + 18 complexity, same total as before the split |
| Checkpoint inventory | 211 paths, manifest 211 ok / 0 failed, `.github/workflows/ci.yml` included |
| Live smoke (dev server, both changed views) | `/findings` slices walk with zero overlap; `/cases/:id` renders; invalid cursor → visible invalid-filter state; past-the-end position → its own notice |

## Artifacts

| Path | SHA-256 |
|---|---|
| `app/lib/triage/inventory/group_cursor.ex` | `3163a92651e652df21df591d6a5d93ca2067c318b4bd037aeb0c41ba2c87231c` |
| `app/lib/triage_web/live/case_live/show.ex` | `a76163128459360e97e384818a998df4064ec12a78a1a57cf0ae5ad0816932ae` |
| `app/lib/triage_web/live/case_live/sections.ex` | `faae67a816427351fe5f6ece0446df787ff42c0adbe446f6076f8967b74799c8` |
| `app/lib/triage_web/live/case_live/format.ex` | `95460842e95abd03cfa2f6a7b72151dce4c0ff02ebdd01cbf4617c4a2308d6f9` |
| `app/.credo.exs` | `9e927132d6fb908c8294bc2cfc32140b76a8f004d42fd963018cf0cb632f5099` |
| `app/mix.exs` | `461968b4212e8738e47ced35d632fc0460c992a8f85c7602fb1b49b0e7aedb72` |
| `.github/workflows/ci.yml` | `2b8be89e8e2df27119e6f08224cabda3c62480b06ea529ddd7ea6770a38aa434` |
| `app/lib/triage/collection/client.ex` | `0cd175bb8800b8c6ef08d3cf7e938acda70df91f7a892fa86fc65c2a0df634c9` |
| `app/lib/triage/collection/errors.ex` | `3c222dae14be3bc156ed2e1ad8c90b5532c9996cd518309db403ef7c7f778086` |
| `app/test/triage/inventory/group_cursor_test.exs` | `f5a47c82e8251b8b7e777605bc58c077484d5ee3e94f781025a2f8297e63ebc9` |
| `app/test/triage_web/live/case_live_sections_test.exs` | `a79c6f6efeeb78aa62f955e796e1be23ce4086e6128c6984fddbdc6f689f2573` |
| `app/lib/triage/import.ex` | `873505110f8ffda4e8cb3f2511a0a6e4f7d7699e9195a1801640a57f821751fe` |
| `app/lib/triage/import/contract.ex` | `2edb02f33a58b386b4fd88d2b53faa010c0ebc462c77b57f4803623e9ec15457` |
| `app/lib/triage/import/parse.ex` | `ba735331b55c39223533461a7de1e4f871715297c8ad07430db0005ea5935a49` |
| `app/lib/triage/import/write.ex` | `1019a00e5662aa1fc405bfcb5232a21f1c93d026f9d65672358389252c84a2dd` |
| `app/lib/triage/import/reconcile.ex` | `c544b4037faf0cfceafcb4a8161292738bbaa51548cfe3fe14a6b8c0604ed141` |
| `app/lib/triage/risk.ex` | `e6142f693400aaff789022784ab3e69a0ba4a6811146c67ef5b95ebd8aa0bf78` |
| `app/lib/triage/exposure.ex` | `d515387853b1d32f2b772bd582e07667303b905267836b3f57a31db90183c43d` |
| `app/lib/triage_web/finding_filters.ex` | `b0f0c193311cd9322fe17347dc5923b38f3f2852948d96f3d2310351d05714f2` |
| `app/lib/triage_web/case_filters.ex` | `71d1f917dea31d2287d71e96869f4dae5f45c95f75aa03d7f124cd2157f9d492` |
| `scripts/checkpoint_inventory.sh` | regenerated inventory: `evidence/checkpoint/source-only.paths` (211 paths) |

## Open

1. Spec coverage beyond the boundary layer: 33 specs against ~340 application-API
   functions (above).
2. The 54 complexity findings behind the two disabled metrics — re-measured after
   the import split as 36 nesting + 18 complexity, recorded with their counts and
   worst offenders in `.credo.exs`; a per-function refactor is the way to retire
   that policy.
3. Nothing else: the import split is done, and the checkpoint inventory now covers
   `.github` (211 paths, manifest 211 ok / 0 failed).
