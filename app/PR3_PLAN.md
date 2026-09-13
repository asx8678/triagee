# PR 3 — read-only Review Queue

Status: IMPLEMENTED AND VERIFIED — FINAL PASS (2026-09-10). The local-only, synthetic-data Review Queue before What's New is delivered: final GLM suite 236 tests passed (161 PR 2 baseline + 75 PR 3; agent `79f594d9e5cc4d6eafc622908689b67a`, Astra-audited), 276 fresh API assertions (Astra `4b41989bf87048aeb4fdb1fcd61123bd`) and 31/31 fresh independent Chrome browser assertions (final Astra signoff `0c4be006927148158fd8a6c659ed3503`). See the record below for combined coverage, retained evidence and failure/fix history. What's New remains deferred; shared deployment still requires a separate authentication/authorization milestone. This is the active Phoenix PR 3 plan; older My Work/news numbering in the historical roadmap is not this implementation slice.

## Goal and non-goals

Make existing review work discoverable without finding the original inventory entry again: open `/cases`, filter by saved team/environment, inspect review and evidence status, and navigate to the existing case detail.

- List existing cases only, one row per `(finding_id, owner, environment)` case. Never group cases into a global CVE decision or create a case merely by browsing.
- Preserve the server-owned, explicitly unauthenticated `local-operator` model and visible local/synthetic coverage warning. Display scoping is not authorization.
- No news feed, publication, AI explanations, collection/import, personal assignments, notifications, Oban jobs, polling, exception activation, scanner writes, authentication implementation, dependency upgrades, or workflow engine.
- No schema migration is expected. Existing tables/indexes are sufficient for this slice; do not edit either historical migration. Any demonstrated need for an index or broader refactor requires an explicit plan amendment.
- Preparation edits only this plan and `IMPLEMENTATION_ROADMAP.md`. No app/test/config/database changes, application start, test execution, commits, or external PR creation are part of preparation.

## Baseline and traced execution path (captured before implementation — statements such as “/cases does not yet exist” describe the pre-PR 3 state, not the current tree)

PR 2's durable record is `PR2_PLAN.md`: 161 tests passed in its last GLM integration run; independent Astra final signoff passed browser, context, recapture and actual restart checks. That is historical verified evidence, not a fresh test run during this preparation.

Relevant paths, relative to `app/`:

- `lib/triage_web/router.ex`: `/cases/:id` exists; `/cases` does not yet exist.
- `lib/triage/cases.ex`: `get_case/1` loads all snapshots/reviews/audit events and recomputes evidence status through `Inventory.fetch_finding/2`. It is not a queue loader.
- `lib/triage/cases.ex`: `build_snapshot/2` / `payload/3` / `content_hash/1` define the canonical evidence hash. Hashed data includes the finding, image, scoped placements (including inactive records within that scope), full finding lifecycle events, scope and coverage. `other_occurrences` is NOT hashed.
- `lib/triage/inventory.ex`: `fetch_finding/2` additionally loads related occurrences and scope-image IDs, which the queue does not need. `teams/0` and `environments/0` read all placements, not active-only placements; nevertheless saved case scopes are the authoritative queue filter source.
- `lib/triage/cases.ex`: review revision bumps and recapture use `Repo.update_all`; `review_cases.updated_at` is NOT a reliable last-activity clock. Do not sort by it or label it as last reviewed.
- `lib/triage_web/finding_filters.ex`: established raw UTF-8/control-character/120-character scope validation and explicit invalid states. Leave this module unchanged.
- `lib/triage_web/live/case_live/show.ex`: saved case scope owns identity/back links; `invalidate_case/2` clears stale bindings and streams after invalid navigation. Preserve all write, conflict, retry and invalidation behavior.
- `lib/triage_web/components/layouts.ex` and `lib/triage_web/controllers/page_html/home.html.heex`: these currently contain no internal triage navigation links (layout links are external Phoenix sites; home is the generated marketing page) — the queue entry links will be added here. Only add the needed internal links; no unrelated visual redesign.
- `config/test.exs`: database is `triage_test#{MIX_TEST_PARTITION}` only under `MIX_ENV=test`; setting a partition under development is not isolation.

Read-only design reviews: GLM `3984c85514d9438b913a4619b071d45d` (read model) and `6ca17bd8e58f4255be078c4d8f93e047` (navigation/tests). Recommendations were checked against source. In particular, do not adopt per-row detail loading, treat `other_occurrences` as hashed, treat `q`/`suppressed` as unrecognized by FindingFilters, or classify a same-snapshot review as current without checking source evidence.

## User experience and chosen defaults

1. Page title: **Review Queue**, not My Work (there are no authenticated users or assignments).
2. `/cases` defaults to all existing cases, including reviewed cases and cases whose placement has retired. All is a read-only aggregate view, never an unscoped writable case.
3. Team (`owner`) and environment filters combine with AND. Either can be absent independently. Options come from saved case scopes, so retired teams/environments remain selectable. Unknown valid values show an empty result, not a silently broadened scope.
4. Default order: case `id DESC`, explicitly labelled **Newest opened first**. This is not priority order or last-activity order.
5. Fixed page size: 25. Keyset pagination using `before` in the URL; controls are **Older cases** and **Newest cases**. Browser Back restores earlier cursor URLs. No numeric page totals, offset pagination, or invented global status counts.
6. Scope changes reset the cursor. Manual **Reload queue** re-queries the current scope/cursor; no timer or automatic mutation.
7. Review/evidence statuses are badges, NOT filters or sorting keys in this slice. Correct filtering on derived source freshness would require evaluating beyond the displayed page; filtering an already limited page is forbidden. Defer that separate read-model/indexing decision rather than misrepresent results.
8. Cases with suppressed/resolved observations stay visible. Those source observations are not verified remediation or a reason to hide a saved case.

Each row shows case ID; frozen CVE, package/version, image repository/tag or digest identity; saved team/environment; current snapshot version/capture time; latest review time and manual priority when present; and both badges below. Long text remains escaped and visually bounded. Full rationale, all evidence payloads and the complete history belong on the existing detail page.

### Two independent status axes

Evidence status is the same contract as PR 2, recomputed read-only for the displayed case scope:

| Value | Meaning |
| --- | --- |
| `:current` | Current local source facts match the captured hash. Label as a local evidence match, NOT production freshness. |
| `:changed` | Current local source content differs from captured evidence. |
| `:source_out_of_scope` | No active placement remains for the saved owner AND environment. History remains readable. |
| `:source_missing` | Required source/captured data is unavailable. Never default to current. |

Use the latest review deterministically by `(inserted_at DESC, id DESC)`, consistent with detail history. Review status is derived, never persisted:

| Condition | `review_status` |
| --- | --- |
| No review exists | `:awaiting_review` (also show any evidence warning) |
| Latest review exists, its `snapshot_id == case.current_snapshot_id`, and evidence status is `:current` | `:current_review` |
| A review exists and either its binding differs OR evidence is changed/out-of-scope/missing | `:needs_revalidation` |

A case whose `current_snapshot_id` is nil maps to `:source_missing`, mirroring `get_case/1`; it is unreachable after a committed open. A recapture alone does not revalidate an old review. A review of current local evidence does not mean approved, accepted risk, fixed, mitigated or globally not affected. A historical review's priority must not be presented as an automatically recomputed queue priority.

## Implemented public contract — frozen before writers started

### Domain: `Triage.Cases`

Add these functions in `lib/triage/cases.ex`; keep query/assembly helpers private so the existing canonical builder can be reused without exposing write internals.

- `list_cases(opts \\ [])`
  - Accept a keyword list containing only optional `:owner`, `:environment`, `:before_id`; reject malformed lists, structs, maps, unexpected/duplicate keys and other request shapes with `{:error, :invalid_request}` before querying.
  - Optional scope values: nil/space-only means no restriction. Otherwise require a plain valid UTF-8 binary with no raw NUL/C0/DEL and <=120 characters after trimming; invalid values return `{:error, :invalid_scope}` before querying. The UI All option is an empty value; the literal string `all` is not a magic unscoping token — a team genuinely named `all` is matched like any other ordinary (matching-or-empty) scope. This read validator is deliberately NOT the existing strict write `validate_scope/1` (which rejects blank and `all`): the queue read contract permits blank absence.
  - `before_id` is nil or an integer in `1..9_223_372_036_854_775_807`. No coercion, floats, booleans or unbounded numeric conversions. No client-controlled page-size or sort options.
  - Returns `{:ok, %{rows: rows, has_more?: boolean, next_before_id: integer_or_nil}}`.
  - Rows are plain projection maps: `id` (case ID), `finding_id`, `owner`, `environment`, `revision`, `current_snapshot_id`, `opened_at` (the case's immutable `inserted_at`; `review_cases` has no separate opened-at column), frozen `finding` and `image` display maps, `snapshot` metadata (`id`, `version`, `captured_at`), `latest_review` (nil or `id`, `snapshot_id`, `inserted_at`, `applicability`, `priority`, `next_action`), `evidence_status`, `review_status`.
  - Do not send idempotency tokens, request hashes, all reviews/audit events, or full evidence histories to the queue LiveView. No writable changeset or save binding is created here.
- `case_filter_options/0` -> `%{owners: [string], environments: [string]}`. Sorted distinct nonblank values from `review_cases`; independent of current active inventory and pagination. Pure read, no status counters.

The domain validates its own inputs; it must not depend on `TriageWeb` filter modules. Preserve the existing strict explicit-scope write validator and all PR 2 public signatures.

### Web: `TriageWeb.CaseFilters`

New `lib/triage_web/case_filters.ex` with `parse/1`, `parse_event/1`, `query_params/1`; return a normalized map `%{owner: ..., environment: ..., before_id: ..., invalid: [...]}` from parse functions.

- Recognized URL fields are `owner`, `environment`, `before`. Reject non-plain-map inputs and malformed recognized values. The reserved `filters` wrapper is invalid in URL parsing, not harmless ignored metadata.
- Extract the `owner`/`environment` values FIRST and validate ONLY those values against the FindingFilters value contract (raw valid UTF-8, no NUL/C0/DEL before trimming, <=120 characters after trim, blank = All). Do NOT pass the whole raw map through `FindingFilters.parse/1` — that would let a malformed unrelated `q`/`suppressed` value invalidate the whole queue view. Do not change FindingFilters itself. Malformed unrelated URL metadata (`q`, `suppressed`, `return_to`) is ignored, never invalidating the queue.
- Cursor: absent/nil/empty means newest; otherwise require 1–19 ASCII decimal digits and a positive bigint value before converting. Reject signs, surrounding whitespace, oversized text, arrays/maps, invalid UTF-8, controls, zero and overflow visibly. The cursor is a position, not an authorization token or a requirement that that case exists.
- `parse_event/1` supports a flat form or one plain `filters` wrapper; reject nested/non-map/ambiguous nonblank flat-plus-wrapper values, including a nonblank flat `before` cursor next to a wrapper. Ignore genuine event metadata (`_target`); do not coerce malformed scope values. A successful scope-filter action discards any old cursor.
- Unrelated URL metadata such as `q`, `suppressed` or `return_to` is not applied to this queue or reflected into links. No atom creation from input; use fixed keys only.
- `query_params/1` emits only validated non-nil owner/environment/cursor values. The LiveView passes an explicit trusted keyword list to `Cases.list_cases/1`; it must not pass the raw URL map.

### LiveView, route and navigation

- New module/file: `TriageWeb.CaseLive.Index`, `lib/triage_web/live/case_live/index.ex`.
- Register `live "/cases", CaseLive.Index` alongside and before `/cases/:id` in the existing browser scope. No extra REST endpoint, supervisor process, feature flag or endpoint configuration is required.
- Use `Layouts.app`, core inputs, `to_form/2`, verified routes and resettable streams. No new JavaScript or replacement assets/transports.
- Stable IDs: `#queue-filters`, `#case-queue`, `#case-{id}`, `#case-link-{id}`, `#review-status-{id}`, `#evidence-status-{id}`, `#queue-empty`, `#queue-error`, `#reload-queue`, `#queue-pagination`, `#older-cases`, `#newest-cases`.
- Filter events patch canonical URLs; `handle_params` is the authoritative queue reload. Invalid params must clear rows, pagination and row links from the previous valid state and render a visible error. Valid unknown scope renders empty. Handle unsupported/malformed events without writes or channel termination; never fall back to showing all cases after invalid input.
- Queue-to-detail links use each ROW's saved owner/environment, not an All filter or another row's scope. Do not carry queue cursors or arbitrary `return_to` values into case detail.
- Add a **Cases for this scope** link (`#back-to-cases`) inside the existing valid-case branch of CaseLive.Show, built directly from `@case.owner` / `@case.environment`. No new persistent back-link assign is necessary. Hide it when the case is invalid; preserve the existing `#back-to-finding` link and all mismatch/error behavior. This returns to the newest queue page in that case's saved scope; it deliberately does not promise exact originating-page return (browser Back does that).
- Add internal Findings / Review Queue entry links to shared navigation and a minimal queue link on the home page. Preserve existing PR 1/2 entry points and warnings. Do not redesign the generated home page as part of this change.

## Read-model implementation strategy and guardrails

1. Apply owner/environment AND scope plus `id < before_id` to `review_cases` in SQL, order `id DESC`, and fetch at most 26 candidates. Use the extra row only for `has_more?`; enrich and display at most 25. `next_before_id` is the last DISPLAYED ID only when more rows exist.
2. Load only each selected case's current snapshot and at most one latest review. Use same-case joins and a latest-per-case subquery/lateral join or equivalent bounded query; never `get_case/1` per row or load every review to find the last one. Fetch case/current-snapshot/latest-review binding together so those references cannot be accidentally mixed across reads/cases.
3. Batch source reads for the displayed finding/image IDs and saved scopes using the existing `Triage.Inventory.Finding`, `Image`, `ImagePlacement`, `FindingEvent` schemas. Preload images in a batch; obtain scoped placements and lifecycle events in fixed query families, not per-row calls to `Inventory.fetch_finding/2`.
4. Match placements by image ID AND saved owner AND environment. Require at least one active matching placement for a source to be in scope, but include ALL matching placements (active and inactive) in the canonical payload, just like PR 2. Include all of that finding's lifecycle events and preserve existing deterministic ordering and timestamp treatment.
5. Assemble the same `finding` (with image), `placements`, `events` shape and call the EXISTING private canonical snapshot builder/hash. Do not copy, simplify, truncate or re-version its algorithm. Do not load `other_occurrences` or cross-CVE inventory for this purpose; they are not part of the hash. Implement this narrow batch reader in Cases, without modifying Inventory's public/detail behavior or the write paths.
6. Use differential tests against `Cases.get_case/1` for committed fixture states to prove status/hash semantics match. A read/assembly failure must never become `:current`; show a controlled queue error rather than inventing trustworthy data.
7. Performance acceptance: instrument SELECTs for an isolated `list_cases/1` call (fixture setup excluded). Both a 1-case and a 25-case page must stay within 8 SELECTs, without query count scaling per row. Filter options may use up to 2 separate SELECTs. Record actual counts; this is a query-budget check, not a claimed production latency benchmark.
8. A fixed query count/page size does NOT bound source history length: full lifecycle events and matching placements are required by the existing hash. Keep this limitation explicit. Do not truncate history, cache stale status, skip source checks or hide the evidence badge to meet a budget. If representative local fixtures expose unacceptable cost, stop and propose a separately reviewed read-model optimization.
9. Reads take no write/row locks and are not a global, frozen dashboard snapshot. Source data can change after a read or between its batch queries; badges are advisory results of that read, not an authorization or production-freshness assertion. Manual reload recomputes; detail/write operations re-read and keep their existing revision/hash checks. No automatic draft submission, rebinding or evidence recapture follows from queue status.

## Implementation sequence and disjoint ownership

The user has now authorized implementation of this prepared slice with zro/glm-5.3 fan-out. First confirm the working-tree baseline without discarding existing/untracked work; no git reset/clean, auto-commit or external PR.

1. Freeze the contracts above and create tests/fixtures in an owned test partition. Existing 161 tests are the baseline, not a target count for the completed PR 3 suite.
2. If using GLM fan-out, use two edit-only writers with disjoint files:
   - **A — read model:** `lib/triage/cases.ex`, new `test/triage/cases_queue_test.exs`. Own batching, validation, projection/status truth table, pagination, query-budget and read-purity tests. Do not change schemas/migrations or existing write tests to force a pass.
   - **B — queue UI:** new `lib/triage_web/case_filters.ex`, `lib/triage_web/live/case_live/index.ex`; narrow router/layout/home/case-detail navigation changes; new `test/triage_web/case_filters_test.exs`, `test/triage_web/live/case_live_index_test.exs`; narrow additional assertions in `test/triage_web/live/case_live_test.exs` and page-controller tests; `README.md` queue usage. Do not edit Cases, Inventory, FindingFilters, endpoint/serializer, or shared fixture definitions.
3. No parallel compilation/formatting/tests or browser servers while either writer is editing. One serialized integrator resolves actual integration failures, runs targeted tests then full `mix precommit` once on the final source, and inspects any failure before retrying. Preserve lockfiles unless a justified change was explicitly approved.
4. Independent Astra review/verification starts only after integration. Verify real shipped-browser navigation and public context behavior; do not substitute a patched client or claim the GLM suite was independently rerun. For a demonstrated defect, fix the narrow cause with a failing-first regression and rerun affected checks, not every unchanged passing audit.
5. Record exact results and cleanup in this plan/roadmap; keep planning review separate from implementation signoff. No migration down/up or broad PR 2 persistence re-audit is necessary if schema/write paths stay untouched; escalate only for an actual cross-cutting change or failure.

## Acceptance ledger — implementation checks, FINAL PASS (2026-09-10 closeout; combined coverage per final independent Astra signoff `0c4be006927148158fd8a6c659ed3503`, see the record below)

- [x] Public `Cases.list_cases/0,1`, `Cases.case_filter_options/0`, CaseFilters `parse/1`, `parse_event/1`, `query_params/1`, and `CaseLive.Index` exist and match this contract. `/cases` is registered; `/cases/:id` and finding routes still resolve. No new supervisor/config/dependency entries are needed; existing guarded V2 websocket/longpoll transports remain unchanged.
- [x] Context/parser tests cover absent/All, each scope alone, AND scope, valid unknown and retired scope; malformed keyword lists/maps/structs, duplicate/unknown context keys; raw unsafe/oversized/invalid-UTF-8 values; wrapper ambiguity; cursor bounds. Invalid context input performs zero queries, and invalid UI input exposes no old rows or widened scope.
- [x] Test 0, 1, 25, 26 and >50 cases, same-CVE multi-scope rows, tie timestamps, exhausted/nonexistent in-range cursor and concurrent newer insertion between pages. Verify strict order, no duplicates/skips in the existing cursor range, correct sentinel handling, newest/reset/reload and URL restoration. Suppressed/resolved observations and retired-scope cases remain discoverable.
- [x] Truth table covers no review; same-snapshot/current-source review; source changes before recapture; recapture with an older review; explicit fresh review; retired placement with/without review. Queue evidence statuses agree with detail for the same committed fixture state. Missing-data/error handling cannot claim current; do not disable FKs/triggers to manufacture unreachable source deletion.
- [x] Frozen finding/image text stays captured until explicit recapture on the existing detail page; new source facts change warnings, not captured evidence. Latest review is deterministic and same-case; no full histories/tokens or fabricated lifecycle ages are displayed.
- [x] Exact no-write evidence for queue GET/mount, URL/filter/cursor navigation, manual reload and malformed/forged events: compare counts AND content/revision/hash fingerprints for all 4 review tables and all 4 source tables. Counts alone do not prove purity. Measure after deliberate fixture setup; rollback Sandbox transactions normally.
- [x] Call-specific SELECT telemetry (a `[:triage, :repo, :query]` telemetry handler counting events during the call, fixture setup excluded) proves the <=8 list / <=2 options query budget at 1 and 25 rows, including source-status checks. Large per-case event fixtures do not change the hash or silently lose evidence. No `Enum.map(&Cases.get_case/1)` or per-row inventory calls, no post-limit derived-status filtering.
- [x] LiveView tests exercise streams/DOM IDs, literal hostile text, filter recovery valid -> invalid -> valid, empty states, pagination, unsupported events, reload and independent scopes. Navigation tests cover row-saved scope under All and partial filters, canonical case-scope return, and removal of queue links after invalid case navigation; all PR 2 draft/conflict/retry/navigation regressions remain green.
- [x] Independent real-browser journey with the actual shipped same-origin scripts: home/navigation -> queue -> scope -> older/newest -> detail -> Cases for this scope, browser Back and hard reload; empty/malformed filters; a second tab's explicit review/recapture becomes visible after queue reload without any queue write. No unexpected JS/channel errors or external requests. Application persistence semantics remain PR 2's, not a new queue-specific store.
- [x] Targeted context/filter/LiveView tests pass, then the complete suite including the 161-test baseline passes, with format and warnings-as-errors checks. A docs-only preparation is not represented as a successful implementation test run.
- [x] Development and shared test data/schema preserved; all owned verification resources cleaned; user's app left stopped. Durable closeout states actual commands/counts, independent vs carried-forward evidence, remaining limits and any failures honestly.

## Safe verification procedure for the implementation phase

- Read `AGENTS.md`, pinned `.mise.toml` and relevant `mix help` before execution. Every mix command must explicitly use `MIX_ENV=test` and a fresh unique `MIX_TEST_PARTITION`, yielding an allowlisted database such as `triage_test_pr3_<unique_nonce>`; reject a preexisting target rather than adopting/resetting it.
- BEFORE create/migrate/seed/test/probe/drop, use `mix run --no-start` to assert `Mix.env() == :test` and configured Repo database equals the literal owned allowlist value. After connecting, assert `current_database()` too. Never use `mix ecto.reset` or seed/migrate/drop `triage_dev` or shared `triage_test`; the test alias itself creates/migrates, so guard it first.
- Run targeted new context/filter/index suites plus touched CaseLive/home suites, then one final `mix precommit`. Use normal Sandbox rollback and supervised deterministic synchronization, not sleeps or weakened append-only triggers. Inspect nonzero command outputs; fix causes rather than repeatedly running unchanged failures.
- Browser probes need a separately owned disposable database/server/Chrome profile and loopback non-4000/non-4002 ports. Read the CDP skill when actually running them. Override test server/pool settings only in an owned temporary runner after the exact database guard; do not edit endpoint/security config or run the development app.
- Capture preexisting dev/shared-test row fingerprints and schema before/after read-only; capture implementation source manifests before verification. Clean only owned literal database names, PIDs, profiles and listeners in finally-style cleanup. Keep temporary raw evidence outside the repository and a compact durable report here.

## Preparation record

- [x] PR 2 baseline, current code paths, scopes/hash/navigation constraints and test-isolation hazards inspected.
- [x] Two independent read-only GLM design reviews completed; discrepancies resolved against the actual source.
- [x] Scope, API, status truth table, query budget, navigation, ownership and acceptance ledger drafted.
- [x] Independent read-only plan review completed and blocking ambiguities resolved (2026-09-10; GLM `8db09a021b1c4a57a5cdde2b75cbc312` domain/read-model and `e4f769b428a14178b4fef665c8f75ab2` web/verification — both verdicts READY-AFTER-FIXES; the blocking findings — nonexistent `opened_at` column, unspecified nil-snapshot mapping, ambiguous `FindingFilters.parse/1` reuse instruction, literal-`all` and event-cursor wrapper ambiguity — were corrected in this plan; the <=8 query budget, no-migration claim, canonical-builder reuse and latest-review tie-break were verified sound against the code).
- [x] User has requested implementation of this prepared slice: "check with me and help me and implement pr3 orchestrate and fan out glm-5.3 [zro]". The local-only queue-first contract is now authorized; shared deployment/news remain excluded.

## Implementation kickoff and execution obligations (completed 2026-09-10; retained as the executed process record)

The concurrent update to `IMPLEMENTATION_ROADMAP.md` was read and reconciled: its active Later slices paragraph correctly assigns the Review Queue to PR 3 and defers My Work/news. Preserve that change and all historical PR 1/2 records. The earlier preparation-only statements describe the completed preparation phase, not a prohibition on this newly authorized implementation.

Execute the entire authorized slice, not merely this status edit:

1. Capture a source/working-tree baseline before application writers start, including untracked `app/` files. Treat `.pi` runtime changes as unrelated harness state, never edit them. No reset/clean, commits, PR creation or unrelated cleanup. Re-read target regions if another session changes them.
2. Fan out two `zro/glm-5.3` writers through `agents.run` with Python Fabric and `asyncio.gather`, using the exact A/B ownership above. Writers are edit-only: do not grant/run shell, builds, tests, databases, servers or recursive handoffs during their parallel phase. Supply the frozen API/result/status/DOM contracts and require each to read `AGENTS.md` and trace its execution path before editing. New tests are authored with the code, not deferred to a build-only signoff.
3. After BOTH writers stop, one serialized GLM integrator owns compilation/formatting, narrowly scoped integration fixes, targeted context/filter/index/touched navigation tests, differential freshness and 1-vs-25-row query-budget probes, and the final full `mix precommit`. BEFORE every write-capable mix command, enforce `MIX_ENV=test`, a fresh unique partition and exact configured/connected database allowlist, using `mix run --no-start` before boot. No writes to `triage_dev` or shared `triage_test`. Record failing outputs and fixes rather than blindly rerunning. Preserve Inventory, schema/migrations, PR 2 write/hash algorithms, endpoint/serializer/assets security, dependencies and lockfile. A queue data-load error must not masquerade as a current review.
4. Run an independent `openai-codex/gpt-6-astra` verifier only AFTER the final writer/integrator stops. Read the CDP skill for real browser work. Use four actual shipped same-origin scripts, a freshly owned disposable database, loopback non-4000/non-4002 server port and owned isolated Chrome/profile/daemon. Cover the plan's browser journey, cursor/invalid-URL recovery, saved-scope links, literal text, manual reload after second-tab review/recapture, no-write fingerprints and public API/query-budget invariants. No app/test/config edits by the verifier, no duplicate full-suite run without a reason, no unnecessary PR 2 migration/restart re-audit if write paths/schema are unchanged. Never substitute a patched client or weaken the guarded V2 transports.
5. For a genuine failure, record its minimal reproduction, have a bounded GLM correction add a failing regression and fix only that cause, then rerun affected checks and any required final suite. Preserve passing evidence through source hashes rather than rerunning unchanged audits. Do not claim PASS while a required browser/runtime check is still blocked.
6. Cleanup only owned databases/PIDs/profiles/listeners/connections in finally-style paths, retain temporary raw evidence outside the repo, verify dev/shared-test data and schema unchanged, and leave the user's app stopped. Finish with an accurate PR 3 closeout in this plan and the roadmap: actual test/query/browser counts, agent IDs, paths, preserved invariants, failures/fixes and remaining limitations. Mechanically confirm public symbols and routes; tick acceptance items only with evidence.

Next after this slice: propose a separate local What's New view for locally observed lifecycle changes with honest provenance/timestamps. Do not equate first seen locally with CVE publication date, or add that feed to this queue PR implicitly.

## Final implementation and verification record (2026-09-10)

- **Delivered**: the read-only `/cases` Review Queue — `Triage.Cases.list_cases/1` + `case_filter_options/0`, `TriageWeb.CaseFilters` (`parse/1`/`parse_event/1`/`query_params/1`), `CaseLive.Index`, team/environment filters, keyset pagination (25, Older/Newest), the two status axes, and home/layout/detail navigation. Local-only, synthetic-data scope; no news feed, auth, collection, AI, exception writes, schema/migration, dependency or transport changes.
- **End-to-end checks and query counts**: final `mix precommit` **236 passed** (161 PR 2 baseline + 75 PR 3; 14 CaseLive Index tests) — GLM `79f594d9e5cc4d6eafc622908689b67a`, raw logs at `/tmp/pr3stream_20260910_160152/` (temporary), Astra-audited, not independently rerun. Fresh API pass **276 assertions** with SELECT budget **4 at one row / 4 at 25 rows / 2 options** (within the <=8/<=2 contract) — Astra `4b41989bf87048aeb4fdb1fcd61123bd`, `/tmp/pr3astrafinal_20260910_144950/` (temporary). Final independent browser signoff **31/31 fresh Chrome assertions PASS** — rows -> empty -> malformed owner-array event -> rows -> empty on one mounted LiveView; empty computed-visible outside the stream; canonical filter URLs, saved-scope links, detail/back, hard reload, Browser Back, nil-snapshot safety; second-tab review -> Reload; own source change -> frozen identity + stale; two-click recapture keeping the old review needs-revalidation; fresh review -> Current review (Astra `0c4be006927148158fd8a6c659ed3503`, `/tmp/pr3astrasign_20260910_160903/`, temporary). The 28 earlier passing browser assertions from `/tmp/pr3astra_20260910_144502/` (Astra `1f54cfff73bc481490ee413815ad4225`, e.g. pagination) are retained where relevant; these are not additive unique counts. `/tmp` evidence is OS-cleanable; this markdown record is durable.
- **Hash continuity and combined ledger coverage**: final source manifest `01c089b64ec3f265e62be8577c5e67014aa870cfb66680d0d13df523c06845f3`; domain `cases.ex` `93aec3e942fc7e2f296dd9fd9715a200aa72a5087038edd16a31ae06bad2072f`; index UI `35df3762246c4f975db2c32a895cb0f72550b635969568e6a37e97acaa1b54ee`. Only `case_live/index.ex` and its test differ from the 276-passing tree; reversing the two changes reproduces the prior bytes exactly. All 11 acceptance items have combined coverage from fresh + retained + attributed-GLM evidence; the full 236 were not all independently Astra-rerun.
- **Failure/fix history (historical, retained as it happened — not rewritten as passes)**: coordinator `041cc0737b6846f0ac0b7d70754cdd25` ran the requested GLM domain/UI fan-out + serialized integration (fe0e40eef7c3465ca9e19f47757660da226 tests) and timed out after GLM `596fc0d288094db7857715bc152e8292` fixed the first Astra defects (empty CSS, struct parse, unsafe query_params) with 6 red-first tests -> 232. Partial Astra run `/tmp/pr3astra2_20260910_150908/` died before tests/DB/server; recovery `5667af768da5406d9d98ae56ff93000f` proved nothing active/owned and no protected rows/schema changes, so no cleanup was needed. Contract gaps found in readback were fixed by GLM `0bf844a71a6646b0a9b8935a8542f5ac` (`/tmp/pr3contract_glm_20260910_153238/`): top-level frozen image with nested compat, single same-case snapshot/latest-review SELECT, unknown-not-live identity on nil snapshot, outer-struct-wrapper rejection; 3 new + strengthened red-first tests -> 235, queries 6 -> 4. Astra `4b41989...` then passed 276 API but the fresh browser empty state was still a static div inside the stream (5/6 fresh browser FAIL); GLM `79f594...` moved the conditional empty div outside the stream as an adjacent sibling with 1 new red-first structure/transition test -> 236. Final Astra `0c4be...` 31/31 fresh browser PASS.
- **Cleanup and remaining limitations**: owned DB/connections, server PID 17807, Chrome 17808, daemon 18001 and owned profiles removed; ports 4000/4002/43183/19283/19883 free; preexisting daemon 27631:9876 untouched; dev/shared FULL rows + normalized schemas match before/after and all prior baselines; app left stopped. No additional API/full-suite/migration/restart rechecks were needed (writes/schema unchanged). Remaining limitations: local synthetic unauthenticated model only; shared deployment blocked on a separate auth milestone; What's New deferred; unbounded source histories and advisory/non-atomic freshness remain. No commits or external PRs created.
