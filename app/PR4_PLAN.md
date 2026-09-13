# PR 4 — local read-only What's New

Status: IMPLEMENTED; independent API/browser/telemetry and wave-local protection
checks PASS. The prior browser journey completed 29/29 assertions; the final PR5
recheck (2026-09-10) confirmed protected UI/assets/Inventory/Cases/config/migration
hashes still match that verified manifest, so no duplicate browser run was needed.
Historical pre-PR4 invariance remains BLOCKED without the original baseline.
This is a small local lifecycle feed, not production collection or personal My Work.

## Baseline and design reviews

PR 3 is complete: 236 full-suite tests (GLM), 276 independent Astra API assertions and 31 fresh browser assertions; durable evidence is in PR3_PLAN.md. Do not repeat that implementation or rerun unchanged verification without cause. Preserve every existing workspace change and historical failure record. Do not commit or create external PRs.

Read-only DeepSeek design reviews: domain `80eb3b05e05f4c3eaa4a6d72ef43ae61`; UI/acceptance `d02357ce40a64e3db856a7971c5a93e3`. Coordinator inspected FindingEvent, Inventory.fetch_finding/2, placement filters, CaseFilters, CaseLive.Index, router and test config. Fovea has incomplete Elixir symbol extraction and no HEEx extractor; native source reads govern.

## Frozen product choices

- Route `/whats-new`, title **What's New**, subtitle **Local inventory lifecycle events · read-only**. Add navigation and home entry links without redesign.
- Inventory-wide existing `finding_events`, not only saved cases. Exactly one row per event, not one per placement or CVE. Include all three event types and findings currently resolved or suppressed. Do not reuse Inventory.list_groups, which excludes resolved findings.
- Order event `id DESC`, label **Newest recorded first (record ID order)**. Fixed page size 25, fetch 26 sentinel, display/enrich only 25. This is not chronological observation, scan freshness, priority or publication ordering. Backdated/equal occurred_at values do not alter this order. New inserts appear on explicit Newest/Reload of newest page; current older-page cursor remains stable. No offset counts or totals.
- Labels: appeared = **First observed locally**; resolved = **No longer observed locally**; reopened = **Observed again locally**. Show occurred_at as **Recorded observation time**. Notes are escaped source text, not generated explanations. Never claim a verified fix, approval, CVE publication date, complete scan or trustworthy timer/SLA.
- Finding/image fields are CURRENT local metadata joined to an existing event, NOT frozen historical facts. Explicitly label this distinction. Do not call the feed immutable: events can be updated by seeds and cascade-deleted with findings. No synthesized events from first_seen; no invention of missing history.
- Optional owner and environment combine with AND on the SAME placement. Include inactive recorded placements. Scope means 'events for findings whose image has a recorded placement matching these filters', NOT attribution to that team/environment when the event occurred. Display this caveat and active/inactive labels. Deduplicate before LIMIT using EXISTS/subquery, not a multiplicative placement join or post-limit dedupe.
- Unscoped feed includes events with no placements; scoped feed excludes them. Options come from all recorded placements, active and inactive, never saved case scopes. Unknown valid scope is honest empty, not All.
- Existing Inventory detail allows unscoped access but requires an active matching placement under any scope. Compute row detail_available? consistently: true when unscoped OR a matching active placement exists. Link to `/findings/:id` with exactly the selected owner/environment only when available. Otherwise show **No active placement in this scope; current scoped detail unavailable**, with no widened fallback link. Existing finding detail stays unchanged and its Back to inventory behavior remains; browser Back restores feed URL. No return_to parameter or new case links.
- Show local/synthetic/unauthenticated coverage warning. Filters are not authorization. Suppression is not mitigation; absence is not remediation. No personal assignments, AI, external news/services, import, collectors, jobs, polling, notifications, auth, exception writes, schema/index/dependency changes or migration edits. PR1–3 write paths, canonical hashes, protected websocket/longpoll serializers, config and shipped assets remain unchanged.

## Public contract

New `Triage.Activity` in `lib/triage/activity.ex` (leave Inventory/Cases untouched):

- `list_events(opts \\ [])`: keyword list with only :owner, :environment, :before_id; reject non-keyword shapes, structs, unknown or duplicate keys. Scope nil/blank is All; require valid UTF-8, no raw NUL/C0/DEL, trimmed <=120 characters; malformed values return controlled :invalid_scope, not unscoped reads. before_id nil or positive integer <=9223372036854775807; invalid returns :invalid_cursor. Bad options return :invalid_request. Validate BEFORE queries, no broad rescue hiding programming/DB errors.
- Success `{:ok, %{rows: rows, has_more?: boolean, next_before_id: integer | nil}}`; next_before_id is last displayed id only if more rows exist.
- Row plain map: `%{id: event_id, finding_id: id, event: string, occurred_at: DateTime, note: string_or_nil, finding: %{cve: value, package_name: value, package_version: value, severity: value, suppressed: boolean, resolved_at: value}, image: %{digest: value, repository: value, tag: value}, placements: [%{owner: value, environment: value, namespace: value, active: boolean}], detail_available?: boolean}`. Placements only matching current filters, deterministic order; all placements when unscoped. No histories/full payloads/per-row detail loading.
- `event_filter_options/0` -> `%{owners: sorted_unique_nonblank_strings, environments: sorted_unique_nonblank_strings}`. At most 2 SELECTs; list_events at most 3 SELECTs at BOTH 1 and 25 displayed rows. Batch events/findings/images and placements. No queries/writes for invalid list input. Query count is not a production latency/index guarantee.

New `TriageWeb.ActivityFilters`: defaults/0, parse/1, parse_event/1, query_params/1. Same owner/environment/before URL and plain-map/wrapper/bigint/metadata/output safety contract as CaseFilters, without changing CaseFilters/FindingFilters. Prefer narrow delegation to the existing identical validator over copying it; document and test the shared contract. Return normalized owner/environment/before_id/invalid fields. URL before absent/nil/empty means newest, otherwise 1–19 ASCII digits positive bigint; reject whitespace/sign/type/overflow. Reserved filters invalid in URL; only one plain event wrapper; reject structs including outer structs carrying filters; unrelated metadata ignored. Invalid recognized input must never load a widened view.

New `TriageWeb.WhatsNewLive` in `lib/triage_web/live/whats_new_live.ex`. handle_params authoritative, scope changes reset cursor, manual Reload reuses current URL. Invalid params/events clear stream, links and pagination and show error; unknown events controlled. Explicit empty-state assign and conditional empty message OUTSIDE stream container (PR3 browser regression lesson). Use shipped assets, Layouts.app and conventional forms. Stable DOM IDs for feed/form/error/empty/reload/Older/Newest/items/detail links. Older/Newest and browser Back URL-restorable; no automatic writes.

## Orchestration and ownership — remaining execution steps

The trajectory executor must CONTINUE from this plan, not merely report the file write. Use exactly requested implementation model `zro/deepseek-v4.1-flash`, never silently substitute GLM. Discover tools/contracts as needed. Fan out two nonrecursive writers concurrently after confirming the contract; no concurrent Mix/DB commands on a shared build. Writers edit and report static checks only, then stop:

1. Domain writer owns only new activity.ex and test/triage/activity_test.exs. Add contract, dedupe, same-placement scope, inactive/no-placement, invalid-boundary, backdated/tied observations, pagination and telemetry tests.
2. UI writer owns only new activity_filters.ex, whats_new_live.ex, their new filter/LiveView tests, plus minimal router/layout/home navigation edits. Read existing files first. No Inventory/Cases/other-filter/detail/transport/assets edits. Add parser and empty-stream structure/transitions, scope-preserving/disabled links and escaping regressions. Existing page/nav test assertion adjustment only if genuinely required, document exact reason.
3. One serialized DeepSeek integrator checks actual source and contracts, runs targeted tests and probes then ONE full `mix precommit`, fixes specific failures with regression evidence, and updates app/README.md plus this ledger/roadmap honestly. Use an acceptance ledger, source manifests and retained logs, not build-only claims. Allow no broad rewrite or extra feature. Report a blocker if broader scope is required.
4. Independent `openai-codex/gpt-6-astra` verification AFTER writers/integrator stop. Read final sources/logs, mechanically confirm APIs and route, run small direct API/purity/query probes plus shipped-browser journey. No application edits by verifier. Fix only reported defects with DeepSeek and recheck affected paths; retain unchanged passing evidence by source hashes. No endless full-suite reruns or duplicate implementation. Keep agent IDs/raw evidence paths and final counts; stop honestly if blocked/timed out.
5. Close this ledger/roadmap only when supported by actual verification; preserve failure/fix history, distinguish implementation test evidence from independent checks. Cleanup and leave app stopped. No next milestone automatically.

## Runtime isolation and cleanup (mandatory)

Read app/AGENTS.md fully; pinned mise runtime; read Mix task help. Never use app dev/shared test DB for writes. Each integration/verifier owns a fresh unique literal `triage_test_pr4_<role>_<nonce>` and refuses preexisting DB. Explicit MIX_ENV=test plus correct MIX_TEST_PARTITION on EVERY Mix operation. Guard with `mix run --no-start` checking environment and configured literal Repo DB BEFORE each create/migrate/seed/test/probe/drop; confirm current_database after connect. A partition without MIX_ENV=test is NOT isolation. Never reset/migrate/seed/drop triage_dev or shared triage_test, never access legacy/production data/credentials.

Capture protected dev/shared FULL row hashes and normalized FULL schema before/after with readonly operations; normalize only pg_dump random restrict/unrestrict lines. Tests/probes use own synthetic data and compare all 8 app tables across readonly phases, separately bracketing authorized fixture insertions. No changes to existing migration/trigger semantics. Use existing build serially rather than fresh-build dependency rebuild. Use pi.bash settle=True and inspect ok/output/exitCode for nonzero probes, one timeout in seconds for long suite.

Browser verifier reads CDP skill, owns isolated fresh Chrome profile/daemon/server and unused loopback ports NOT4000/4002, uses actual four shipped scripts with same-origin request checks. Do not touch preexisting daemon PID27631:9876 or any unrelated process; revalidate ownership rather than assuming old PID identity. Record and finally remove only owned DB/connections/processes/profiles/listeners. No killall/pkill. Runtime pool/server overrides only in own temporary runner after DB guard, never project config. Retain evidence outside repository; record compact durable summary here as /tmp can be removed.

## Acceptance ledger

Current ledger includes the later independent browser/telemetry and wave-local
protected hashes. The original historical baseline remains unavailable; do not
confuse bounded before/after evidence with proof of pre-review invariance.

- [x] Public Activity APIs, ActivityFilters and /whats-new route/navigation mechanically confirmed. **Astra confirmed the APIs, `ActivityFilters` and the `/whats-new` route plus primary navigation** (router `/whats-new` registration, primary navigation, `Activity.list_events/1`, `event_filter_options/0` and the four `ActivityFilters` delegates). **Still blocked:** a historical pre-review protected PR1–3 path baseline — the original baseline was never captured, so invariance before that review began remains unproven.
- [x] One event per row, all kinds/resolved/suppressed/no-placement inclusion, current metadata versus historical event and truthful labels — covered by `app/test/triage/activity_test.exs` (27 passed on the clean partition DB `triage_test_pr4fix1`).
- [x] Same-placement owner AND environment scoping, inactive inclusion, options, unknown empty, no historical ownership claims — covered by `activity_test.exs`.
- [x] Exactly 0/1/25/26/>50 pagination cases, id DESC independent of backdated/tied observation times, insertion between pages, no duplicate/skipped records under stable source — covered by `activity_test.exs`.
- [x] Total malformed domain/URL/event/struct/wrapper/output boundaries; invalid domain input performs zero SELECTs; UI invalid clears rather than widens. The targeted boundary tests pass and PR4 SELECT telemetry measured **0 SELECTs across eight malformed requests**.
- [x] Scope-preserving detail links and inactive-only no-fallback behavior: prior
  independent 29/29 browser journey. Current detail/UI/assets/Inventory/Cases
  hashes still match that verified manifest in the final importer recheck; no
  browser rerun. Original pre-PR4 invariance remains blocked, not inferred.
- [x] Query telemetry <=3 SELECTs at 1/25 rows and <=2 options; all-eight-table counts/full-row hashes unchanged across readonly phases. Measured **2 SELECTs at one row, 2 at 25 rows, 2 for options and 0 for eight malformed requests**, with all eight table hashes unchanged before/after.
- [x] Targeted ExUnit/LiveView tests plus full precommit/format/warnings pass, preserving verified baseline regressions. `mix test activity_test.exs test_environment_test.exs whats_new_live_test.exs --seed 0` = 40 passed; `mix precommit` = 292 passed on the still-seeded shared `triage_test`; `mix format --check-formatted` exit 0.
- [x] Independent real browser: navigation, filters, Older/Newest, detail/back/hard reload, rows->empty->invalid->rows->empty on SAME mount with computed visibility, literal hostile text, manual Reload observes an explicitly inserted own-fixture event without feed writes. **29/29 final assertions passed** on a fresh headless Chrome profile (same root LiveView `phx-GNQUZWXVfUCr3ABE`, computed visibility for empty/error/stream states, manual Reload showed the owned backdated event first by record id, hostile `<img ...>` note rendered as text).
- [x] Four shipped scripts, no unexpected JS/channel/request failures or external page/WebSocket traffic; no security/config/assets weakening. All four shipped same-origin scripts returned HTTP 200 and no unexpected HTTP >=400, request/WebSocket errors, JS exceptions or external requests were observed (background-process traffic outside the attached page is not claimed audited).
- [x] Final source manifest, protected DB/schema proof for this wave, all owned resources removed. The 177-file protected source manifest was byte-identical before/after (SHA-256 `bc2706cb6dd14516a3044876df5ece91d2c99526b155f89709ebd2f3052c39e6`), `triage_dev` full-row/schema hashes were unchanged (8-table rows artifact SHA-256 `0de53409182fe40a0515c7518ed4e1c6cf635ec7ab3ddd32631ad7e8f9edd3a9`, counts 9/10/44/64/9/9/1/10) and shared `triage_test` was unchanged (artifact `a9be8ca6e9240512189f0740c514629a51e795e1364c4c6032552bda25d44978`, counts 3/4/8/11/0/0/0/0); both normalized schema dumps `5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`. Owned DB/server/Chrome/daemon and ports were removed. **Still blocked:** the historical pre-review protected-path baseline (no original baseline captured) and full-sequence/catalog audit (full-row hashes cover the eight application tables only).

## Implementation and verification record

Root cause of the 17 Activity failures: `app/mix.exs` chained `run priv/repo/seeds.exs` into `ecto.setup`, so `MIX_ENV=test mix ecto.reset` seeded `triage_test`. The Ecto SQL sandbox rolls back test writes but not pre-existing seeded rows.

Fixes:
- `app/mix.exs` — `ecto.setup` no longer seeds; new `ecto.seed` alias; `ecto.reset = [ecto.drop, ecto.setup, ecto.seed]`; the `test` alias creates and migrates without seeding.
- `app/test/support/data_case.ex` — new `reset_inventory!/0` running `TRUNCATE TABLE images, findings, finding_events, image_placements CASCADE`.
- `app/test/triage/activity_test.exs` and `app/test/triage_web/live/whats_new_live_test.exs` — call `reset_inventory!/0` in `setup`.
- `app/test/triage/test_environment_test.exs` — new guard.

Checks:
- Targeted: `mix test activity_test.exs test_environment_test.exs whats_new_live_test.exs --seed 0` = **40 passed**.
- `mix precommit` = **292 passed** on the still-seeded shared `triage_test`.
- `mix format --check-formatted` = exit 0.
- `app/test/triage/activity_test.exs` = **27 passed** on the clean partition DB `triage_test_pr4fix1`.

Independent verification: `openai-codex/gpt-6-astra` verified the `mix.exs` aliases, `reset_inventory!/0`, both `setup` call sites, the existence of `Triage.Activity`/`ActivityFilters`, and the `/whats-new` route plus primary navigation, and independently re-ran the targeted command (40 passed). Astra did **not** run the full suite; the 292 figure was produced by the coordinator.

That earlier outstanding list is superseded by the independent remaining-review
record: **29/29 browser assertions**, **2/2/2/0 SELECT** telemetry at one row,
25 rows, options and malformed requests, and unchanged full-row/schema hashes.
See `/tmp/triage-astra-remaining-review.md`; browser/network limits there remain
applicable. The final importer recheck retained that evidence by matching all
protected source hashes rather than repeating the journey. Fresh PR5 safety,
validation/concurrency/atomicity checks and one full precommit (**337 passed**)
are recorded in `PR5_PLAN.md` and `/tmp/triage-import-final-recheck.md`.
Dev/shared full-row/schema hashes were again unchanged; the owned DB was dropped
with zero connections and no new browser/server processes were created. This is
not proof against transient external writes or missing historical-baseline drift.
The original baseline and a real approved legacy export remain explicitly blocked.
