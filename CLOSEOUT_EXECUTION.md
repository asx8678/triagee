# Local triage closeout — execution and acceptance ledger

Status: IN PROGRESS — final guard/browser verification repair. Started from committed HEAD `0b7fc1af6223e3321cb5a6cf666a0af3f2fe61c6` after the owner requested “do the remaining fan out agents”, followed by “do remaining”. The prior executor implemented the UI and reported tests, but its browser acceptance was explicitly deferred and documentation finalization left contradictory fragments. Do not call all acceptance verified until this repair is complete.

## Required final verification repair — coordinator handoff

All four fan-out agents are COMPLETED; do not spawn duplicate writers or redo their UI work. Current source was read and spot-checked after the handoff. `git diff --check` passes. Actual diff outside .pi is 5 root docs, 10 production/test tracked app files plus inventory_readability_test.exs and 3 new regression files; final exact counts must be recomputed, not copied from the prior claim. Existing app/config/test.exs currently matches the original localhost/default-port configuration. No new filter/auth/ingestion/lookup feature is authorized.

### Concrete findings requiring work

1. This ledger had three duplicate Pending acceptance rows alongside DONE rows; those duplicates are removed in this initiating edit. Prior executor explicitly did not run browser CDP or `verify_owned_db.sh`, so prior 785/2 result is reported evidence, not a browser/guard pass.
2. CURRENT_STATUS.md lines 29–34 contains a pasted “Closeout verified” sentence followed by leftover “another worker is implementing”/“no current evidence” fragments. NEXT_STEPS_PLAN.md lines 11–16 and CVE_VISIBILITY_PLAN.md lines 5–8 have the same broken blockquote/pending fragments. Repair all three summaries coherently after verification. CHECKPOINT_REVIEW.md opening incorrectly calls current worktree app-clean; distinguish the committed baseline from the current uncommitted closeout. Do not invent staging chronology: initial app checkpoint was 6a8a5e5; later integrated delta was 0b7fc1a. Preserve historical sections rather than rewriting test history.
3. Browser acceptance is a real remaining task, not automatically deferred. Chromium and browser-harness-js are installed. CDP skill and lifecycle recipe have been read; use owned browser profile, owned harness port/state, explicit session.connect({port: own_debug_port}), bounded readiness/LiveView connected checks and cleanup, not a user's browser.
4. psql DOES exist: `/home/adam/.local/postgresql-16/usr/lib/postgresql/16/bin/psql`, version16.15. Its libs need `LD_LIBRARY_PATH=/home/adam/.local/postgresql-16/usr/lib/x86_64-linux-gnu`. Other postgres/initdb/pg_ctl binaries are in the same bin directory. Reuse read-only binaries; do not delete or change user-local installation. A fresh passwordless probe with credential lookup disabled at localhost:5432 failed exit2, `fe_sendauth: no password supplied`. A pre-existing listener is there. DO NOT read/guess passwords, reconfigure or stop that server. No downloads are needed.

### Frozen minimal verification-infrastructure extension

Add explicit optional `TRIAGE_OWNED_DB_PORT` for OWNED test verification only, default5432. Implement end to end in `app/scripts/verify_owned_db.sh`, `app/scripts/verify_owned_db.exs`, `app/config/test.exs`, guard selftests and `app/OWNED_DB_VERIFICATION.md`, plus targeted configuration tests if needed. Validate bounded ASCII decimal port1024..65535 BEFORE any database effects; reject empty/malformed/overflow. Preserve all default behavior with variable absent. The wrapper must pass the exact validated port to every psql connection and export it into Mix test configuration. Test config may use the override only with a valid generated `_ab_...` partition (fail closed otherwise); no dev/prod port change or arbitrary host/database/credential input. The .exs identity verifier must compare configured port with the validated expected owned port, NOT merely delete the existing5432 invariant. Preserve Repo membership, hostname localhost, username postgres, no URL/socket overrides, generated DB identity, first-SQL current_database, pristine tables, ambient partition/concurrency refusals, exact owned cleanup without FORCE/session termination. Add selftests for invalid port with zero effects, default5432, alternate-port propagation including cleanup, and existing failure paths. Mechanically confirm registration/doc/config and call sites. No ad-hoc app/config/test.exs rewrites to make tests pass.

### Execute and prove, in this order

A. Read app/AGENTS.md, complete relevant Mix task help and existing guard files/tests before implementation (parent has read them fully). Make scoped infrastructure changes with regression coverage; run guard selftests and smallest config tests/probes first. Use shell settle=True on nonzero, inspect failures before retry. No parallel shared builds.
B. Initialize a NEW uniquely named mktemp user-owned PG16 cluster with postgres role/trust authentication, loopback-only, a free high port and owned socket directory. Own PID/data path explicitly, use traps/finally. Never adopt old /tmp/triage_pg or pre-existing DB names. Export only the explicit owned port plus binary/library PATH needed, keep other guard environment sanitation. Run the REAL guarded `verify_owned_db.sh precommit` once on the final changed tree (it creates/drops its generated DB). Run compile/format/Credo/Dialyzer as needed, recording actual exit codes and full-suite totals. Prior785 results do not cover newly modified guard/config. Concurrency tests remain separately opt-in; do not count skipped tests as executed.
C. On this OWNED cluster create a separate fresh generated browser DB using the same config/current_database/pristine guards, explicit refusal of preexisting names and exact cleanup. Migrate and synthetic seed only that DB. Start one test-mode Endpoint with in-memory server/port settings, SQL sandbox :auto for owned browser fixtures, `TRIAGE_BIND=127.0.0.1` and `PORT=0` (or reserved owned random port); do not edit app config on disk and do not use user ports4000/4001/4002. Read actual bound port. Stage never-refreshed, populated/no-match, empty-success, failed-with-retained-cache synthetic states via existing context functions/owned fixture scripts; do not add production test routes. Use CDP to verify visible status and retained badges on findings/queue/case/Timeline, activity current-metadata qualification, deduped finding title/copy/navigation, and scope retained through Timeline Next/First paging and close/reset. Check mobile reflow, duplicate IDs, JS/channel/request errors and no external feed requests. Retain bounded actual assertion results, screenshots only if useful; do not manufacture browser signoff from LiveView tests. If blocked, record exact blocking evidence and leave browser acceptance partial.
D. Stop only the owned Endpoint/Chrome/harness. Drop exactly owned DBs after connections close, without FORCE; stop/remove only the owned cluster and profile/scratch dirs. Verify catalog absence/connections while cluster live, listener cleanup and unchanged pre-existing localhost5432/user ports. Preserve original user-local binaries and unrelated .pi/evidence.
E. Repair the malformed root summaries and this acceptance ledger with actual final outcomes. Separate committed baseline0b7fc1a, current uncommitted delta, inherited executor claims, fresh guarded tests, fresh browser evidence and explicit remaining contracts. Retain reproducible commands, relevant source hashes and logs under `evidence/closeout-final/` (logs need not be committed). No commit/stage/push. Read actual final files before summarizing. Do not finish by saying only that you intend to verify: either execute or report an evidenced blocker.


## Frozen scope

Close the existing local-only deliverable. Do not implement live collection, observation ingestion, SSO/shared deployment, automated remediation, AI, upstream exception writes, or real historical-data migration. No credential access, user/shared database effects, commit, stage, push, or deployment is authorized by this closeout. Preserve unrelated `.pi/` modifications and pre-existing evidence.

1. Show source-level KEV cache row count and latest refresh status/time on findings, queue, case and Timeline, independent of matching badges. Preserve cached-positive semantics after failed refresh and truthful never/empty/failed wording; never infer safety or invent a TTL policy. Existing overview/advisory receipt displays are not replaced gratuitously.
2. Put CVE identity in activity headings explicitly as current joined metadata; remove the duplicate finding eyebrow. Preserve DOM IDs, scope-carrying links, blank-value behavior, copy affordances and event-versus-current truth.
3. Correct stale root status/scope/checkpoint records without erasing historical failures or presenting earlier full-suite results as current. Keep KEV-only filters, new queue filters and global CVE navigation lookup as separately scoped follow-ups.
4. Verify actual combined source, tests, UI, and safety gates. Only coordinator may run database verification. Do not accept compiled DB tests as executed SQL or offline query probes as integration proof.

## Acceptance ledger

| Check | Status/evidence |
| --- | --- |
| KEV cache health is visible with populated/nonmatching, empty-success, never-refreshed and failed-refresh states | DONE — `Intel.kev_status/0` + `<.kev_source_status>` wired into findings (`finding_live/index.ex`), queue (`case_live/index.ex`), case header (`case_live/show.ex`), Timeline (`timeline_live.ex`, `timeline_live/lanes.ex`); context test `app/test/triage/intel_cache_test.exs`; new tests `app/test/triage_web/live/kev_status_test.exs`, `app/test/triage_web/kev_status_components_test.exs` |
| Cached markers stay per-advisory and batched; no network or write on browsing | DONE — one batched `kev_index/1` + one `kev_status/0` per view; read-only request contract retained |
| Activity CVE identity remains qualified as current metadata; finding title no longer duplicated | DONE — `app/lib/triage_web/live/whats_new_live.ex` adds CVE to the event title under a current-metadata qualifier; `app/lib/triage_web/live/finding_live/show.ex` eyebrow deduped; tests `app/test/triage_web/live/cve_presentation_test.exs` |
| Scope and status records accurately distinguish historical, committed and current verification | DONE — supersession notes in `CURRENT_STATUS.md`, `CHECKPOINT_REVIEW.md`, `NEXT_STEPS_PLAN.md`, `TIMELINE_SCOPE.md`, `CVE_VISIBILITY_PLAN.md` |
| New and previous unexecuted database regressions run on an owned DB | DONE — user-local trust-auth PostgreSQL 16.15 (`postgresql-16 16.15-0ubuntu0.24.04.1`, apt-extracted, no root) at `/tmp/triage_pg` on `127.0.0.1:55432`; owned database `triage_test_ab_close2026` created/migrated/dropped; closeout modules 31/31 passed |
| Static gate, full suite and relevant direct/browser probes on final combined tree | PARTIAL — prior executor reported compile/format/Credo/Dialyzer and 785 passed / 2 skipped. It explicitly did not run the owned-browser checks or the documented shell guard. Final repair below must execute those checks and retain actual logs; compilation/LiveView tests are not browser evidence. |
| No source/config/schema changes outside assigned scope; unrelated files preserved | DONE at finalization — 15 modified + 3 new app/doc files, all assigned; `app/config/test.exs` temporary socket override restored to HEAD (`hostname: "localhost"`); `/tmp/triage_pg` removed, owned cluster stopped; `.pi/` harness state and pre-existing evidence untouched |

## Coordination and implementation instructions

Four leaf agents were spawned before this ledger was written. Their handles appear below. Inspect their state/results with `agents.status`/`agents.wait`; do NOT duplicate ongoing writers. All share this tree, no worktree/cherry-pick is needed.

- `closeout-kev` owns Intel read status helper, shared UIComponents, finding/queue list, case header and Timeline parent/lanes, plus non-overlapping tests. It must not edit finding detail/activity/root docs.
- `closeout-polish` owns finding detail and activity LiveViews plus their existing tests; no shared component or other source edits.
- `closeout-docs` owns CURRENT_STATUS.md, CHECKPOINT_REVIEW.md, NEXT_STEPS_PLAN.md, TIMELINE_SCOPE.md and CVE_VISIBILITY_PLAN.md; provisional evidence only until coordinator finalization.
- `closeout-db-readiness` is strictly read-only; returns environment/prerequisite findings. Workers must never run `verify_owned_db.sh`, DB effects or shared builds. Coordinator serializes all builds/tests after writers stop.

## Remaining coordinator steps

1. Wait for agents; read the actual modified files and diff, inspect failures and any ownership conflict before accepting claims.
2. Read `app/AGENTS.md` and `app/OWNED_DB_VERIFICATION.md` fully. Guard wrapper is `app/scripts/verify_owned_db.sh`; uses pinned mise toolchain, passwordless localhost:5432 postgres and its own generated `triage_test_ab_...` DB. Preserve config-only, first-connection identity, pristine/population and exact cleanup checks. No unowned DB. Guarded precommit creates/drops only its owned DB. Full `mix ci` includes static checks; ordinary `mix test` alias creates/migrates and must not run unguarded.
3. Make a bounded good-faith attempt to resolve psql/server availability safely using the readiness findings. Prefer existing local tools or user-owned provisioning; no unsafe shared-service changes, credential lookup, blind sudo, force drops or session termination. If blocked by permissions/network/dependencies, retain exact evidence and do not label verified.
4. Execute smallest targeted new/previously-unexecuted regression suites and probes first, inspect/repair failures, then one full guarded precommit plus formatting/compile/Credo/Dialyzer checks on combined final source. Do not rerun unchanged passing full suites needlessly. Read Mix task help per safety procedure. Concurrency is an explicit separate opt-in if needed; never count normal skips as executed.
5. If an owned runtime can be established, use the CDP skill for owned-browser checks of empty/success/failure KEV states, activity/finding navigation and scoped Timeline paging. Do not take over user listeners/browser sessions; clean owned resources.
6. Finalize this ledger and status docs with exact current command outcomes, source hashes/revision, blockers, ownership/cleanup, and inherited-vs-fresh evidence. Mechanically confirm public helper/caller registrations and no unrequested routes/config/schema/dependencies. No commit/push. Report completed items and unresolved environmental/approval boundaries honestly.

Historical evidence: `evidence/code-quality-followup/REPORT.md` and `evidence/code-quality-retry/REPORT.md`. Latest filter evidence: 84 tests and 109,944 comparisons; latest full database gate BLOCKED. Earlier 721-pass result is not current SQL/history acceptance. Initial application diff was empty; only `.pi/` tracked modifications and 60 untracked evidence files were present.

## Agent handles

- closeout-kev: `16499d1bc662420e820f9c64bcd5286f`
- closeout-polish: `44f67cfba7ea4766ad4cce0a0891528c`
- closeout-docs: `db24919a52694e40af2feb2a1da0eb05`
- closeout-db-readiness: `70ed38a2903f40f8a688fd6a65fe3aaa`

## Prior executor verification record (retained; not final browser/guard signoff)

All acceptance checks on the combined tree (base HEAD 0b7fc1af6223e3321cb5a6cf666a0af3f2fe61c6; no commit/push made):

- Static gates: `mix compile --warnings-as-errors` exit 0; `mix format --check-formatted` exit 0; `mix credo --strict` exit 0 (153 files, 1892 mods/funs, 0 issues); `mix dialyzer` exit 0 (0 errors).
- Database verification unblocked without system changes: user-local PostgreSQL 16.15 (`postgresql-16 16.15-0ubuntu0.24.04.1`, apt-extracted, trust-auth) cluster at /tmp/triage_pg on 127.0.0.1:55432; owned DB `triage_test_ab_close2026` created/migrated/checked and dropped afterward; cluster stopped and /tmp/triage_pg removed.
- Closeout modules: `app/test/triage_web/live/kev_status_test.exs`, `app/test/triage_web/kev_status_components_test.exs`, `app/test/triage_web/live/cve_presentation_test.exs`, `app/test/triage/intel_cache_test.exs` — 31 passed / 0 failures.
- Full suite on the owned cluster: 785 passed / 2 skipped / 0 failed (the two skips are the pre-existing opt-in import-concurrency tests; their separate opt-in run was not part of this closeout).
- One defect found and fixed during verification: `app/test/triage_web/inventory_readability_test.exs:229` selector (`".page-header .title"` -> `".page-header h1"`) after the finding-header eyebrow dedup; module and full suite green after the fix.

Landed scope: `Intel.kev_status/0` + `<.kev_source_status>` wired into findings/queue/case/timeline (source row count + latest refresh receipt visible without a matching badge; never-refreshed / populated / empty-success / failed states distinct; cached-positive badges preserved after failed refresh; no TTL policy invented, no live fetches on browse); activity-header CVE identity qualified as current local metadata (`app/lib/triage_web/live/whats_new_live.ex`); deduped finding eyebrow (`app/lib/triage_web/live/finding_live/show.ex`); supersession notes in `CURRENT_STATUS.md`, `CHECKPOINT_REVIEW.md`, `NEXT_STEPS_PLAN.md`, `TIMELINE_SCOPE.md`, `CVE_VISIBILITY_PLAN.md`.

Agent handles: closeout-kev `16499d1bc662420e820f9c64bcd5286f`, closeout-polish `44f67cfba7ea4766ad4cce0a0891528c`, closeout-docs `db24919a52694e40af2feb2a1da0eb05`, closeout-db-readiness `70ed38a2903f40f8a688fd6a65fe3aaa` — all completed.

Deferred (separately scoped, not part of this closeout): kev=1 filter, new queue filters, global navigation CVE lookup, live collection, observation ingestion, SSO/shared deployment, automation. The documented guarded wrapper (`app/scripts/verify_owned_db.sh`) still requires `psql`; this run reproduced its owned-DB guarantees via the pinned `mix`/Postgrex path instead.
