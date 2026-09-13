# A+B execution ledger

Date: 2026-09-12. Scope: **A+B only, implemented and freshly integration-tested**.
**Fresh independent final-tree Astra review: PASS, no blocking defect.** This is not full-roadmap, production
deployment, real-data compatibility, historical-baseline recovery, or checkpoint-commit completion.
HEAD: `dc4843141b94aa8f9a040eec6aa0ea61978784cc`; `app/` remains untracked.

## Orchestration and ownership

Three concurrent exact `openai-codex/gpt-5.6-sol`, thinking **low**, nonrecursive
leaves were launched after `evidence/a_b/OWNERSHIP.md` froze disjoint ownership:
A docs (`fd75b029…`), B runtime (`5e742374…`), B scripts (`80a5fa3f…`). All completed
exit 0. Two disjoint bounded Sol repairs (`7c077185…`, `ce655e03…`) followed the first
integration audit. A final bounded Sol production IPv6 repair (`4ccc5146…`) extended
ownership explicitly to `app/config/prod.exs`; all writers were awaited before
runtime/DB integration. The coordinator then added Bandit's bracketed IPv6 Host
literal after a real listener probe falsified the unbracketed-only repair.
No silent model substitution, recursion, worktree, .pi configuration edit, reset,
stash, checkout, git add/commit/push, process interruption, or deferred handoff.
Fresh independent reviewer `e981380f87e14317b2824a13c9b9fb69` ran exact
`openai-codex/gpt-6-astra`, high, nonrecursive after all code writers/integration
completed; status completed, exit 0. Report: `evidence/a_b/ASTRA_REVIEW.md`.

## Changes

- `.gitignore`: reviewed secret/export/harness-journal exclusions; tracked harness
  changes remain visible. `app/.gitignore` reviewed and unchanged.
- `CURRENT_STATUS.md`, `CHECKPOINT_REVIEW.md`, `NEXT_STEPS_PLAN.md`, this ledger:
  authoritative bounded status and explicit prospective checkpoint coverage/gates.
- `app/config/runtime.exs`: default numeric IPv4 loopback; only exact `127.0.0.1`
  and `::1` accepted as `TRIAGE_BIND`; unsigned decimal `PORT` in 0..65535,
  test default 4002 and dev/prod 4000; absent/empty production DB URL/key rejected.
  `PHX_HOST` is URL generation only; no public-bind/auth escape.
- `app/config/dev.exs`, `test.exs`: explicit documented local defaults.
- `app/config/prod.exs`: necessary B-only local IPv6 HTTP usability fix, excluding
  `::1` and Bandit's `[::1]` Host form from the existing HTTPS redirect. Other TLS
  semantics remain unchanged. Public URL default remains example.com.
- `app/test/triage/runtime_config_test.exs`: 9 standalone subprocess config/raw
  listener tests, also discovered by the full suite. No Repo in standalone mode.
- `app/LOCAL_RUNTIME.md`; `app/scripts/verify_owned_db.{sh,exs}`,
  `verify_owned_db_test.sh`; `app/OWNED_DB_VERIFICATION.md`: deterministic guarded
  disposable testing, executable refusal tests, explicit modes and cleanup.
- Precommit also reformatted only SQL argument whitespace in
  `app/lib/triage/import_flow.ex` and `app/test/triage/replay_runs_test.exs`.
  Exact pre-execution SHA originals reconstructed and validated; metadata-free ASTs
  equal. Retained diff: `evidence/a_b/reviewed-source.diff`. No semantic changes.
- No schema, dependency, lockfile, Collection, router/auth, or inventory contract
  changes. Collection remains offline/test-only. Existing migrations only ran on
  verifier-owned absent-before disposable DBs.

## Acceptance ledger (fresh unless marked inherited)

| Check | Result / evidence |
|---|---|
| A prospective source inventory/exclusions/ignore review | PASS; CHECKPOINT_REVIEW + final inventory. No staging permitted. |
| A authoritative current status + retained historical failures | PASS; CURRENT_STATUS links old records without rewriting them. |
| A missing old baseline stays unresolved | PASS (unresolved gap retained; fresh baseline is new). |
| A staged diff / checkpoint commit | NOT DONE, intentionally gated; prospective review is not staged approval. |
| B config default/dev/test/prod, missing+empty secrets, invalid bind/port | PASS; final 9-test matrix covered in full precommit and standalone Sol check. |
| B actual listener address and owned cleanup | PASS; test IPv4/IPv6 + fresh isolated production build IPv4/IPv6, PORT=0. |
| B navigation/import/replay | PASS within synthetic test coverage: 89 targeted and full suite incl LiveView/navigation tests. No fresh browser run. |
| B full precommit | PASS: exactly one full alias, 484 passed / 2 skipped, exit 0. |
| B dedicated import concurrency | PASS: 2 passed, exit 0; separate DB, exact internal TRIAGE_IMPORT_CONCURRENCY_DB opt-in after empty guard. |
| B guard adversarial refusals | PASS fake-command execution: invalid mode/env/ambient partition/opt-in, config mismatch, preexisting/unowned, current DB mismatch, populated, exact cleanup and failed-drop behavior. Real happy-path identity/pristine/empty guards also executed. |
| B no shared/dev effects or existing process interruption | PASS within execution/protection evidence; no shared/dev DB reads were used to make stronger row-hash claims. |
| Source/lock/assets preservation | PASS: initial protected source unchanged except four configs and two AST-equal formatter edits; mix.lock and vendor bytes unchanged. |
| Fresh independent Astra review | PASS; 9 runtime tests, 10 shell scenarios, 31 actual-helper simulations, production IPv4/IPv6 listeners + 4 HTTP responses + 2 closed-port probes, 142 unchanged candidate hashes, cleanup/protection checks. See evidence/a_b/ASTRA_REVIEW.md for exact commands, exits and limits. |

## Commands, failures, and results

Pinned toolchain: `mise exec -- …` from `app/` (Erlang 27.3.4.16, Elixir
1.20.4-otp-27); PostgreSQL CLI PATH `/opt/homebrew/opt/postgresql@18/bin`.
Read complete `mix help run`, `ecto.migrate`, `test`, `precommit` before effects;
format help before scoped formatting. DB wrapper re-reads help for reproducibility.

1. Default-PATH `elixir` unavailable (Sol exit 127); installed mise resolved it,
   no install/network. Coordinator initial standalone runtime suite: exit 2,
   5/8 passed. Fixed empty-env subprocess handling and unsafe whole-config term
   decoding; repaired suite 8/8 exit 0. Added production SSL test: 9/9 exit 0.
2. `sh app/scripts/verify_owned_db_test.sh`: exit 0; durable `guard-tests.log`.
   Initial script audit found ambient listener/DB guard gaps; repaired before DB use.
3. `MIX_ENV=test sh app/scripts/verify_owned_db.sh target`: exit 0, **89 passed**.
   `evidence/a_b/target.log` includes configured/current DB checks before effects,
   existing migrations, test result, and successful owned drop.
4. `MIX_ENV=test MIX_TEST_PARTITION=_ab_listener_10405 PORT=0 TRIAGE_BIND=127.0.0.1
   mise exec -- mix run --no-start ../evidence/a_b/listener_probe.exs`: initial
   test Endpoint IPv4/IPv6 static HTTP 200 probes + closed listeners, exit 0.
5. Production: unique `mktemp -d /tmp/triage-ab-prod-build.XXXXXX`,
   `MIX_BUILD_PATH=<owned>` + `MIX_ENV=prod`, explicit `_ab_prodprobe_10405`
   partition, `PORT=0`, synthetic DATABASE_URL/key; no Repo started. Run same
   `mix run --no-start` probe, then remove only owned build via trap.
   Initial static expectation failed (404 in isolated build); switched probe to
   deliberate DB-free absent route with expected 404, not a static-release signoff.
   IPv6 then revealed HTTPS 301 redirect; unbracketed-only repair still failed.
   Bandit source/actual probe established bracketed Host; final `listener-prod-pass.log`
   exits **0**, both listener addresses and HTTP 404 responses verified, Repo absent,
   both closed afterward. Prior failing logs retained. Existing production-only
   unused offline-transport function/dependency warnings retained, not broadened fixes.
6. `MIX_ENV=test sh app/scripts/verify_owned_db.sh precommit`: **exit 0, 484 passed,
   2 skipped** (`precommit.log`). The skipped cases are the intentionally unset
   concurrency opt-in. Existing compile-time nil-opt-in test warning retained.
   Formatting/lock/assets inspected: two whitespace-only changes; lock/vendor equal.
7. `MIX_ENV=test sh app/scripts/verify_owned_db.sh concurrency`: **exit 0, 2 passed**
   (`concurrency.log`), new pristine DB, all nine application tables empty first.
8. Formatter audit: initial source-root invocation exit 1, fixed explicit path;
   bounded whitespace candidates initially unresolved. Final exact SHA reconstruction
   and equal metadata-free AST checks passed for both files (`format-audit.log`).
   This recovers only this execution's pre-format bytes, NOT missing historical proof.
9. Cleanup catalog queries: exit 0, all three exact owned names have 0 databases
   and 0 connections (`cleanup-db.log`). All four owned production build dirs absent;
   initial/final user-port lsof files equal; index empty; inherited roadmap diff equal.

## Ownership and preservation limits

The wrapper derives a unique `_ab_<UTC timestamp>_<PID>_<mode>` partition, refuses
caller-selected partition/concurrency and non-test environment, scrubs DB redirects,
sets credential/service files to `/dev/null`, checks catalog absence before CREATE,
checks configured Repo/localhost/postgres/5432/name before CREATE, then actual
`current_database()` and pristine user-table state before migrations/test aliases.
It drops only after this invocation's successful CREATE, never FORCE/terminate.
Names and successful absent cleanup are in `evidence/a_b/owned-databases.txt`:

- `triage_test_ab_20260912110640_18781_target`
- `triage_test_ab_20260912111141_25807_precommit`
- `triage_test_ab_20260912111212_26651_concurrency`

No credential-file reads/copies, raw DBs, legacy DB reads, live APIs, shared/dev
writes/migrations/resets, or existing process stops. Logs use only synthetic data,
controlled errors, help/source SQL and safe generated identities. Dev/test framework
signing literals are public synthetic source, not production credentials.

Initial hashing covered 116 sanitized app source files; the absent `app/assets`
caused the shell group to omit subsequent app-root/root inventory commands. An
11-file static-source supplement and later 142-file precommit manifest cover those
additional execution phases, but must not be mislabeled initial whole-tree hashes.
Four configs were backed up with matching initial SHA; mix.lock's precommit bytes
were captured later (not worker-owned). Inherited roadmap diff was captured at
preflight and still matches; root ignore diff is reviewed against HEAD. Harness,
dependency/build/crash, credential and DB contents were deliberately not hashed/read;
no stronger whole-machine or shared-DB row-preservation claim is made. Harness
state files may naturally change through supported agents; no .pi configuration was
edited by this execution. Baseline limitations do not authorize resets or replacement.

`evidence/a_b/` contains durable sanitized commands/logs/manifests/probes/diffs.
Before/snapshot directories are review-only and excluded from prospective checkpoint
until separately approved. The exact final prospective list remains unstaged.

## Independent closeout (fresh, after integration)

Exact Astra high/nonrecursive review completed with no application blocker. It ran
9 standalone runtime tests; 10 executable shell-guard scenarios; 31 no-network
simulations executing the unchanged actual Elixir DB helper (26 refusals, 5 success
cases); an independent isolated production build with actual IPv4/IPv6 Endpoint
listeners, local HTTP404 and public-Host HTTPS301 responses (not followed), and
closed-port checks. All final checks exited 0. It independently proved all 142
candidate hashes unchanged, 110/116 initial files byte-equal (only four configs +
two AST-equal formatter files differ), 11 static/3 vendor files unchanged, exact
147-path prospective inventory coverage, inherited roadmap/index preservation,
and all three owned DB catalog/connection counts zero.

Reviewer build `/tmp/triage-ab-astra-v317-prod.XruA8I` and all four coordinator
builds are absent. Existing user listener PID 7847 on 4000 was left untouched;
4001 remained unused. **Only owned app/listener instances were stopped**; no claim
that the user's preexisting service was stopped. Reviewer-only quote/preflight/stub
harness failures were repaired in reviewer evidence and disclosed in its report,
not hidden or counted as application defects. Helper simulation is source-control-
flow evidence, not real PostgreSQL race/failure integration; real DB happy paths
remain coordinator evidence, and historical browser evidence remains inherited.

After review, only root status/ledger and evidence-inventory closeout were updated;
no application source/config/test changed and candidate hashes still match.

## Remaining gates

C requires approved historical export/provenance/environment mapping; D requires
approved endpoint/auth/budget/security contract; E requires SSO/authorization and
shared deployment contract; F observation ingestion is separately designed/approved.
None was implemented or accessed. Original historical baseline remains unavailable.
Checkpoint staged-diff/approval/commit and any production packaging/deployment remain
pending, regardless of this bounded A+B result.
