# Independent Astra final-tree review — A+B

**PASS, bounded A+B verification. No blocking application defect found.**
Date: 2026-09-12. Exact exposed harness identity: `PI_PROVIDER=openai-codex`,
`PI_MODEL=gpt-6-astra`, `PI_REASONING_LEVEL=high`. Fresh, independent, nonrecursive;
no agents/delegation or model substitution. Identity is verified from harness
metadata, not independent provider attestation.

HEAD remains `dc4843141b94aa8f9a040eec6aa0ea61978784cc`; app remains untracked,
index empty. This is **not** checkpoint commit/staged-diff approval, production
deployment, historical-baseline recovery, or C–F approval.

## Independent acceptance ledger

Evidence below uses prefix `evidence/a_b/astra-20260912-v317-` (abbreviated `P`).
The prefix and report were absent before this review. Only this report and
prefixed sanitized evidence/probes were durably written.

| Check actually executed by reviewer | Result / exit / evidence |
|---|---|
| Candidate before/after hashes | **142/142 PASS**, exit 0; `Pbefore.log`, `Pfinal-hashes.log`. Candidate manifest itself unchanged. |
| Standalone final runtime suite | **9 passed**, exit 0, seed 173913; `Pruntime.log`. No test helper, Mix application, or Repo startup. |
| Shell syntax and actual wrapper with fake commands | **10 scenarios PASS**, exit 0; `Pshell-guards.log`. Expected statuses: 64,65,65,65,41,73,42,43,0,74. |
| Actual unchanged Elixir DB helper with no-network doubles | **31 scenarios PASS** (26 expected refusals, 5 successful cases), final exit 0; `Phelper-final.log`, reproducible `Phelper.exs`. |
| Complete Mix help before compilation/listening | `mix help run` and `mix help compile`, both exit 0; `Phelp-run.log`, `Phelp-compile.log`, read before effect. |
| Isolated production build + actual Endpoint-only loopback probes | **2 listeners / 4 HTTP responses / 2 closed-port checks PASS**, exit 0; `Pprod-listener.log`, `Plistener.exs`. IPv4 `127.0.0.1:51719`, IPv6 `[::1]:51722`; both requested PORT=0. |
| Production SSL behavior | Local Host HTTP404 on deliberately absent DB-free route for both families; public Host HTTP301 with HTTPS Location for both, redirects not followed. |
| Application protection | Probe checks `:triage` absent from started applications and `Triage.Supervisor`/Repo absent, before/during/after probes. Only owned PubSub/Endpoint supervisor stopped. |
| Initial/later source phases, formatter ASTs and inventory | Exit 0; `Ppreservation.log`, `Ppreservation.exs`; detailed counts below. |
| Authorized admin catalog counts | **3 exact owned names each 0 databases / 0 connections**, exit 0; `Pcatalog.log`. No reviewer DB created or accessed. |
| Build/ports/index/roadmap/root protection | PASS, final composite exit 0; `Pfinal-protection.log`. Four coordinator builds and one reviewer build absent; all port snapshots identical; index empty; inherited roadmap diff identical. |

Read the required plans, status, ownership, candidate manifest, both local runtime
and DB verification guides; traced runtime/environment configs, standalone tests,
Mix aliases, application/Endpoint startup, listener probe, wrapper/helper/tests,
concurrency guard, nine migration table declarations, inventory/ignore rules, and
the two formatter-only source regions. Structural navigation's legacy-collector
suggestions were not followed: C–F and legacy data stayed out of scope.

## Exact independent executions

From repository root, unless stated otherwise:

```sh
cd app && MIX_ENV=test MIX_TEST_PARTITION=_ab_astra_20260912_v317 \
  mise exec -- elixir test/triage/runtime_config_test.exs

# From repository root:
sh -n app/scripts/verify_owned_db.sh app/scripts/verify_owned_db_test.sh
env -u MIX_TEST_PARTITION -u TRIAGE_IMPORT_CONCURRENCY_DB MIX_ENV=test \
  sh app/scripts/verify_owned_db_test.sh

cd app && MIX_ENV=test MIX_TEST_PARTITION=_ab_astra_20260912_v317 \
  mise exec -- elixir ../evidence/a_b/astra-20260912-v317-helper.exs
cd app && MIX_ENV=test MIX_TEST_PARTITION=_ab_astra_20260912_v317 \
  mise exec -- elixir ../evidence/a_b/astra-20260912-v317-preservation.exs
```

The two latter commands each start from root independently. Output was redirected
to the corresponding evidence logs and returned exit status inspected. No full
precommit, database test suite, migrations, assets setup, dependency fetch/unlock,
or Triage application startup was run by this reviewer.

Production exception, DB-FREE only: allocated with
`mktemp -d /tmp/triage-ab-astra-v317-prod.XXXXXX`, yielding
`/tmp/triage-ab-astra-v317-prod.XruA8I`, recorded in `Pbuild.txt`.
Both help commands and the listener execution used this environment from `app/`:

```sh
unset PHX_SERVER DNS_CLUSTER_QUERY ECTO_IPV6 POOL_SIZE \
  HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
export MIX_ENV=prod MIX_TEST_PARTITION=_ab_astra_20260912_v317
export MIX_BUILD_PATH=/tmp/triage-ab-astra-v317-prod.XruA8I
export PORT=0 TRIAGE_BIND=127.0.0.1 HEX_OFFLINE=1 PHX_HOST=example.invalid
export DATABASE_URL=ecto://localhost/triage_astra_db_never_opened
export SECRET_KEY_BASE=astra_synthetic_00000000000000000000000000000000000000000000000000
mise exec -- mix help run
mise exec -- mix help compile
# Complete help read before this command:
mise exec -- mix run --no-start --no-listeners \
  ../evidence/a_b/astra-20260912-v317-listener.exs
```

The synthetic DB URL/key are deliberately non-secret; no DB driver/Repo is started
by this probe. The probe reloads actual final runtime config with unset bind for
IPv4 default, then `::1`; it merges real production endpoint config and explicitly
enables only its owned Endpoint. It asserts actual `server_info(:http)` addresses,
rejects selected ports 4000/4001, disables Req retry/redirect, bounds HTTP receive
at 5 seconds and closed-port connect at 1 second. It asserts local 404 rather than
claiming static asset/release packaging correctness. An EXIT trap removed only
the exact reviewer-owned build. No existing process was stopped.

Only this SQL was sent to PostgreSQL, after checking the three names exactly equal
`owned-databases.txt`:

```sh
env -i PATH=/opt/homebrew/opt/postgresql@18/bin:/usr/bin:/bin \
  PGPASSFILE=/dev/null PGSERVICEFILE=/dev/null \
  psql -X --no-password -h localhost -p5432 -U postgres -d postgres \
  -v ON_ERROR_STOP=1 -Atqc "SELECT wanted.name,
    (SELECT count(*) FROM pg_database WHERE datname = wanted.name),
    (SELECT count(*) FROM pg_stat_activity WHERE datname = wanted.name)
  FROM (VALUES
    ('triage_test_ab_20260912110640_18781_target'),
    ('triage_test_ab_20260912111141_25807_precommit'),
    ('triage_test_ab_20260912111212_26651_concurrency')) AS wanted(name)"
```

All three returned `|0|0`; awk asserted exactly three zero-count rows. psql emitted
only its benign `/dev/null` password-file-not-plain-file warning in addition.
No connection was made to any named test DB, shared/dev DB, or legacy DB.

Preservation commands included:

```sh
shasum -a 256 -c evidence/a_b/candidate-app.sha256  # before and after
shasum -a 256 -c evidence/a_b/astra-20260912-v317-protected.sha256
git diff --cached --exit-code
git diff --cached --name-only
git diff -- IMPLEMENTATION_ROADMAP.md             # own before/final captures
/usr/sbin/lsof -nP -iTCP:4000 -iTCP:4001 -sTCP:LISTEN
```

`cmp` verified reviewer before/final roadmap captures against
`evidence/a_b/inherited-roadmap.diff`; reviewer port files against each other and
coordinator initial/final port files. All comparisons exited 0. `test ! -e` passed
for all exact paths in `owned-prod-build.txt` and `Pbuild.txt`. Wrapper/test
executable bits were independently checked.

## Actual guard audit and simulation limits

The shell tests invoke the real wrapper, but fake `mise` assigns failure codes
without evaluating Elixir and fake `psql` does not execute SQL. Consequently their
PASS alone cannot establish actual Repo configuration, SQL, table population,
connection cleanup, PG environment handling, or real DB lifecycle safety.

The additional reviewer harness executes **unmodified**
`app/scripts/verify_owned_db.exs` using actual Mix env, System argv, application
configuration and its own source logic, with an in-memory `Triage.Repo.config/0`
and Postgrex double. It loads a synthetic OTP Postgrex application spec, not the
real driver; there is no socket/network implementation. It covers:

- Wrong DB, host, user, port, URL/socket/socket_dir overrides; wrong Mix env,
  absent/wrong partition, wrong repo registry, unsafe expected name, invalid mode.
- Valid config with default and explicit 5432; valid identity, pristine, empty.
- Actual/current DB mismatch in identity, pristine, and empty modes: only the
  identity query runs, with no subsequent table query.
- Nonpristine user tables and **each of all nine populated application tables**,
  including `replay_runs`; refusal stops at the first populated table.
- Exact first statement `SELECT current_database()`, bounded query counts,
  connection-option projection and stopped stub connection on all 16 connected
  success/refusal paths. Config-only paths perform zero queries/connections.

Static audit confirms wrapper refuses caller partition/opt-in/non-test env,
scrubs PG variables and startup/DB redirects, forces localhost/postgres/5432 and
credential/service files `/dev/null`, checks absence before CREATE and actual
identity/pristine tables before migrations/tests, and drops only after its own
successful CREATE. No FORCE/session termination path exists. The nine empty-check
tables match current migration declarations; the guard is stronger than the older
concurrency test's eight-table list by also checking replay receipts.

Limits: simulated query rows are not a PostgreSQL integration test, syntax/parser
proof, failure-under-real-sessions proof, or atomic race/hostile-template defense.
Pristine means no user **tables** according to the explicit pg_tables query, not
absence of every possible PostgreSQL object. The wrapper's real happy paths remain
coordinator evidence. No new blocker was found within this local-owned contract.

## Preservation findings and evidence boundaries

The independent read-only preservation probe established:

- **116 initial files: 110 unchanged**; exactly four configs and two formatter
  files differ. Collection, schema/migrations, router/auth and other included
  application sources are byte-preserved.
- **142 later precommit files:** only `app/lib/triage/import_flow.ex` and
  `app/test/triage/replay_runs_test.exs` differ. Their stored originals match exact
  initial SHA256 and independently normalized metadata-free ASTs equal current
  source. This is evidence of the reported formatter-only changes, not historical
  baseline recovery.
- **11 initial static files and 3 precommit vendor files unchanged.**
  `mix.exs`/`mix.lock` match the later precommit manifest; lock also matches the
  stored before copy. No dependency/schema/Collection/auth change introduced by
  review. Dependency/build trees themselves were intentionally not inventoried or
  claimed byte-identical; compilation used installed dependencies offline.
- **147 prospective paths = exactly 142 current nonignored app paths + 5 root
  files**. No .pi, dependencies/build/editor/fetch output, generated vendor,
  credential/DB extensions, legacy collector or inherited roadmap in that list.
  Public runtime keys, standalone ExUnit module and all verification/docs paths
  are present. This is prospective coverage only, not staged secret scanning.
- `.gitignore`, required root docs and candidate manifest match reviewer baseline;
  inherited roadmap diff unchanged. No app/source/docs were edited by reviewer.
- Existing IPv4 listener PID **7847** on 4000 is byte-identical in all snapshots;
  4001 has no listener. Owned production listeners explicitly refused connections
  after shutdown. All five recorded production build paths are absent.

The initial 116-file inventory omitted app-root entries due to its known absent
assets-directory/grouping bug. The 11-file supplement and later 142-file manifest
are distinct phases, **not** an initial whole-tree manifest. No credential-file,
raw/legacy DB, shared DB row, dependency-tree, whole-machine or historical-tree
preservation claim is made. No live APIs, credentials, shared/dev DB effects,
migrations, Git staging/commit/reset/stash/checkout/push, worktrees or .pi config
edits were performed. Existing harness state modifications remain inherited and
may naturally evolve through supported tooling.

## Failures, severity and retained warnings

**Application defects: none reproduced; no blocking repair requested.**

Verifier-only failures were inspected rather than concealed:

1. Initial orchestration string quoting failed before any command executed.
2. Initial composite preflight stopped with exit 1 at lsof's multi-port status
   because 4001 had no listener. Its captured output correctly showed PID 7847 on
   4000; separate `cmp` checks passed. Final check records this expected lsof exit
   separately instead of treating it as candidate failure.
3. First helper harness run exited 1 before evaluation: `Application.load/1`
   accepts an atom, not an application-spec tuple. Fixed only the reviewer probe
   to `:application.load/1`; original `Phelper.log` preserved. Final 31-case run
   exited 0. No application source repair was involved.

Informational/nonblocking coverage limitation: shipped shell guards are fakes,
not independent real-helper failure tests; the reviewer harness above closes the
source-control-flow gap for this review but intentionally not real DB behavior.
An optional future authorized test change could retain equivalent no-network helper
cases; it is not a prerequisite repair or deferred verification handoff.

Isolated production compilation emitted inherited dependency warnings and unused
functions in unchanged `Triage.Collection.Transport.Req`. They are retained in
`Pprod-listener.log`, not silently fixed, hidden, or characterized as a clean
warnings-as-errors production deployment build.

## Own versus coordinator versus historical evidence

This review's fresh results are **9 runtime + 10 shell scenarios + 31 helper
simulations + actual production listener/HTTP/cleanup and preservation/catalog
probes**, as above. Counts are different check types, not one combined ExUnit suite.

Coordinator's **89 targeted**, **exactly one full precommit 484 passed / 2 skipped**,
and **separate opt-in concurrency 2 passed**, their three owned DB lifecycles,
initial runtime/HTTP failures and repairs are retained coordinator evidence; they
were **not rerun or relabeled as this review's results**. Earlier PR/UI/browser
counts and missing historical-baseline proof remain inherited/unresolved.

**Final disposition: PASS for the bounded final A+B candidate.** Checkpoint
staging/approval/commit remains pending by policy; C–F, production deployment,
real-data compatibility, credentials/live access and shared auth remain gated.
All authorized independent verification is complete; no deferred handoff.
