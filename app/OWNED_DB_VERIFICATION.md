# Owned disposable database verification

`./scripts/verify_owned_db.sh` is a coordinator-run, fail-closed wrapper for database-backed verification. **Workers must not run it.** It uses the pinned `mise` toolchain plus `psql` from the caller's `PATH` (for example `/opt/homebrew/opt/postgresql@18/bin`) and a local passwordless PostgreSQL server.

## Coordinator procedure

Before any mutating run, read the complete task help:

```sh
mise x -- mix help run
mise x -- mix help ecto.migrate
mise x -- mix help test
mise x -- mix help precommit
./scripts/verify_owned_db_test.sh
```

Then run modes separately as needed:

```sh
./scripts/verify_owned_db.sh target
./scripts/verify_owned_db.sh suite     # full suite without automatic formatting
./scripts/verify_owned_db.sh ci        # full suite plus strict static checks
./scripts/verify_owned_db.sh precommit
./scripts/verify_owned_db.sh concurrency
# or all three phases on one disposable database
./scripts/verify_owned_db.sh all
```

The wrapper targets passwordless loopback PostgreSQL on the standard port 5432 by default. When that port already belongs to a pre-existing server that must not be touched, export `TRIAGE_OWNED_DB_PORT` (decimal, 1024..65535) to point at an owned cluster elsewhere. The value is validated **before any database effect**; an empty, non-decimal or out-of-range value is rejected with exit 65 and no effects. The wrapper passes the validated port to every `psql` connection and exports it for the test configuration; `config/test.exs` honors it only alongside the guard's generated `_ab_` partition with the same range validation and fails closed otherwise, and `scripts/verify_owned_db.exs` re-checks the configured port against the validated value. Dev/prod configuration never reads this variable.

`focused test/FILE.exs ...` runs explicit in-repository test files and rejects flags/traversal; `suite` runs all ExUnit tests without rewriting source; `ci` runs all non-mutating quality gates and the full suite. `target` covers runtime configuration plus focused import, navigation/scope, and replay tests. `precommit` runs the full alias once. `concurrency` alone sets the exact internal `TRIAGE_IMPORT_CONCURRENCY_DB` opt-in and runs the import concurrency test; do not report ordinary target/precommit evidence as concurrency evidence.

## Fail-closed guards

The wrapper rejects a caller-supplied non-test `MIX_ENV`, any ambient `MIX_TEST_PARTITION`, and any ambient `TRIAGE_IMPORT_CONCURRENCY_DB`. It generates its own safe `_ab_...` partition and exact `triage_test_ab_...` database and logs that non-secret name. It unsets `DATABASE_URL`, every ambient `PG*` variable, `PHX_SERVER`, and `DNS_CLUSTER_QUERY`; then it uses disabled credential/service files, loopback PostgreSQL, `TRIAGE_BIND=127.0.0.1`, and `PORT=0`.

Before `CREATE DATABASE`, the no-connection config probe uses supported argv syntax:

```sh
mise x -- mix run --no-start scripts/verify_owned_db.exs DATABASE config
```

It requires `Mix.env() == :test`, `Application.get_env(:triage, :ecto_repos) == [Triage.Repo]`, the generated database, hostname `localhost`, username `postgres`, the validated owned port (default 5432), and no URL/socket override. No Triage application is started. After creation, the verifier starts Postgrex and its dependencies only. Its first SQL statement is `SELECT current_database()`; it then requires the fresh database to contain no user tables before any migration or test.

Before concurrency, a later guard checks every application table from the migrations is empty: inventory/finding tables, all review case/evidence/review/event tables, and `replay_runs`.

A preexisting generated name is never adopted. Cleanup drops only the exact database created by that invocation. It never uses `FORCE`, terminates sessions, or invokes `dropdb`; a failed drop is reported and turns an otherwise successful run into exit 74. Commands and exit outcomes are logged without URLs, environment values, SQL rows, or credentials.

Exit 64 means invalid mode, 65 rejected ambient execution control or an invalid `TRIAGE_OWNED_DB_PORT`, 69 missing tools, 70 unsafe generated identity, 73 preexisting database, and 74 cleanup failure. Other Mix/psql failures preserve their nonzero status.

## Tested boundary

`scripts/verify_owned_db_test.sh` uses fake `mise` and `psql` commands only. It executes invalid mode/environment paths, ambient partition/concurrency rejection, config mismatch with no create/drop, preexisting refusal with no effects, current-database mismatch with exact owned cleanup, populated-table rejection before concurrency tests, successful exact cleanup, focused target selection, and failed cleanup without force. It does not validate a real PostgreSQL connection, migrations, application tests, listener behavior, or cleanup under real sessions; the coordinator performs those integrations later. Listener ownership extensions belong in a separate coordinator-approved script/probe.
