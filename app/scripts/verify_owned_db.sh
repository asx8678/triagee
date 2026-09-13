#!/bin/sh
set -eu

usage() { echo "usage: $0 {target|precommit|concurrency|all}" >&2; exit 64; }
[ "$#" -eq 1 ] || usage
mode=$1
case "$mode" in target|precommit|concurrency|all) ;; *) usage ;; esac

# Refuse caller-selected execution controls before sanitizing the environment.
case "${MIX_ENV-}" in ""|test) ;; *) echo "verify-owned-db: refuse non-test MIX_ENV" >&2; exit 65;; esac
[ -z "${MIX_TEST_PARTITION+x}" ] || { echo "verify-owned-db: refuse ambient MIX_TEST_PARTITION" >&2; exit 65; }
[ -z "${TRIAGE_IMPORT_CONCURRENCY_DB+x}" ] || { echo "verify-owned-db: refuse ambient concurrency opt-in" >&2; exit 65; }

# Never inherit connection redirects, credential lookup controls, or listeners.
unset DATABASE_URL PHX_SERVER DNS_CLUSTER_QUERY
for pg_name in $(env | sed -n 's/^\(PG[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$pg_name"; done
export MIX_ENV=test PGPASSFILE=/dev/null PGSERVICEFILE=/dev/null PGCONNECT_TIMEOUT=5
export TRIAGE_BIND=127.0.0.1 PORT=0

command -v mise >/dev/null 2>&1 || { echo "verify-owned-db: mise unavailable" >&2; exit 69; }
command -v psql >/dev/null 2>&1 || { echo "verify-owned-db: psql unavailable" >&2; exit 69; }

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd); cd "$root"
nonce="$(date -u +%Y%m%d%H%M%S)_$$_${mode}"
partition="_ab_${nonce}"; db="triage_test${partition}"
case "$partition" in _ab_[a-zA-Z0-9_]*) ;; *) echo "verify-owned-db: unsafe generated partition" >&2; exit 70;; esac
case "$db" in triage_test_ab_[a-zA-Z0-9_]*) ;; *) echo "verify-owned-db: unsafe generated database" >&2; exit 70;; esac
export MIX_TEST_PARTITION="$partition"
echo "verify-owned-db: generated database=$db"

psql_admin() { psql -X --no-password -h localhost -p 5432 -U postgres -d postgres -v ON_ERROR_STOP=1 -Atqc "$1"; }
created=0
cleanup() {
  status=$?
  if [ "$created" -eq 1 ]; then
    echo "verify-owned-db: command=drop database=$db"
    if psql_admin "DROP DATABASE $db" >/dev/null; then created=0; echo "verify-owned-db: drop exit=0"
    else echo "verify-owned-db: drop exit=nonzero; cleanup failed (no FORCE or session termination attempted)" >&2; [ "$status" -ne 0 ] || status=74
    fi
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

run() {
  echo "verify-owned-db: command=$1"
  shift
  if "$@"; then echo "verify-owned-db: exit=0"; else status=$?; echo "verify-owned-db: exit=$status" >&2; return "$status"; fi
}
verify() { run "guard-$1" mise x -- mix run --no-start scripts/verify_owned_db.exs "$db" "$1"; }

# Read complete task help in the pinned toolchain before any database effect.
for task in run ecto.migrate test precommit; do
  run "help-$task" mise x -- mix help "$task"
done

present=$(psql_admin "SELECT count(*) FROM pg_database WHERE datname = '$db'")
[ "$present" = 0 ] || { echo "verify-owned-db: refuse preexisting database" >&2; exit 73; }
# Config-only: no PostgreSQL connection and no Triage application startup.
verify config
run create psql_admin "CREATE DATABASE $db"
created=1
# First connection proves identity and that the newly created DB has no user tables.
verify pristine

run_migrations() { run ecto.migrate mise x -- mix ecto.migrate; verify identity; }
run_target() {
  run_migrations
  run targeted-tests mise x -- mix test test/triage/import_test.exs test/triage/import_flow_test.exs test/triage/inventory_scope_test.exs test/triage/replay_test.exs test/triage/replay_runs_test.exs test/triage/runtime_config_test.exs
}
run_precommit() { verify identity; run precommit mise x -- mix precommit; }
run_concurrency() {
  run_migrations; verify empty
  export TRIAGE_IMPORT_CONCURRENCY_DB="$db"
  run concurrency-test mise x -- mix test test/triage/import_concurrency_test.exs
  unset TRIAGE_IMPORT_CONCURRENCY_DB
}

case "$mode" in target) run_target;; precommit) run_precommit;; concurrency) run_concurrency;; all) run_target; run_precommit; run_concurrency;; esac
echo "verify-owned-db: mode=$mode completed"
