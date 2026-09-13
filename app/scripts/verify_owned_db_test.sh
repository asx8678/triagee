#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
script="$root/scripts/verify_owned_db.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/verify-owned-db-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fail() { echo "not ok - $1" >&2; exit 1; }

mkdir "$tmp/bin"
cat >"$tmp/bin/mise" <<'EOF'
#!/bin/sh
echo "mise:$*" >>"$FAKE_LOG"
case "$*" in
  *"mix run --no-start scripts/verify_owned_db.exs"*)
    [ "${MIX_ENV-}" = test ] && [ "${TRIAGE_BIND-}" = 127.0.0.1 ] && [ "${PORT-}" = 0 ] || exit 91
    [ -z "${PHX_SERVER+x}" ] && [ -z "${DNS_CLUSTER_QUERY+x}" ] && [ -z "${DATABASE_URL+x}" ] || exit 92
    last=; for arg in "$@"; do last=$arg; done
    case "$last" in
      config) [ "${FAKE_CONFIG_FAIL:-0}" = 0 ] || exit 41;;
      pristine) [ "${FAKE_CURRENT_FAIL:-0}" = 0 ] || exit 42;;
      empty) [ "${FAKE_POPULATED:-0}" = 0 ] || exit 43;;
    esac
    ;;
esac
exit 0
EOF
cat >"$tmp/bin/psql" <<'EOF'
#!/bin/sh
echo "psql:$*" >>"$FAKE_LOG"
case "$*" in
  *"SELECT count(*) FROM pg_database"*) printf '%s\n' "${FAKE_PRESENT:-0}" ;;
  *"CREATE DATABASE"*) : ;;
  *"DROP DATABASE"*) [ "${FAKE_DROP_FAIL:-0}" = 0 ] || exit 44 ;;
esac
EOF
chmod +x "$tmp/bin/mise" "$tmp/bin/psql"
PATH_FAKE="$tmp/bin:/usr/bin:/bin"
run_case() {
  name=$1; shift
  : >"$tmp/$name.log"
  set +e
  env PATH="$PATH_FAKE" FAKE_LOG="$tmp/$name.log" "$@" >"$tmp/$name.out" 2>&1
  CASE_STATUS=$?
  set -e
}
no_effects() { ! grep -E 'CREATE DATABASE|DROP DATABASE|mix ecto.migrate|mix test|mix precommit' "$1" >/dev/null; }
db_from_out() { sed -n 's/^verify-owned-db: generated database=//p' "$1" | head -1; }

run_case bad_mode "$script" nope
[ "$CASE_STATUS" -eq 64 ] || fail "invalid mode status=$CASE_STATUS"
no_effects "$tmp/bad_mode.log" || fail "invalid mode performed effects"
run_case bad_env env MIX_ENV=dev "$script" target
[ "$CASE_STATUS" -eq 65 ] || fail "non-test MIX_ENV status=$CASE_STATUS"
no_effects "$tmp/bad_env.log" || fail "non-test MIX_ENV performed effects"
run_case partition env MIX_TEST_PARTITION=_caller "$script" target
[ "$CASE_STATUS" -eq 65 ] || fail "ambient partition status=$CASE_STATUS"
run_case optin env TRIAGE_IMPORT_CONCURRENCY_DB=caller "$script" concurrency
[ "$CASE_STATUS" -eq 65 ] || fail "ambient concurrency opt-in status=$CASE_STATUS"

run_case config env FAKE_CONFIG_FAIL=1 "$script" target
[ "$CASE_STATUS" -eq 41 ] || fail "config mismatch status=$CASE_STATUS"
no_effects "$tmp/config.log" || fail "config mismatch created/dropped or ran tasks"

run_case existing env FAKE_PRESENT=1 "$script" target
[ "$CASE_STATUS" -eq 73 ] || fail "preexisting status=$CASE_STATUS"
no_effects "$tmp/existing.log" || fail "preexisting DB path performed effects"

run_case current env FAKE_CURRENT_FAIL=1 "$script" target
[ "$CASE_STATUS" -eq 42 ] || fail "current-db mismatch status=$CASE_STATUS"
db=$(db_from_out "$tmp/current.out"); [ -n "$db" ] || fail "missing generated DB log"
grep -F "CREATE DATABASE $db" "$tmp/current.log" >/dev/null || fail "current mismatch did not create owned DB"
grep -F "DROP DATABASE $db" "$tmp/current.log" >/dev/null || fail "current mismatch did not clean exact owned DB"
[ "$(grep -c 'DROP DATABASE' "$tmp/current.log")" -eq 1 ] || fail "current mismatch dropped another DB"
! grep -E 'mix ecto.migrate|mix test|mix precommit' "$tmp/current.log" >/dev/null || fail "current mismatch ran tasks"

run_case populated env FAKE_POPULATED=1 "$script" concurrency
[ "$CASE_STATUS" -eq 43 ] || fail "populated guard status=$CASE_STATUS"
grep -F 'mix ecto.migrate' "$tmp/populated.log" >/dev/null || fail "populated scenario missed migration"
! grep -F 'import_concurrency_test.exs' "$tmp/populated.log" >/dev/null || fail "populated guard ran test"

run_case success "$script" target
[ "$CASE_STATUS" -eq 0 ] || fail "success status=$CASE_STATUS"
db=$(db_from_out "$tmp/success.out")
[ "$(grep -c "DROP DATABASE $db" "$tmp/success.log")" -eq 1 ] || fail "success did not drop exact guarded DB once"
grep -F 'import_flow_test.exs' "$tmp/success.log" >/dev/null || fail "target lacks import focus"
grep -F 'inventory_scope_test.exs' "$tmp/success.log" >/dev/null || fail "target lacks navigation focus"
grep -F 'replay_runs_test.exs' "$tmp/success.log" >/dev/null || fail "target lacks replay focus"

run_case dropfail env FAKE_DROP_FAIL=1 "$script" target
[ "$CASE_STATUS" -eq 74 ] || fail "cleanup failure status=$CASE_STATUS"
grep -F 'cleanup failed (no FORCE or session termination attempted)' "$tmp/dropfail.out" >/dev/null || fail "cleanup failure diagnostic missing"
! grep -E 'FORCE|pg_terminate_backend|dropdb' "$tmp/dropfail.log" >/dev/null || fail "cleanup used force/termination"

echo "ok - executable refusal, identity, population, target, and exact cleanup guards"
