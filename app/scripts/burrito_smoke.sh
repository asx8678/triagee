#!/bin/sh
# Invoked only by verify_owned_db.sh, after creation and identity/pristine guards.
set -eu
[ "$#" -eq 2 ] || exit 64
binary=$1; db=$2
case "$binary" in /*) ;; *) exit 64 ;; esac
case "$db" in triage_test_ab_[a-zA-Z0-9_]*) ;; *) exit 65 ;; esac
[ "$db" = "triage_test${MIX_TEST_PARTITION:?owned wrapper required}" ] || exit 65
port=${TRIAGE_OWNED_DB_PORT:?owned wrapper required}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/triage-burrito-smoke.XXXXXX")
pid=
phase=cli
cleanup() {
  status=$?
  [ "$status" -eq 0 ] || echo "Burrito smoke failed in phase: $phase" >&2
  if [ -n "$pid" ]; then
    # Burrito 1.6 uses a wrapper parent plus a BEAM child. Stop only this
    # invocation's direct child before waiting for the wrapper to reap it.
    children=$(pgrep -P "$pid" || true)
    if [ -n "$children" ]; then
      for child in $children; do kill "$child" 2>/dev/null || true; done
    else
      kill "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM
mkdir "$tmp/home"
# No Elixir executable or ambient integration/credential variables reach the binary.
plain() { env -i HOME="$tmp/home" PATH=/usr/bin:/bin TMPDIR="$tmp/" "$binary" "$@"; }
plain --help >"$tmp/help"
grep 'Usage:' "$tmp/help" >/dev/null
plain --version | grep '^Triage '
secret=$(plain secret)
[ "${#secret}" -eq 88 ]
if plain invalid-command >"$tmp/invalid" 2>&1; then exit 1; else [ "$?" -eq 64 ]; fi
if plain start >"$tmp/missing" 2>&1; then exit 1; fi
grep 'DATABASE_URL is missing' "$tmp/missing" >/dev/null
url="ecto://postgres@localhost:$port/$db"
run() {
  env -i HOME="$tmp/home" PATH=/usr/bin:/bin TMPDIR="$tmp/" \
    DATABASE_URL="$url" SECRET_KEY_BASE="$secret" PHX_HOST=localhost PORT=0 \
    TRIAGE_ACCOUNT_EMAIL=portable-smoke@example.test \
    TRIAGE_ACCOUNT_PASSWORD=synthetic-portable-smoke-only TRIAGE_ACCOUNT_ROLE=admin \
    "$binary" "$@"
}
query() { psql -X --no-password -h localhost -p "$port" -U postgres -d "$db" -v ON_ERROR_STOP=1 -Atqc "$1"; }
phase=migrations
run migrate
before=$(query 'SELECT count(*) FROM schema_migrations')
[ "$before" -gt 0 ]
run migrate
[ "$(query 'SELECT count(*) FROM schema_migrations')" = "$before" ]
phase=accounts
run account
[ "$(query "SELECT count(*) FROM account_users WHERE email = 'portable-smoke@example.test' AND role = 'admin'")" = 1 ]
if run account >"$tmp/duplicate" 2>&1; then exit 1; else [ "$?" -eq 1 ]; fi
! grep 'synthetic-portable-smoke-only' "$tmp/duplicate" >/dev/null
[ "$(query 'SELECT count(*) FROM account_users')" = 1 ]
phase=server
env -i HOME="$tmp/home" PATH=/usr/bin:/bin TMPDIR="$tmp/" \
  DATABASE_URL="$url" SECRET_KEY_BASE="$secret" PHX_HOST=localhost PORT=0 \
  "$binary" start >"$tmp/server.log" 2>&1 &
pid=$!
tries=0
while [ "$tries" -lt 60 ]; do
  kill -0 "$pid" 2>/dev/null || { cat "$tmp/server.log" >&2; exit 1; }
  http_port=$(sed -n 's/.*at 127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$tmp/server.log" | head -1)
  if [ -n "$http_port" ] && curl --fail --silent "http://127.0.0.1:$http_port/health" >"$tmp/health"; then break; fi
  tries=$((tries + 1)); sleep 1
done
[ "$tries" -lt 60 ] || { cat "$tmp/server.log" >&2; exit 1; }
grep '"status":"ok"' "$tmp/health" >/dev/null
# Catch wrappers that briefly start the endpoint, then let Elixir's CLI halt it.
sleep 2
kill -0 "$pid" 2>/dev/null || { cat "$tmp/server.log" >&2; exit 1; }
base="http://127.0.0.1:$http_port"
phase=login-form
curl --fail --silent -c "$tmp/cookies" "$base/login" >"$tmp/login"
grep -F 'name="session[email]"' "$tmp/login" >/dev/null
! grep 'Continue as local user' "$tmp/login" >/dev/null
[ "$(curl --silent -o /dev/null -w '%{http_code}' "$base/")" = 302 ]
phase=authenticated-login
csrf=$(sed -n 's/.*name="_csrf_token"[^>]*value="\([^"]*\)".*/\1/p' "$tmp/login" | head -1)
[ -n "$csrf" ]
[ "$(curl --silent -o /dev/null -w '%{http_code}' -b "$tmp/cookies" -c "$tmp/cookies" \
  --data-urlencode "_csrf_token=$csrf" \
  --data-urlencode 'session[email]=portable-smoke@example.test' \
  --data-urlencode 'session[password]=synthetic-portable-smoke-only' "$base/login")" = 302 ]
[ "$(curl --silent -b "$tmp/cookies" -o "$tmp/workspace" -w '%{http_code}' "$base/")" = 200 ]
grep 'workspace-nav-findings' "$tmp/workspace" >/dev/null
phase=assets
curl --fail --silent "$base/assets/js/app.js" >"$tmp/asset"
[ -s "$tmp/asset" ]
printf 'Burrito smoke passed: CLI, migrations, account uniqueness, readiness, auth gate and bundled assets.\n'
