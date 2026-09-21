#!/bin/sh
# Restore only into a newly created database; NEVER adopts, drops, or cleans one.
set -eu
umask 077
[ "$#" -eq 2 ] || { echo "usage: $0 ARCHIVE NEW_DATABASE" >&2; exit 64; }
: "${PGHOST:?set PGHOST explicitly}" "${PGPORT:?set PGPORT explicitly}" "${PGUSER:?set PGUSER explicitly}"
archive=$1
target=$2
case "$target" in ''|*[!a-zA-Z0-9_]*|[0-9]*|postgres|template0|template1) echo 'unsafe target database name' >&2; exit 65;; esac
[ "${#target}" -le 63 ] || { echo 'target database name is too long' >&2; exit 65; }
[ "${TRIAGE_RESTORE_CONFIRM-}" = "$target" ] || { echo 'set TRIAGE_RESTORE_CONFIRM to the exact new database name' >&2; exit 65; }
[ -f "$archive" ] || { echo 'archive does not exist' >&2; exit 66; }
command -v createdb >/dev/null
command -v pg_restore >/dev/null
pg_restore --list "$archive" >/dev/null
# createdb fails if the name exists. No preflight race, --clean, or force-drop.
createdb --no-password --maintenance-db=postgres --template=template0 "$target"
if pg_restore --no-password --exit-on-error --single-transaction --no-owner --no-privileges --dbname="$target" "$archive"; then
  echo 'Restore completed into a new database. Validate it before changing application configuration.'
else
  echo 'Restore failed; the newly created database is retained for inspection. No existing database was overwritten.' >&2
  exit 74
fi
