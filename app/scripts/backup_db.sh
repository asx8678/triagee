#!/bin/sh
# Uses standard PGHOST/PGPORT/PGUSER/PGDATABASE and a protected PGPASSFILE.
# Credentials are never passed as command arguments or printed.
set -eu
umask 077
[ "$#" -eq 1 ] || { echo "usage: $0 NEW_ARCHIVE_PATH" >&2; exit 64; }
: "${PGHOST:?set PGHOST explicitly}" "${PGPORT:?set PGPORT explicitly}" "${PGUSER:?set PGUSER explicitly}" "${PGDATABASE:?set PGDATABASE explicitly}"
case "$PGDATABASE" in ''|*[!a-zA-Z0-9_]*|[0-9]*) echo 'PGDATABASE must be a simple database name, not a connection string' >&2; exit 65;; esac
[ ! -e "$1" ] && [ ! -L "$1" ] || { echo 'refusing to overwrite an archive' >&2; exit 73; }
command -v pg_dump >/dev/null
command -v pg_restore >/dev/null
archive=$1
partial=$(mktemp "${archive}.partial.XXXXXX")
trap 'rm -f -- "$partial"' EXIT HUP INT TERM
pg_dump --no-password --format=custom --file="$partial"
pg_restore --list "$partial" >/dev/null
# Hard link is atomic and refuses a concurrent creator, unlike overwriting mv.
ln "$partial" "$archive"
echo 'Backup completed; rehearse restoration and store an encrypted off-host copy.'
