#!/bin/sh
# Fail-closed boundary probes using fake PostgreSQL tools only.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
mkdir "$work/bin"
export PROBE_LOG="$work/effects" PGHOST=127.0.0.1 PGPORT=55483 PGUSER=postgres PGDATABASE=triage_probe
unset PGSERVICE PGOPTIONS DATABASE_URL TRIAGE_RESTORE_CONFIRM
cat > "$work/bin/pg_dump" <<'EOF'
#!/bin/sh
printf 'dump\n' >> "$PROBE_LOG"
for arg in "$@"; do case "$arg" in --file=*) printf 'archive' > "${arg#--file=}";; esac; done
EOF
cat > "$work/bin/pg_restore" <<'EOF'
#!/bin/sh
case "$1" in --list) exit 0;; esac
printf 'restore\n' >> "$PROBE_LOG"
[ "${PROBE_FAIL_RESTORE-0}" = 0 ]
EOF
cat > "$work/bin/createdb" <<'EOF'
#!/bin/sh
printf 'create\n' >> "$PROBE_LOG"
[ "${PROBE_PREEXISTING-0}" = 0 ]
EOF
chmod +x "$work/bin/pg_dump" "$work/bin/pg_restore" "$work/bin/createdb"
export PATH="$work/bin:$PATH"
: > "$PROBE_LOG"
sh "$root/scripts/backup_db.sh" "$work/backup.dump" >/dev/null
[ "$(cat "$work/backup.dump")" = archive ]
if sh "$root/scripts/backup_db.sh" "$work/backup.dump" >/dev/null 2>&1; then exit 1; fi
[ "$(wc -l < "$PROBE_LOG" | tr -d ' ')" = 1 ]
if sh "$root/scripts/restore_db.sh" "$work/backup.dump" triage_restore >/dev/null 2>&1; then exit 1; fi
[ "$(wc -l < "$PROBE_LOG" | tr -d ' ')" = 1 ]
export TRIAGE_RESTORE_CONFIRM=triage_restore PROBE_PREEXISTING=1
if sh "$root/scripts/restore_db.sh" "$work/backup.dump" triage_restore >/dev/null 2>&1; then exit 1; fi
[ "$(tail -n 1 "$PROBE_LOG")" = create ]
[ "$(wc -l < "$PROBE_LOG" | tr -d ' ')" = 2 ]
export PROBE_PREEXISTING=0
sh "$root/scripts/restore_db.sh" "$work/backup.dump" triage_restore >/dev/null
[ "$(tail -n 1 "$PROBE_LOG")" = restore ]
export TRIAGE_RESTORE_CONFIRM='postgresql://secret@host/db'
if sh "$root/scripts/restore_db.sh" "$work/backup.dump" "$TRIAGE_RESTORE_CONFIRM" >/dev/null 2>&1; then exit 1; fi
[ "$(wc -l < "$PROBE_LOG" | tr -d ' ')" = 4 ]
export TRIAGE_RESTORE_CONFIRM=triage_restore PROBE_FAIL_RESTORE=1
if sh "$root/scripts/restore_db.sh" "$work/backup.dump" triage_restore >/dev/null 2>&1; then exit 1; fi
[ "$(tail -n 1 "$PROBE_LOG")" = restore ]
printf 'backup/restore safety probes passed\n'
