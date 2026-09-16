#!/bin/sh
# Triage-owned local development database. Loopback-only, trust auth for the
# local postgres role, and never a substitute for another service on this host.
#
#   ./scripts/triage_dev_db.sh start    create (once) + start, prints the port
#   ./scripts/triage_dev_db.sh setup    migrate + load the real NVD catalogue
#   ./scripts/triage_dev_db.sh status   report server and catalogue state
#   ./scripts/triage_dev_db.sh env      print the TRIAGE_DB_PORT export
#   ./scripts/triage_dev_db.sh stop     stop the owned server
set -eu

cd "$(dirname "$0")/.."
mode=${1:-start}
base=${TRIAGE_OWNED_DB_DIR:-$HOME/.local/share/triage-dev-db}
data=$base/pgdata
log=$base/server.log
port_file=$base/port
pg_bin=/home/adam/.local/postgresql-16/usr/lib/postgresql/16/bin
pg_lib=/home/adam/.local/postgresql-16/usr/lib/x86_64-linux-gnu
[ -d "$pg_bin" ] || { echo "PostgreSQL binaries missing: $pg_bin" >&2; exit 69; }
export LD_LIBRARY_PATH="$pg_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="$pg_bin:$PATH"

free_port() {
  for candidate in 5433 5434 5435 5436 5437 5438 5439; do
    if ! ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$candidate\$"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

running() { [ -d "$data" ] && pg_ctl -D "$data" status >/dev/null 2>&1; }
current_port() { [ -f "$port_file" ] && cat "$port_file"; }

start_server() {
  if running; then
    echo "already running on port $(current_port)"
    return 0
  fi
  if [ ! -d "$data" ]; then
    mkdir -p "$base"
    echo "initdb: $data"
    initdb -D "$data" -U postgres -A trust --no-locale --encoding=UTF8 > "$base/initdb.log"
  fi
  port=$(free_port) || { echo "no free loopback port in 5433..5439" >&2; exit 69; }
  echo "$port" > "$port_file"
  pg_ctl -D "$data" -l "$log" -o "-p $port -c listen_addresses=localhost -c unix_socket_directories=$base" -w -t 20 start
  echo "started: port=$port data=$data"
}

setup() {
  running || { echo "not running: ./scripts/triage_dev_db.sh start" >&2; exit 69; }
  port=$(current_port)
  export MIX_ENV=dev TRIAGE_DB_PORT="$port"
  mise x -- mix ecto.create --quiet
  mise x -- mix ecto.migrate
  mise x -- mix triage.reference --preview
  mise x -- mix triage.reference --apply --database triage_dev
}

status() {
  if running; then
    echo "server: running port=$(current_port) data=$data"
  else
    echo "server: stopped data=$data"
    return 0
  fi
  port=$(current_port)
  export MIX_ENV=dev TRIAGE_DB_PORT="$port"
  mise x -- mix run -e 'IO.inspect(Triage.ReferenceData.active_counts(), label: "reference active CVE counts"); IO.inspect(Triage.Inventory.cve_summary_counts(), label: "inventory summary"); IO.inspect(Triage.Inventory.summary_counts(), label: "findings open/suppressed")'
}

case "$mode" in
  start) start_server ;;
  setup)
    start_server >/dev/null
    setup
    ;;
  status) status ;;
  env) echo "export TRIAGE_DB_PORT=$(current_port)" ;;
  stop)
    running || { echo "already stopped" >&2; exit 0; }
    pg_ctl -D "$data" -m fast -w stop
    ;;
  *) echo "usage: $0 {start|setup|status|env|stop}" >&2; exit 64 ;;
esac
