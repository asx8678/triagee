# Shared deployment and disaster recovery

This chapter covers a VPS with systemd. For a self-contained cluster
deployment (application, in-pod reverse proxy, and PostgreSQL inside
Kubernetes), see [KUBERNETES](KUBERNETES.md).

## Status and prerequisites

Local tests and a macOS release rehearsal are **not VPS certification**. Build the
release on the same Linux distribution, CPU architecture and ABI as the VPS (or
on the VPS itself). Never upload a macOS `_build/prod/rel` to Linux. Confirm the
server/domain, SSH identity, database ownership and maintenance window before any
production effect. No production host or access was provided for this change.

Use a dedicated unprivileged `triage` service account, PostgreSQL 18 on a private
interface, a non-superuser application DB role, and Caddy or an equivalent TLS
reverse proxy. Only SSH (restricted), 80 and 443 should be externally reachable.
Phoenix remains bound to `127.0.0.1:4000`; do not expose PostgreSQL or Erlang
ports. Authentication must remain enabled, including during colleague testing.
Roles are application-wide: viewer reads, reviewer performs ordinary review
work, admin manages accounts and privileged work. Confirm the exact policy in
the account authorization module before assigning roles; team filters are not
row-level tenancy.

## Build and install

From `app/`, using the versions pinned in CI (Elixir 1.20.4, OTP 27.3.4.17):

```sh
mise x -- mix deps.get --only prod
MIX_ENV=prod mise x -- mix compile --warnings-as-errors
MIX_ENV=prod mise x -- mix assets.setup
MIX_ENV=prod mise x -- mix release
```

Use immutable versioned release directories under `/opt/triage/releases/` and a
`/opt/triage/current` symlink. Keep the previous release for rollback. Store no
credentials in release artifacts or Git. Use `deploy/triage.env.example` as a
checklist, not as working credentials; install the populated environment file
outside the checkout with mode 0600 and ownership appropriate for systemd.
Generate `SECRET_KEY_BASE` with `mise x -- mix phx.gen.secret`. URL-encode DB
passwords in `DATABASE_URL`. Use a least-privilege Azure PAT only after explicit
integration validation; leave all `ADO_*` unset during the first rehearsal.

After loading the approved environment securely, take a backup, stop the app,
and run additive migrations under the designated migration role:

```sh
/opt/triage/current/bin/triage eval 'Triage.Release.migrate()'
```

Provision each account explicitly. There is no public signup or default user.
Supply `TRIAGE_ACCOUNT_EMAIL`, `TRIAGE_ACCOUNT_PASSWORD` and
`TRIAGE_ACCOUNT_ROLE` via a protected environment, **not CLI arguments or shell
history**. A password must contain at least 12 bytes. Then:

```sh
/opt/triage/current/bin/triage eval 'Triage.Accounts.bootstrap!()'
# From source: mise x -- mix triage.accounts.create
```

Unset the provisioning variables immediately afterward. Existing users are not
silently overwritten. Keep an emergency administrator recovery procedure under
operator access control.

Install `deploy/triage.service`, adjust paths if needed, and use
`deploy/Caddyfile.example` with the actual DNS name. Let systemd start the release
only after successful migrations. Do not automate destructive rollback migrations.
The sample unit disables distributed Erlang and grants writes only to its private
runtime directory.

## Acceptance on the actual VPS

Record commands, exit status and date without credentials:

1. Verify database/release identity and migration status against the intended DB.
2. `curl --fail http://127.0.0.1:4000/health` must return only `{"status":"ok"}`.
3. Check public HTTPS `/health`, certificate validation, HTTP-to-HTTPS redirect,
   WebSocket connectivity, and firewall/listener exposure (`ss -lntp`).
4. Anonymous workspace access must go to login. Confirm viewers cannot mutate,
   roles are enforced for direct events, logout revokes access, and audit records
   reflect the logged-in user even with a forged actor value.
5. With disposable application data, test two-user refresh, dirty-draft protection,
   reload/reconnect recovery, and a complete review workflow.
6. Rehearse backup/restore below. Confirm restored logins, decisions, pending Azure
   operations and drafts, not just table counts. Review ambiguous Azure operations
   before re-enabling integrations after recovery; backup restore cannot undo a
   remote ticket created after the backup snapshot.
7. Inspect service logs and test service restart. Establish monitoring for readiness,
   DB storage, backup age and uncertain Azure operations.

A `/health` success proves DB connectivity, not complete feature correctness.
Live Azure calls need a separately approved test project and permissions.

## Backup

Use PostgreSQL client tools matching or newer than the server. Explicitly set
`PGHOST`, `PGPORT`, `PGUSER` and `PGDATABASE`; put a password in a protected
`PGPASSFILE` (mode 0600), never on the command line. Use an approved backup role.

```sh
./scripts/backup_db.sh /secure/backups/triage-UNIQUE_TIMESTAMP.dump
```

The script uses a consistent PostgreSQL snapshot, writes with restrictive umask,
checks the archive, and atomically publishes it without overwriting an existing
file. It does not rotate or delete archives. Store encrypted off-host copies;
database dumps contain sensitive inventory, audit history and credential hashes.
Define retention, RPO and RTO, and alert on failures. Cluster roles, PostgreSQL
configuration, TLS and application secrets require separate protected backups.

## Restore rehearsal and recovery

Restore only trusted archives. `pg_restore` executes SQL from the archive; do not
restore attacker-supplied dumps. Explicitly select the approved target server via
`PGHOST`/`PGPORT`/`PGUSER` and use a fresh database name:

```sh
TRIAGE_RESTORE_CONFIRM=triage_restore_YYYYMMDD \
  ./scripts/restore_db.sh /secure/backups/triage-TIMESTAMP.dump triage_restore_YYYYMMDD
```

The target must not already exist. The script never drops a database, uses
`--clean`, or terminates other sessions. Restoring is transactional; a failure
leaves the newly created target for operator inspection. Owner/grants are not
restored automatically: apply reviewed least-privilege grants separately.

Before switching production, compare application records and schema migrations,
run the new release against the restored copy with integrations disabled, and
perform the acceptance checks. Restored sessions may predate revocations; revoke
sessions before accepting users on a recovered DB. Stop old writers before
switching `DATABASE_URL`. Preserve both databases and the previous release until
recovery is signed off. Do not point old code at a schema it cannot interpret.

## Local verification

The coordinator can run `scripts/verify_owned_db.sh suite`, `ci` and `concurrency`
against an owned disposable PostgreSQL cluster (see `OWNED_DB_VERIFICATION.md`).
`sh scripts/backup_restore_test.sh` checks fail-closed behavior with fake tools;
it is not a real restore rehearsal. Record the real restore/release evidence
separately and explicitly distinguish local success from VPS validation.
