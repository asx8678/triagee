# Portable Triage with Burrito (Linux and macOS)

Burrito packages Triage, its browser assets and the Erlang/Elixir runtime into
one native executable. Destination machines need **neither Elixir nor Docker**.
**PostgreSQL 18 is still required**, locally or on an approved private database
host. A TLS reverse proxy (for example Caddy) is also required for shared access;
neither PostgreSQL nor Caddy is inside the executable. This is not a database
migration to SQLite, a desktop GUI, or a zero-prerequisite installer.

## Choose a bundle

| Machine | Bundle |
| --- | --- |
| Linux Intel/AMD 64-bit | `triage-linux_x86_64.tar.gz` |
| Linux ARM64 | `triage-linux_arm64.tar.gz` |
| macOS Intel | `triage-macos_x86_64.tar.gz` |
| macOS Apple Silicon | `triage-macos_arm64.tar.gz` |

Builds are produced by the **burrito** GitHub Actions workflow (manual dispatch
or a `v*` tag). Download its `burrito-bundles` artifact, unzip it, and verify the
selected archive using `shasum -a 256 -c triage-TARGET.tar.gz.sha256` before
extracting it. Obtain both files from a trusted build: checksums detect corruption,
not an untrusted publisher. Then `tar -xzf triage-TARGET.tar.gz` and enter the
extracted directory. Run as your own user or a dedicated unprivileged service
account, not root. Binaries are currently **unsigned/not notarized** on macOS;
only approve an executable from your own trusted build using macOS security UI.
Do not disable Gatekeeper globally. Each OS/architecture needs its own smoke test.

## First run

1. Install PostgreSQL 18 and create a dedicated database and login. Do not expose
   it publicly. Use a non-superuser application role and approved migration
   permissions; shared deployments should use a separate migration role.
2. Keep configuration outside the extracted bundle so upgrades cannot overwrite it:

   ```sh
   umask 077
   mkdir -p "$HOME/.config/triage"
   cp triage.env.example "$HOME/.config/triage/triage.env"
   chmod 600 "$HOME/.config/triage/triage.env"
   ./triage secret
   ```

   Edit that file with the correct `DATABASE_URL`, the generated `SECRET_KEY_BASE`,
   and `PHX_HOST`. Never use the example placeholders, commit credentials, or
   rotate the secret at every startup. `secret`, `--help` and `--version` need
   no database configuration. Load only your own trusted configuration file:

   ```sh
   set -a
   . "$HOME/.config/triage/triage.env"
   set +a
   ./triage migrate
   ```

   Migrations are explicit application migrations, never seed/reset operations.
   Take a database backup first when upgrading an existing install.
3. Provision an account. There is **no default password or production local-user
   shortcut**. Supply `TRIAGE_ACCOUNT_EMAIL`, `TRIAGE_ACCOUNT_PASSWORD` (at least
   12 bytes), and `TRIAGE_ACCOUNT_ROLE` (`admin`, `reviewer`, or `viewer`) through
   a password manager or a separate protected environment file, not command-line
   arguments or shell history. After loading them:

   ```sh
   ./triage account
   unset TRIAGE_ACCOUNT_EMAIL TRIAGE_ACCOUNT_PASSWORD TRIAGE_ACCOUNT_ROLE
   ```

   Remove the provisioning file/variables afterward. Existing accounts are never
   overwritten. A failure exits nonzero and does not print supplied credentials.
4. Run `./triage start` (or just `./triage`). It stays in the foreground; Ctrl-C
   stops it. For unattended use, run it under systemd (Linux) or launchd (macOS)
   with the same protected environment and user. Load configuration on every start.
   `PHX_SERVER` is not needed for Burrito. Administrative commands do not start
   the HTTP listener, job workers, or optional integrations.
5. The app listens on `127.0.0.1:4000` by default; `::1` is also supported.
   Verify `curl --fail http://127.0.0.1:4000/health`. Configure the bundled
   `Caddyfile.example` with your host and use **HTTPS** to sign in. Secure session
   cookies and authentication remain enabled. Keep the app and database ports
   private; changing `PHX_HOST` never changes the loopback-only bind restriction.
   Local Caddy certificates need to be trusted by the browser; shared deployments
   need an appropriate DNS name and certificate. The health URL alone is not an
   authenticated end-to-end readiness test.

Optional AI/Azure tools and their credentials are not included or enabled.
All persistent application data lives in PostgreSQL, not in the executable.
Burrito extracts its runtime to a per-user cache: the executing user needs writable
cache/temp space. Never store database backups or configuration in that cache.

## Updates and backup

Back up PostgreSQL and protected configuration, stop Triage, extract the new bundle
into a new versioned directory, load the same configuration, run `./triage migrate`,
and start the new binary. Keep the old binary and backup until verified. Do not
run multiple versions against the same database during migration or assume an
old binary can read a newer schema. Rehearse restore before shared use. Use
`pg_dump`/`pg_restore` matching or newer than PostgreSQL 18; see `DEPLOYMENT.md`
(bundled) or `app/docs/DEPLOYMENT.md` (source) for the full recovery procedure.
The bundle does not automatically install a service, proxy, or update itself.

## Build from source

Use the pinned `.mise.toml` Elixir/OTP versions, **Zig 0.16.0**, and `xz` on PATH.
Burrito currently uses immutable upstream commit
`f2d437041418abb9073a6d7588d22835a04ee7cb` from [PR #230](https://github.com/burrito-elixir/burrito/pull/230).
**This fix is not yet merged/released upstream.** Released 1.6.0 consumes app
arguments and stops long-running servers ([#229](https://github.com/burrito-elixir/burrito/issues/229));
1.5.0's older Zig compiler failed to link on the macOS 27 build host. The pin
changes only wrapper argument handling. Revisit it when a fixed release is
available, and retain the native foreground-server smoke test when upgrading.
The build needs network access for Hex packages, Tailwind, and Burrito's compatible
precompiled OTP runtimes. From `app/`:

```sh
mise x -- sh scripts/build_burrito.sh macos_arm64  # one target
mise x -- sh scripts/build_burrito.sh              # all four targets
```

Archives and SHA-256 receipts appear under `app/dist/`; raw executables are under
`app/burrito_out/`. Both are ignored by Git. Never place real credentials or private
inventory files under `priv/`: release contents include that directory.
`MIX_ENV=prod mix burrito` builds the raw executables directly. Ordinary
`MIX_ENV=prod mix release` still builds the existing non-Burrito `triage` release;
the Docker/VPS/Kubernetes paths are unchanged.

## Verification

The workflow runs each binary's help/version/secret/error checks on its native
Linux/macOS architecture, plus a PostgreSQL migration/account/HTTP smoke test on
Linux x86-64. Locally, the database-safe wrapper can verify a matching binary:

```sh
./scripts/verify_owned_db.sh burrito "$PWD/burrito_out/triage_burrito_macos_arm64"
```

This creates and guards its own disposable database, runs the binary, stops it,
and drops only that database. It must not be pointed at production. Native
smokes are necessary: cross-compilation or unit tests alone do not certify a
particular destination PC, its TLS setup, or its backup/restore procedure.
