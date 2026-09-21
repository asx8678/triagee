# Local runtime boundary

Triage requires provisioned accounts and server-side role authorization. The HTTP
listener remains restricted to the local machine in every Mix/release environment.
This restriction is enforced by `config/runtime.exs`, after environment-specific
configuration is loaded.

## Environment variables

- `TRIAGE_BIND` defaults to `127.0.0.1`. Its only accepted values are the exact
  literals `127.0.0.1` and `::1`. Hostnames, wildcard/public addresses, and every
  other IP are rejected during configuration loading.
- `PORT` must be an unsigned decimal integer from `0` through `65535`. It defaults
  to `4002` in test and `4000` in development and production. Port `0` is intended
  for owned ephemeral verification probes; ordinary startup should use a stable
  nonzero port.
- `PHX_HOST` controls production URL generation only. It does not select or weaken
  the listener bind.
- `PHX_SERVER` retains Phoenix's normal release-server switch. Enabling it does not
  bypass bind validation.


Production HTTPS redirection preserves its existing TLS and HSTS behavior for public
hosts. Requests whose HTTP `Host` is the local literal `localhost`, `127.0.0.1`, or
`::1` (including Bandit's bracketed HTTP Host form `[::1]`) are excluded from that
redirect, so either supported loopback listener can be
probed locally without being redirected to the public `PHX_HOST`.

Production still requires non-empty `DATABASE_URL` and `SECRET_KEY_BASE`; absent or
empty values fail during configuration loading. The loopback guard does not add defaults
or bypass those failures. Existing collection behavior also
remains offline: these settings neither enable a transport nor authorize live API
access.

Examples:

```sh
# Development default: http://127.0.0.1:4000
mix phx.server

# Explicit IPv6 loopback
TRIAGE_BIND=::1 PORT=4000 mix phx.server
```

A value such as `TRIAGE_BIND=0.0.0.0`, `TRIAGE_BIND=localhost`, or an invalid
`PORT` fails before the application starts. Shared deployment requires TLS, a local
reverse proxy, provisioned accounts and the operational checks in
[DEPLOYMENT.md](docs/DEPLOYMENT.md). Production session cookies require HTTPS;
use a TLS tunnel/proxy rather than plain HTTP for authenticated production testing.

## Skip sign-in for local development

Development (`MIX_ENV=dev`) shows a small **Skip** button on `/login`. It signs in
as `local-user@triage.test`, an ordinary **reviewer**, using an eight-hour revocable
session. This user can save decisions and drafts and use reviewer actions, but
cannot administer accounts. Skip does not itself change findings or create tickets.

The reserved local account is created once with a random undisclosed password,
then reused so its identity, drafts and history persist across local sign-ins.
Local users of Skip share that account. Existing disabled, viewer or admin accounts
at the reserved email are never re-enabled, promoted or silently adopted. An
already signed-in user keeps their current account; sign out before switching.

The action is a CSRF-protected POST, requires a direct loopback peer, and is rate
limited. Set `config :triage, :local_login_skip, false` to disable it in development.
Production builds permanently reject the action even if that flag is enabled at
runtime. Never expose a development server as a production deployment; the VPS
still requires provisioned accounts.

## Focused verification

`test/triage/runtime_config_test.exs` is pure ExUnit. It evaluates runtime config in
isolated Elixir subprocesses and does not load `test_helper.exs`, start the Phoenix
application, or touch a Repo. It can be run directly:

```sh
MIX_ENV=test MIX_TEST_PARTITION=_ab_runtime_10405 mise exec -- elixir test/triage/runtime_config_test.exs
```

The listener test asks the OS for an ephemeral port and opens only a raw IPv4
loopback TCP socket; it does not start the app or access a database. The normal full
suite may also discover this file, but database-integrated suite execution is a
coordinator-owned step.
