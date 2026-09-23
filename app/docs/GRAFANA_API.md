# Grafana reporting API

The application exposes a **read-only, versioned JSON API** for server-side Grafana datasources. It reports current recorded inventory and effective decisions; it does not prove scanner completeness, mutate triage state, or mark risk acceptance as remediation.

Contract: [`openapi/grafana-v1.yaml`](openapi/grafana-v1.yaml)

Design and remaining rollout gates: [`GRAFANA_API_PLAN.md`](GRAFANA_API_PLAN.md)

## Security boundary

- Phoenix remains bound to `127.0.0.1` or `::1`. Publish it only through the approved private TLS reverse proxy or tunnel.
- The API is disabled by default. `TRIAGE_REPORTING_API_ENABLED=true` is required at application startup.
- Authentication uses a dedicated expiring `trg_...` bearer token. Only its SHA-256 hash is stored.
- A token grants either all reporting scope or exact `{team, environment}` pairs. Pair grants are not expanded into a team/environment cross product.
- Every request rechecks token expiry/revocation and the enabled parent viewer/reviewer/admin identity.
- Reporting credentials cannot authorize browser review, decision, ticket, AI, or refresh actions.
- Responses are `Cache-Control: no-store`; unknown parameters fail with `400`; unavailable or disabled reporting fails with `503`, never an all-zero success.

## Enable and provision

Run migrations through the normal owned/deployment process, then restart with:

```sh
TRIAGE_REPORTING_API_ENABLED=true mise x -- mix phx.server
```

Create a dedicated enabled viewer account through the existing account process. Issue a token only from a protected operator shell; tasks intentionally reject command-line arguments so secrets are not placed in shell history:

```sh
export TRIAGE_REPORTING_USER_EMAIL='grafana@example.invalid'
export TRIAGE_REPORTING_TOKEN_LABEL='grafana demo'
export TRIAGE_REPORTING_TOKEN_EXPIRES_AT='2026-10-01T12:00:00Z'
export TRIAGE_REPORTING_TOKEN_SCOPES_JSON='[{"team":"demo-payments","environment":"prod"}]'
mise x -- mix triage.reporting.issue
```

For explicitly approved estate-wide reporting, set `TRIAGE_REPORTING_TOKEN_SCOPES_JSON='"all"'`. The task prints the opaque secret once. Deliver it through the approved secret channel; do not put it in a URL, dashboard JSON, repository file, screenshot, or client-side browser datasource.

Rotate atomically (the old token is revoked only when replacement issuance succeeds):

```sh
export TRIAGE_REPORTING_TOKEN_ID='123'
export TRIAGE_REPORTING_TOKEN_EXPIRES_AT='2026-11-01T12:00:00Z'
mise x -- mix triage.reporting.rotate
```

Revoke:

```sh
export TRIAGE_REPORTING_TOKEN_ID='123'
mise x -- mix triage.reporting.revoke
```

Token lifetimes are mandatory and limited to 90 days.

## HTTP use

Use the approved TLS URL in deployed environments. A local probe can use loopback:

```sh
curl --fail-with-body \
  -H "Authorization: Bearer $TRIAGE_REPORTING_TOKEN" \
  -H 'Accept: application/json' \
  'http://127.0.0.1:4000/api/v1/summary'
```

Available GET routes:

| Route | Purpose |
|---|---|
| `/api/v1/summary` | Current CVE/target counters and bounded severity/team/environment breakdowns. |
| `/api/v1/cves` | Keyset-paged active CVE aggregates, including partial/full whitelist coverage. |
| `/api/v1/cves/:cve` | One scoped active-CVE aggregate. |
| `/api/v1/targets` | Keyset-paged exact CVE × placement rows and authenticated-app drilldown links. |
| `/api/v1/targets/:placement_id/packages?cve=...` | Bounded scanner package evidence for one exact pair. |
| `/api/v1/options` | Keyset-paged authorized `{team, environment}` option pairs and fixed enums. |

Default page size is 50 and maximum is 100. Follow `pagination.next_cursor` without changing the endpoint, filters, token, or grants. Cursor pages are deterministic but do not freeze one database snapshot across HTTP requests. Grafana stat panels should read `/summary`, not sum separate target pages.

`placement_id`, `decision_id`, and finding `id` values are decimal strings so JavaScript does not lose PostgreSQL bigint precision. `evaluated_at` is the API evaluation clock, not a source scan time. `source_coverage` remains `unknown` until a real source-completeness contract exists.

## Grafana Infinity setup

The intended integration is the Infinity datasource using **backend/server-side parsing**. Confirm the installed Grafana and Infinity versions and plugin policy before rollout; this repository does not claim a live Grafana connection.

1. Install/approve `yesoreyeram-infinity-datasource` on the Grafana server.
2. Create a datasource using the approved private TLS base URL.
3. Select backend parsing so alerting and server-side credentials are supported.
4. Store `Authorization` as a secure datasource HTTP header with value `Bearer <token>`.
5. Set a 60-second initial dashboard refresh. Tune only after measuring representative estate and package fan-out.
6. Restrict datasource permissions. Dashboard variables and hidden fields are not an authorization boundary.
7. Query relative paths such as `/api/v1/summary`; use `data` as the root selector and treat non-2xx responses as errors.
8. Populate team/environment choices from paged `/api/v1/options`. Preserve each authorized pair; do not independently combine all team and environment values.
9. Build app links from returned relative `detail_path` values and the approved Triage base URL. Do not prepend an untrusted query value.

The importable starter at `priv/grafana/triage-reporting-dashboard.json` contains no datasource URL or credential. Select the secured Infinity datasource during import. Its plugin query model is a local starter only and still requires validation against the installed plugin version.

## Semantics to show on dashboards

- `active`: unresolved recorded finding on an active placement.
- `whitelisted`: active target covered by the effective `accepted_risk` decision and current evidence policy.
- `whitelist_coverage`: calculated against all active targets for the CVE in authorized/requested scope. Two accepted targets and one uncovered target is `partial`.
- `needs_decision` and `needs_attention` are different predicates.
- `reported_fixed` is a claim awaiting deployment verification, not verified remediation.
- `not_affected` is distinct from accepted risk.
- Retired placements and reference-only records do not enter operational totals.
- Summary team/environment breakdowns are capped at 100 rows; `breakdown_truncated` states whether a cap was reached.

Show API errors and `source_coverage: unknown` visibly. Never translate a `401`, `403`, `429`, or `503` into a green zero.

## Rollback

1. Set `TRIAGE_REPORTING_API_ENABLED=false` and restart.
2. Revoke the datasource token.
3. Disable Grafana datasource queries.

This leaves browser triage and existing decisions intact. Do not roll back by dropping token tables or rewriting decision history. Production network exposure, real plugin validation, load measurements, migration rollback rehearsal, and rollout approval remain explicit release gates.
