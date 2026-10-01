# Going live with real data

How to run Triage on your own machine with real inventory, and how Grafana reads
it. Every command runs from `app/`. The data commands are mix tasks, so run the
app from source for now; a packaged release cannot run them yet.

## 1. Start with an empty database

```sh
mise install
mise x -- mix deps.get
mise x -- mix ecto.setup      # not `mix setup`, which also loads the demo data
mise x -- mix assets.setup
```

Start the server with the demo behaviour off. In development mode it is on by
default: it preselects Whitelist, ticks deployments and shows a demo link.

```sh
TRIAGE_DEMO_MODE=false mise x -- mix phx.server    # http://127.0.0.1:4005
```

Development mode also offers **Continue as local user** without a password. Set
`config :triage, :local_login_skip, false` in `config/dev.exs` to remove it. A
production release never has it.

## 2. Create your account

```sh
TRIAGE_ACCOUNT_EMAIL=you@example.com \
TRIAGE_ACCOUNT_PASSWORD='at least 12 characters' \
TRIAGE_ACCOUNT_ROLE=reviewer \
mise x -- mix triage.accounts.create
```

Roles are `viewer`, `reviewer` and `admin`. Only reviewers and admins decide.

## 3. Load the inventory

The app reads a JSON snapshot file. Something on your side has to write that
file from your scanner or data source: the app does not connect to it itself.

```json
{
  "format": "triage.snapshot",
  "version": 1,
  "source": "my-scanner",
  "generated_at": "2026-10-01T06:00:00Z",
  "images": [
    {
      "digest": "sha256:0123...",
      "repository": "registry.example/payments-api",
      "tag": "1.4.2",
      "placements": [
        {"namespace": "payments", "owner": "team-a", "environment": "prod",
         "first_seen": "2026-09-20T06:00:00Z", "last_seen": "2026-10-01T06:00:00Z"}
      ],
      "findings": [
        {"cve": "CVE-2025-0001", "package_name": "openssl", "package_version": "3.0.1",
         "severity": "HIGH", "fix": "3.0.2",
         "first_seen": "2026-09-20T06:00:00Z", "last_seen": "2026-10-01T06:00:00Z",
         "events": []}
      ]
    }
  ]
}
```

Rules the file must follow:

- `owner` is the team. `environment` is required for every placement.
- `severity` is `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or null. Map anything else.
- Keep `first_seen` stable between runs. `last_seen` may only move forward.
- At most 10,000 records and 5 MB per file. Split a large estate by team or
  environment.

For a regular feed, declare the file complete:

```sh
mise x -- mix triage.import --file today.json --complete           # dry run
mise x -- mix triage.import --file today.json --complete --apply
```

`--complete` means the file is the full current state, as of `generated_at`, of
every team and environment pair it mentions and of every image it lists. Then:

- a deployment of those pairs that the file does not list is retired, which is
  what happens when a workload moves to a new image;
- an open finding missing from a listed image is recorded as no longer observed;
- a finding listed again later is reopened.

Findings belong to the image, not to a team. A listed image must carry its full
finding list even when several teams run it, because a finding the file omits is
closed for every team that runs that image. Deployments are only retired for the
team and environment pairs the file itself mentions.

The dry run shows the counts and examples before anything is written. Without
`--complete` nothing is ever inferred from absence; use that for partial files.
A daily cron entry is enough to keep the app current.

## 4. Say which deployments are internet-facing

The scanner does not know this, so you declare it. Do it before triaging:
recording exposure changes the evidence a decision was made from, so a whitelist
recorded while exposure was unknown needs a decision again.

```json
{
  "format": "triage.exposure",
  "version": 1,
  "source": "manual:security-team",
  "deployments": [
    {"team": "team-a", "environment": "prod", "exposure": "internal"},
    {"team": "team-a", "environment": "prod", "namespace": "gateway",
     "exposure": "internet_exposed"}
  ]
}
```

```sh
mise x -- mix triage.exposure --file exposure.json           # dry run
mise x -- mix triage.exposure --file exposure.json --apply
```

An entry without `namespace` covers the whole team and environment. An entry
with one wins for that namespace. Anything not declared stays Unknown.

## 5. Known-exploited vulnerabilities

```sh
TRIAGE_INTEL_SOURCES=kev mise x -- mix triage.intel --kev
```

This fetches the CISA catalogue over HTTPS and needs outbound access to
`cisa.gov`. Run it daily next to the import. Without it nothing is marked as
known exploited and review priority follows severity only.

## 6. Grafana

The reporting API is read-only and off by default. Details and the endpoint
list are in [GRAFANA_API.md](GRAFANA_API.md).

```sh
# A token for Grafana, valid for at most 90 days.
export TRIAGE_REPORTING_USER_EMAIL=you@example.com
export TRIAGE_REPORTING_TOKEN_LABEL=grafana
export TRIAGE_REPORTING_TOKEN_EXPIRES_AT=2026-12-15T12:00:00Z
export TRIAGE_REPORTING_TOKEN_SCOPES_JSON='"all"'
mise x -- mix triage.reporting.issue

# Then start the server with the API on.
TRIAGE_DEMO_MODE=false TRIAGE_REPORTING_API_ENABLED=true mise x -- mix phx.server
```

In Grafana, install the Infinity data source, point it at
`http://127.0.0.1:4005` and add the header `Authorization: Bearer <token>`.
Import `priv/grafana/triage-reporting-dashboard.json`. It shows the current
counts and, from `/api/v1/statistics`, the same handling numbers as the
Statistics page.

The app listens on `127.0.0.1` only. Grafana installed on the same machine
reaches it directly. Grafana in a container needs host networking or a reverse
proxy on the host.

## 7. Compare with the repository whitelist (optional)

If the list of whitelisted CVEs is kept as a file in an Azure Repos Git
repository, Triage can read it and set it beside its own whitelists.

```sh
export ADO_ORG_URL=https://dev.azure.com/your-org
export ADO_PROJECT=YourProject
export ADO_WHITELIST_REPO=security-config
export ADO_WHITELIST_PATH=/whitelist/cves.yaml
export ADO_WHITELIST_PAT=<token with the Code (Read) scope only>

# From a terminal, read-only:
mise x -- mix triage.whitelist
# Or compare a local copy without contacting Azure DevOps:
mise x -- mix triage.whitelist --file ./cves.yaml
```

In the app, **Whitelist overview** on the Triage tab row shows the same
picture: what is whitelisted and until when on both sides, with a green, orange
or red bar per end date, what is whitelisted in Triage and missing from the
list, what is in the list and still needs a decision in Triage, and the CVEs
that need a decision and are in neither. The file may be JSON, YAML, CSV, a
Markdown table or plain lines. If its layout is not picked up correctly, the
dialog says that no CVE id was found; the parser is
`lib/triage/repo_whitelist/parse.ex`. Token setup is in
[AZURE_CREDENTIALS.md](AZURE_CREDENTIALS.md#optional-read-the-repository-whitelist).

## Not in the app yet

- A direct connection to the scanner. The snapshot file is the only way in.
- Running the import, exposure, intelligence, whitelist and token commands from
  a packaged release. They are mix tasks.
