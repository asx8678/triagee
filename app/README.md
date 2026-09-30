# Triage

Local vulnerability review with Phoenix LiveView, Ecto and PostgreSQL.
Review findings, preserve scoped case evidence, record time-limited decisions,
and explicitly request remediation. A ticket or risk acceptance is not a fix.

## Safety boundary

**Production and write access require provisioned accounts; there is no public registration or default password.**
For local development, **Continue as local user** appears above the credential fields and signs in as `local-user@triage.test` with normal reviewer access, without entering credentials.
This shortcut is unavailable in production; see [Local runtime](LOCAL_RUNTIME.md#skip-sign-in-for-local-development).
Viewer/reviewer/admin roles are enforced server-side and workspace audit identity
comes from the authenticated session. Runtime binding still accepts only
`127.0.0.1` or `::1`; keep PostgreSQL local too. See
[deployment and recovery](docs/DEPLOYMENT.md) for TLS, account provisioning,
release migrations and backup/restore. A local test pass is not VPS certification.
Demo placements are simulated and public CVE reference data is not evidence that
any real deployment is affected. No background collection or automatic approvals
are enabled. AI advice and Azure ticket creation are opt-in and human-triggered.

## Portable Linux/macOS executable

Use [Burrito packaging](docs/BURRITO.md) to build or download a standalone
executable for Intel/AMD or ARM machines. No Elixir or Docker is needed on the
destination. PostgreSQL remains a separate prerequisite; migrations, account
provisioning, TLS, and backups are still explicit operator responsibilities.

## Setup and run

Requirements: `mise`, the pinned Elixir/OTP versions in `.mise.toml`, and local
PostgreSQL 18. The development configuration uses the local `postgres` user with
trust authentication; do not expose that database.

```sh
cd app
mise install
# Start your local PostgreSQL service if needed.
mise x -- mix setup
mise x -- mix phx.server
# http://127.0.0.1:4005
```

`mix setup` fetches dependencies, creates/migrates `triage_dev`, loads the offline
demo seed in development only, and builds assets. Test setup never seeds the demo
implicitly. `TRIAGE_BIND` controls the loopback address and `PORT` the listener port.

## Kiro classification in Triage

Select a CVE in **Triage** and click **Classify with AI**. Phoenix sends its complete
stored evidence for the current team/environment scope to **headless Kiro**, then
shows a **risk score**, **whitelist-suitability score**, and reasoning directly in
Triage. Results are saved independently of the browser connection. Classification
never applies a whitelist, edits a repository or creates an Azure ticket.

**Classify all critical with AI** queues the same guarded classification for every
critical CVE that needs a decision in the current team and environment. Runs go
through the single classifier slot one at a time; a CVE whose result is already
current is not re-run. The list shows **AI classifying…** and then each CVE's AI
risk score as results arrive. Nothing is decided automatically.

Enable explicitly with `TRIAGE_ANALYSIS_ENABLED=true` and `TRIAGE_KIRO_CLI` pointing
to your authenticated `kiro-cli`; optionally pin `TRIAGE_KIRO_MODEL`. No separate
model HTTP endpoint/API key is used. There is no classification merely from
browsing. The old `/classifier` screen redirects to Review, and its HTTP-model
flags are retired. See [setup, scoring and safety](docs/AI_CLASSIFIER.md).

## Presentation demo

Development preselects **Whitelist** and the CVE's active deployments in the
current scope, so the **Whitelist** button starts enabled. A reason and confirmation
are still required; existing drafts are preserved. Set `TRIAGE_DEMO_MODE=false`
for neutral defaults (the default in test/production).

Load the expanded fictional estate with
`mise x -- mix triage.demo --database triage_dev`: 30 CVEs, 18 workloads and
54 placements across seven teams and three environments. No reset or external
calls. Use **Demo mode · examples** in the scope bar or the
[presentation walkthrough](docs/DEMO.md).

## Single workspace UI

The homepage `/` is the workspace; `/workspace` is an alias for the same UI.
The navigation has two pages, **Triage** and **Timeline**:

- **Triage** (`/?page=findings`, with `/?page=review` for one CVE): three counts
  at the top (**Need a decision**, **Active CVEs**, **Whitelisted**) also pick
  the list shown beneath them. The list is searchable by CVE or package; each row
  shows severity, whether the affected deployments are **External**
  (internet-facing), **Internal** or of unknown exposure, and the latest AI state.
  Whitelisted rows show their expiry. The selected CVE shows its description and
  fixed version, **Your infrastructure** (each deployment's exposure, team,
  environment, service, package version and status), AI classification and the
  decision history. The decision offers **Whitelist**, **Mark as fixed** or
  **Create ticket** for the ticked deployments. A whitelist needs a reason and an
  end date (three months by default) and is confirmed in a dialog; it applies
  through the selected date and expires at the following midnight UTC. AI
  classification is optional and never blocks a manual decision.
- **Timeline** (`/?page=daily`): one history per CVE, ordered from detection
  through whitelisting, work actions, marked fixes, and scanner observations.
  Each CVE shows its first detection, first recorded action on any deployment,
  and response time. Every action includes its timestamp, scope, reviewer,
  reason, expiry when present, and elapsed time since detection. CVEs without a
  recorded action show a waiting duration. Response time describes the recorded
  action; it does not establish verified remediation or coverage of every
  deployment. A single operation across several deployments is one step with
  all its scopes. Independent later reviews remain dated steps; repeated
  whitelist decisions are labelled **Whitelist updated**. CVEs are sorted by
  latest activity and paged as complete histories, so detection and action
  cannot end up on separate pages.

To add three fictional local Timeline examples, run
`mise x -- mix run priv/repo/timeline_samples.exs` in development. The two
whitelist examples respond after 2 and 5 hours. The third shows detection,
a fix marked by a reviewer, then a later scanner clearance. These records use
`CVE-2099-9028` through `CVE-2099-9030`, have no public advisory URLs, and are
added only if missing; repeated runs preserve existing history.

The detection timeline shows history across all teams and environments; its
scope bar states this explicitly. Team/environment filters remain available in
Triage and the observation chart. Existing URLs preserve bookmarks and unsaved
drafts. The full observation chart remains at `/timeline` and `/?page=timeline`
in the same shell. Navigation keeps the LiveView connection and unsaved drafts.
Stored inventory, decisions and case evidence are unchanged.

The former **Overview**, **Vulnerabilities**, **Risk decisions** and **News**
pages were removed to keep the workspace to one triage flow. Their bookmarks
(`/?page=overview`, `inventory`, `exceptions`, `news`) open Triage. Whitelisted
CVEs and their expiry are listed under **Whitelisted** in Triage; decision
history stays on each CVE and in Timeline.

Timeline retains its connected observation chart (fit/daily scale), detection and
response table, day bands, weekday heatmap, KEV context and paged CVE event/case
history. Complete saved-case histories expand read-only in place. Team/environment
scopes, 4/8/12-week windows and old timeline bookmarks are preserved. Imports, replay, intelligence
refresh are not available in this UI. Explicit Azure ticket creation uses the
separate [review actions](docs/REVIEW_ACTIONS.md) workflow and `ADO_*`
configuration.

## Retired screens

The earlier standalone screens (Findings, CVE details, Action required, Guided
review, Cases, Exceptions, What's new, Intel, Statistics, Replay, Imports and the
separate classifier) have been removed. Their URLs (`/findings`, `/cves/:id`,
`/triage`, `/cases`, `/whats-new`, `/intel`, `/statistics`, `/replay`, `/imports`,
`/classifier`, ...) redirect into the matching workspace page and keep team,
environment, search and severity filters. Their history remains in Git.

The backend capabilities stay available without those screens:

- **Cases:** scoped, frozen, append-only case evidence (`lib/triage/cases.ex`).
- **Replay:** `mix triage.replay` runs a synthetic replay without changing
  inventory. See [PR7_CLI.md](PR7_CLI.md) and [PR7_HISTORY.md](PR7_HISTORY.md).
- **Imports:** `mix triage.import` previews an approved historical snapshot and
  applies it only on explicit confirmation. See the
  [Domain/API guide](docs/DOMAIN_API.md#approved-historical-snapshot-import).

### Decision policy

The latest **effective** decision is selected separately for each exact
`{CVE, placement}` scope; a `nil` placement means the whole advisory. Future
`decided_at` values are pending and cover nothing. A newer effective replacement
that expires does not revive an older acceptance. Expiry is inclusive at the
stored timestamp; the next second is expired. A placement decision never covers
its siblings. Triage records an advisory as decision-covered only when every
active scope is covered. Decisions do not resolve or suppress inventory findings.

### Optional integrations

Server-side configuration:

| Variable | Purpose |
|---|---|
| `TRIAGE_AZURE_ORGANIZATION` | Azure DevOps organization |
| `TRIAGE_AZURE_PAT` | Server-side credential; never commit it |
| `TRIAGE_AZURE_TEAMS_JSON` | Exact team names mapped to `project` and `area_path`; optional `work_item_type` |
| `TRIAGE_AI_EXECUTABLE` | Absolute path to an administrator-owned read-only CLI wrapper |
| `TRIAGE_ANALYSIS_ENABLED` | AI triage is disabled by default; must be exactly `true`/`1` (or `false`/`0`) or startup fails. Never implied by any installed binary |
| `TRIAGE_KIRO_CLI` | Absolute path to the administrator-reviewed analysis runner; required alongside `TRIAGE_ANALYSIS_ENABLED` for any AI suggestion |

For connecting a least-privilege Azure DevOps token — and verifying it can create tickets but never delete them — see [Azure credentials setup and verification](docs/AZURE_CREDENTIALS.md).

Public-intelligence refreshes store each validated snapshot as an immutable generation and serve only the current one; a failed or unverifiable refresh keeps the previous generation and records a receipt. Exposure evidence is displayed from the latest observation, but only evidence from a source with an approved bounded age may support a dismissal:

```elixir
config :triage, :exposure_policy, %{
  "scanner:trivy" => %{max_age_days: 30, require_expiry: true}
}
```

Without an entry for a source, that source's evidence can prompt investigation but can never close work. See `app/docs/experiment-requirements.md` for the acceptance ledger.

The AI wrapper accepts one JSON argument and returns a JSON object containing
`recommendation` (`whitelist`, `fix`, or `investigate`) and a nonempty `reason`
(up to 8,000 bytes). Output is capped at 65,536 bytes with a 30-second deadline.
It must not perform actions; recommendations do not authorize changes.

Ticket confirmation binds to previewed evidence and destination, including the
Azure organization. Successful requests are not automatically resent. An
uncertain response or interrupted send requires checking Azure; do not blindly
retry. Test adapters use synthetic credentials and never contact Azure or AI.

## Quality checks

```sh
cd app
mise x -- mix format --check-formatted
MIX_ENV=test mise x -- mix compile --warnings-as-errors
mise x -- mix credo --strict
mise x -- mix test
mise x -- mix dialyzer
# Combined non-rewriting quality gate:
mise x -- mix ci
```

Ordinary tests use the sandboxed `triage_test` database. For isolated verification,
follow [OWNED_DB_VERIFICATION.md](OWNED_DB_VERIFICATION.md): create an absent-before,
identity-checked disposable partition and drop only the database you created.
Real-commit import concurrency tests are opt-in and must never run on shared data.
`mix precommit` rewrites formatting and may update the lockfile; use `mix ci` when
checking a tree without silently fixing source files.

DB-free checks are available with
`TRIAGE_SKIP_DB_SETUP=1 mise x -- mix test`; these exclude database tests and are
not a substitute for database-backed verification.

## Code map

- `lib/triage/decisions.ex`: time- and placement-scoped decision policy.
- `lib/triage/guided_review/query.ex`: bounded queue reads and individual CVE lookup.
- `lib/triage/guided_review.ex`: plans, fingerprints and durable ticket claims.
- `lib/triage/cases.ex`: public case API and transactional writes.
- `lib/triage/cases/queue.ex`: read-only case projections and pagination.
- `lib/triage/cases/evidence.ex`: canonical evidence payloads and stable hashes.
- `lib/triage_web/live/`: UI state, navigation and explicit confirmations.
- `lib/triage_web/live/workspace_live.ex`: the single workspace LiveView (routing,
  shared state, page shell). Page behaviour lives in plain modules under
  `workspace_live/`: `params.ex` (URLs and page names) and `review.ex` (drafts,
  decisions, tickets, classification).
- `dev/`: demo seeds and `mix triage.demo`, compiled in dev/test but never shipped
  in production releases.

## Assets and reference data

`mise x -- mix assets.setup` builds Tailwind and copies Phoenix browser clients.
The pinned standalone Tailwind CLI downloads on a cold cache; subsequent builds
use the cached binary. CSS source is `assets/css/tailwind.css`; the current root
layout loads generated `priv/static/assets/css/tailwind.css` followed by
`priv/static/assets/css/workspace.css`. The retained legacy `app.css` is not loaded.
`source(none)` plus the explicit `lib/` source keeps dependency/build/evidence
files out of Tailwind scanning; the development watcher uses the same profile.

On macOS, `mix tailwind triage` (and so `mix setup`, `mix test` and `mix ci`) can
fail with `exited with 137` right after the download: macOS kills the downloaded
CLI because it rejects its code signature (`codesign -v` reports an invalid
signature). Sign the cached binary locally once, then rerun:

```sh
codesign --force -s - _build/tailwind-macos-*
```

The binary lives in the ignored `_build/` directory, so this changes no tracked
file. Repeat it after a Tailwind version bump or after deleting `_build/`.

Phoenix vendor scripts are copied from fetched dependencies pinned in `mix.lock`,
not a browser CDN. The root loads those deferred scripts before the tracked
`priv/static/assets/js/app.js` LiveSocket bootstrap. Generated vendor assets and
Tailwind output are not committed; setup/test/quality aliases build them. If the
browser reports missing Phoenix scripts, run `mix assets.setup` and reload.
Release packaging must include generated assets, not only tracked sources.
No Node bundler is required.

See [REAL_CVES.md](REAL_CVES.md) for the separate public-reference dataset workflow.
See [Domain/API guide](docs/DOMAIN_API.md) for retained backend contracts and
[Workspace boundaries](docs/WORKSPACE.md) for source paths, rollback safety and
remaining acceptance requirements. Historical test counts do not certify the
current code.

The [Grafana reporting API guide](docs/GRAFANA_API.md) documents the implemented
local read-only `/api/v1` surface, scoped bearer-token lifecycle and credential-free
starter dashboard. The [OpenAPI contract](docs/openapi/grafana-v1.yaml) and
[implementation plan](docs/GRAFANA_API_PLAN.md) distinguish verified local API work
from the still-pending live Grafana, network, load and rollout gates.
