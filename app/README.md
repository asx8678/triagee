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
# http://127.0.0.1:4000
```

`mix setup` fetches dependencies, creates/migrates `triage_dev`, loads the offline
demo seed in development only, and builds assets. Test setup never seeds the demo
implicitly. `TRIAGE_BIND` controls the loopback address and `PORT` the listener port.

## Single workspace UI

The homepage `/` is the new workspace; `/workspace` is an alias for the same UI.
The primary navigation is **Review**, **Risk decisions**, and **Timeline**:

- **Review** (`/?page=findings`, with `/?page=review` for existing detail links):
  review CVEs, select deployments, and record the next action.
- **Risk decisions** (`/?page=exceptions`): the last 365 days of whitelist and
  not-affected decision records, including older replacements. The table shows
  the CVE, deployments, action, reason, reviewer, and expiry. Expiry status only
  describes the record's time limit; open the CVE for its current effective status.
  A whitelist applies through the selected date and expires at the following
  midnight UTC. The deployments then need review unless a newer decision applies.
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

Risk decisions and the detection timeline show history across all teams and
environments; their scope bar states this explicitly. Team/environment filters
remain available in Review. Existing URLs preserve bookmarks and unsaved drafts.
Overview and Vulnerabilities remain at their existing `/?page=...` URLs. The full
observation chart remains at `/timeline` and `/?page=timeline` in the same shell.
Navigation keeps the LiveView connection and unsaved review drafts.
Retired screen URLs redirect into the workspace and no longer mount their old
LiveViews. The old stylesheet and links back to old screens are not loaded.
Stored inventory, decisions and case evidence are unchanged.

The workspace currently supports inventory inspection and local scoped decisions.
In Vulnerabilities, **Add CVE** opens an optional dialog with the research list,
accepts a CVE number and explicitly fetches its
English description from NVD. Review the preview, then save it to the persistent
research list. Duplicate IDs are saved only once. Research entries do not create
affected deployments or change operational counts. This manual lookup works
without enabling background intelligence collection and sends only the CVE ID
to NVD; failed or unpublished lookups do not create entries.

The **News** tab fetches this month's published critical CVEs from NVD (CVSS
v3/v4) and recent vulnerability headlines from BleepingComputer when opened.
Refresh reloads both sources independently; errors retain the last successful
results in the current connection. The table shows CVE IDs, publication dates,
CVSS scores and descriptions. This public news does not create findings,
change inventory counts, or claim local exposure. Fetch timestamps and source
links are visible. Each NVD severity query is capped at 2,000 records and the UI
reports incomplete results if that limit is reached.
Timeline retains its connected observation chart (fit/daily scale), detection and
response table, day bands, weekday heatmap, KEV context and paged CVE event/case
history. Complete saved-case histories expand read-only in place. Team/environment
scopes, 4/8/12-week windows and old timeline bookmarks are preserved. Imports, replay, intelligence
refresh and AI are not yet available in this UI. Explicit Azure ticket creation
uses the separate [review actions](docs/REVIEW_ACTIONS.md) workflow and `ADO_*`
configuration. Decision history
also remains in the CVE inspector.

## Historical workflows (retired screen URLs)

The following describes the previous UI and retained backend capabilities, not
additional currently accessible screens.

- **Findings / CVE details:** inspect recorded inventory, scope, lifecycle and
  cached intelligence. Unknown exposure is not evidence of safety.
- **Action required (`/triage`):** pages scan 25 candidate CVEs in descending review-priority
  order, with ascending CVE as the tie-breaker. Counts are page-local. Covered/ticketed candidates may leave an empty
  page with a **Next page** link; continue until no next page remains. Details
  load independently of the current page. **First page** resets the cursor.
- **Guided review:** understand the CVE, verify teams/exposure, assess risk and
  confirm an action. Local remediation planning creates no external ticket.
- **Cases / previous assessments:** explicitly open scoped cases; evidence is
  frozen and append-only. Review submissions bind to the case revision and
  snapshot. Refresh evidence explicitly after source changes.
- **Timeline (`/timeline`):** displays recorded history, with guided-review links
  for actionable displayed CVEs, independently of action-queue pagination.
- **Replay (`/replay`, `/replay/history`):** run a synthetic replay without changing
  inventory; save a summary only when requested. See [PR7_CLI.md](PR7_CLI.md)
  and [PR7_HISTORY.md](PR7_HISTORY.md).
- **Imports (`/imports`):** preview an approved historical snapshot, then review
  and explicitly confirm. Apply rechecks evidence under the import lock;
  changed previews must be uploaded again. See [Domain/API guide](docs/DOMAIN_API.md#approved-historical-snapshot-import).

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

For connecting a least-privilege Azure DevOps token — and verifying it can create tickets but never delete them — see [Azure credentials setup and verification](docs/AZURE_CREDENTIALS.md).

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

## Assets and reference data

`mise x -- mix assets.setup` builds Tailwind and copies Phoenix browser clients.
The pinned standalone Tailwind CLI downloads on a cold cache; subsequent builds
use the cached binary. CSS source is `assets/css/tailwind.css`; the current root
layout loads generated `priv/static/assets/css/tailwind.css` followed by
`priv/static/assets/css/workspace.css`. The retained legacy `app.css` is not loaded.
`source(none)` plus the explicit `lib/` source keeps dependency/build/evidence
files out of Tailwind scanning; the development watcher uses the same profile.

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
