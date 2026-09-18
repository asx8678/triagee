# Triage

Local vulnerability review with Phoenix LiveView, Ecto and PostgreSQL.
Review findings, preserve scoped case evidence, record time-limited decisions,
and explicitly request remediation. A ticket or risk acceptance is not a fix.

## Safety boundary

**Trusted local operators only: there is no authentication or authorization.**
Runtime binding accepts only `127.0.0.1` or `::1`; keep PostgreSQL local too.
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

## Main workflows

- **Findings / CVE details:** inspect recorded inventory, scope, lifecycle and
  cached intelligence. Unknown exposure is not evidence of safety.
- **Action required (`/triage`):** pages scan 25 candidate CVEs in ascending CVE
  order. Counts are page-local. Covered/ticketed candidates may leave an empty
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
  changed previews must be uploaded again. See [UI_WORKFLOWS_PLAN.md](UI_WORKFLOWS_PLAN.md).

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
use the cached binary. CSS source is `assets/css/tailwind.css`; semantic overrides
are `priv/static/assets/css/app.css`. Generated vendor assets and Tailwind output
are not committed. No Node bundler or browser CDN is required.

See [REAL_CVES.md](REAL_CVES.md) for the separate public-reference dataset workflow.
Historical development notes and verification reports are preserved in
[README_HISTORY.md](README_HISTORY.md). Their old PASS/FAIL verdicts and temporary
artifact paths do not certify the current code.
