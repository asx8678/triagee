# Workspace boundaries and remaining acceptance

## Current route and source map

[Router](../lib/triage_web/router.ex) mounts WorkspaceLive at `/`, `/workspace`
and `/timeline`. Old case, finding, guided-review, import and replay URLs redirect
through [WorkspaceRedirectController](../lib/triage_web/controllers/workspace_redirect_controller.ex).
The opt-in rollout plan is superseded; route cutover alone does not prove that
its complete acceptance catalog passed.

- [Workspace](../lib/triage/workspace.ex): `(CVE, placement ID)` targets,
  scope-local priority, exact metric/drilldown sets and history.
- [Commit](../lib/triage/workspace/commit.ex): explicit-target writes, frozen
  observed evidence, fingerprint checks, operation replay and conflicts.
- [Decisions](../lib/triage/decisions.ex): chronological scoped/global coverage;
  newer scoped work cannot be hidden by older global acceptance or resurrect it
  on expiry. Legacy global records keep their labels.
- [WorkspaceLive](../lib/triage_web/live/workspace_live.ex) and
  [components](../lib/triage_web/components/workspace_components.ex): inspector,
  selection, review, confirmation and draft handling.
- [Review actions](REVIEW_ACTIONS.md): current fixed/accepted-risk/Azure ticket
  behavior and `ADO_*` configuration. Older work labels remain readable.
- [Domain APIs](DOMAIN_API.md): cases, exceptions, timeline, imports, collection
  and replay; these are not interchangeable decision stores.

A finding is one CVE/package/version in an image; a placement is that image's
namespace/team/environment. A target includes all affected package occurrences at
the selected placement. Changed evidence invalidates pending writes, not silently
expands scope. Reference-only images and public-reference scopes are excluded from
operational totals. Active/needs/urgent count distinct CVEs; unknown-exposure
counts targets. Team totals are not additive across shared CVEs. Unassigned uses
`__unassigned__`.

Scanner suppression, absence and resolved_at are observations, not remediation.
Case assessments/exceptions retain their own frozen snapshot/revision bindings;
do not approximate them with advisory decisions. Filters and internal actor names
are not authentication. Keep the [loopback runtime](../LOCAL_RUNTIME.md) boundary.

Local fixed/risk-acceptance saves do not call external adapters. Explicit
create_ticket does: review the preview and uncertainty policy before confirming.
The separate legacy guided-review adapter uses `TRIAGE_AZURE_*`, not `ADO_*`.
Public news/research lookups described in [README](../README.md) are also network
features, not enabled background collection.

## Retained requirements and verification gaps

These requirements survive removal of execution reports. They are a release
checklist, **not a claim of current failure or fresh test success**. Implementation
has advanced since the first vertical slice; validate current source rather than
treating old PASS/FAIL counts as certification.

- Map the approved package's 90 acceptance cases and capture the exact 32-case
  canonical synthetic visual fixture. The old two-CVE browser subset did not
  satisfy this gate. Require pixel overlays/diffs and explicit visual-deviation
  approval, not just input-asset checksum validation.
- Security items **#81–90 cannot be closed without the original findings** and
  evidence addressing them. Passing general tests is not a substitute; obtain
  the original findings before declaring those requirements resolved.
- Reconcile complete legacy case/exception/decision history and Timeline Event
  log/Daily activity/coverage semantics, including IDs, scope and provenance.
  Timeline now exists in the workspace; that alone does not certify full parity.
  Consolidated settings, saved views/exports, durable drafts across reload/
  disconnect, and integration preview/partial/unknown states still need acceptance
  against approved requirements. Session loss guards are not durable storage.
- Complete physical-keyboard horizontal table scrolling, screen-reader, actual
  browser zoom/text-spacing and additional-browser testing. Earlier injected-key
  and wheel probes did not confirm horizontal scrolling. Resizing headless Chrome
  and sampled contrast checks are not WCAG certification. Legacy dirty-history
  navigation depends on a cancelable Navigation API in supported browsers.
- Verify large-data behavior and query plans/timing. Workspace presentation is
  paged but its projection hydrates matching data server-side. Move aggregation/
  pagination into bounded queries/streams before production-scale use. Commit's
  NOWAIT source-table locks can conflict with unrelated writes; preserve explicit
  retry/reconciliation. Timeline aggregates, full case detail and source hashing
  can still traverse substantial history despite bounded page results.
- Rehearse migration reconciliation/rollback on a representative copy with legacy
  history AND new work rows. Empty-database migrations do not establish this.
  Do not silently migrate an operator's working data.
- Validate a real approved legacy export before claiming real-data compatibility.
  Original pre-review source/database baselines were not captured; historical
  invariance cannot be reconstructed from later hashes. Whole-machine, all
  PostgreSQL objects/sequences and transient-write protection were not established
  by application-row hashes or simulated guard tests.
- Preserve offline-review coverage limits: real PostgreSQL/LiveView checks for
  intel cache preservation, scoped exposure/assessment aggregation, timeline
  pagination and CLI receipt persistence require owned DB verification. Later
  full-suite reports supersede the old environment's missing-psql blocker, but
  are not a fresh validation in this cleanup. Dedicated injected UI DB-unavailable/
  upload-read-failure coverage was not established by the workflow report;
  lower-level failure tests are not equivalent UI coverage.
- Shared deployment requires authentication/authorization and approval policy.
  Live Azure and administrator-owned AI-wrapper connectivity require deployment-
  owner validation; fake adapters do not establish it. Remote ticket creation and
  local commit are not a distributed transaction: reconcile unknown outcomes,
  never blindly retry. Keep broader case-workflow restructuring and complexity-
  policy changes separate from this documentation cleanup.

## Database and rollback safety

The additive [workspace migration](../priv/repo/migrations/20260919123750_extend_scoped_workspace_decisions.exs)
adds work_owner, due_on, operation_id and metadata plus operation/placement
uniqueness to the existing decision store. Do not drop these columns or revert
to readers that cannot interpret new labels after writes exist. A UI rollback
must preserve extended schema/readers and all decision history. Route cutover is
already present; production migration/release still needs representative-data
and acceptance gates above.

## Reproduce with owned resources only

The coordinator, **not parallel workers**, runs the DB wrapper. Follow
[OWNED_DB_VERIFICATION](../OWNED_DB_VERIFICATION.md), read task help and use pinned
mise with PostgreSQL CLI available. Never use shared/dev data:

```sh
# From app/, coordinator only:
./scripts/verify_owned_db.sh workspace
./scripts/verify_owned_db.sh precommit
./scripts/verify_owned_db.sh concurrency
node --test test/workspace_hooks_test.cjs test/saved_queue_filters_test.cjs
./scripts/verify_owned_db_test.sh
./scripts/verify_owned_db.sh workspace_browser
```

Browser mode creates/migrates an owned empty DB, prints its loopback URL and exits
after ten minutes with exact owned cleanup. If cached BEAM files are incompatible,
use a new temporary MIX_BUILD_PATH rather than deleting another worker's build.
Never adopt a preexisting database/process.

Connect `browser-harness-js` to an owned browser and fresh tab. Set
`globalThis.workspaceFixtureOrigin` to the printed origin and
`globalThis.workspaceEvidenceDir` to an absolute output directory. Navigate there,
then from repository root:

```sh
browser-harness-js "$(cat app/scripts/workspace_interactions.js)"
browser-harness-js "$(cat app/scripts/workspace_geometry.js)"
browser-harness-js "$(cat app/scripts/workspace_draft_guard.js)"
```

Interaction writes only the owned synthetic fixture. Geometry resizes/scrolls;
the draft probe edits/discards uncommitted drafts and disconnects its own LiveSocket.
Never target real inventory. Bring the QA tab forward for animation-frame readiness.
Inspect current selectors/actions before running historical probes; source changes
can supersede their assumptions.
