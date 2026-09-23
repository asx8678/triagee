# CVE Triage & Remediation — coding-agent implementation plan

- **Handoff version:** 1.1, 22 September 2026 — re-verified against the current working tree: every claimed-existing file path referenced in this document is present, and the Section 2.2 safety gaps are re-confirmed in current code
- **Repository:** `/Users/adam2/projects/triagee` (reported upstream: `asx8678/triage`)
- **Inspected HEAD:** `eef81e26b542325912e133059349ecf74bc2cdd0`, branch `main`, plus existing uncommitted work
- **Purpose:** implement a measurable, human-controlled CVE triage and constrained-remediation experiment in the existing Phoenix application.
- **Status:** implementation instructions, NOT a statement that the capabilities below exist or are approved for live use.

Start the coding agent with [CVE_TRIAGE_REMEDIATION_AGENT_PROMPT.md](CVE_TRIAGE_REMEDIATION_AGENT_PROMPT.md). This document is standalone; the agent must not require access to the preceding conversation.

## 1. Mandate, precedence and boundaries

Extend Phoenix LiveView, Ecto and PostgreSQL. Keep the existing inventory, authenticated workspace, scoped decisions, durable drafts, ticket recovery and historical case records. Do not rewrite in Go, run the legacy TypeScript application as a second coordinator, add a graph database, redesign navigation, or build a generic agent platform.

The original requirements audit referenced `6040e2a797efb0b5a472e9c0d788878c77c11052`. That is NOT the implementation baseline. Re-audit the actual checkout before editing. Module names and APIs proposed below do not imply that they already exist.

Precedence for this work:

1. Applicable repository/agent instructions and security restrictions remain in force. Report genuine conflicts; do not silently bypass them.
2. This handoff defines the CVE experiment scope. Retain existing functional and accessibility safeguards from older design bundles.
3. The older Go architecture is reference material for safety/integrations, not a runtime instruction.
4. Earlier AI/UI bundle rules required per-finding explicit analysis. For this experiment, separately enabled and owner-approved jobs may automatically prepare proposals. Navigation/rendering still cannot trigger analysis, source mutation, approval or publishing. Default operation remains off/manual.
5. Earlier deferral of grouping is superseded ONLY for same-dependency remediation deduplication. Do not add general cross-repository grouping or batch approval.
6. Keep local final decisions separate from authoritative external security tags. Humans apply final tags and merge PRs in the approved systems; Triage may import verified receipts. No agent security-tag, suppression, merge, deployment or exception-activation tool is permitted.

Two delivery outcomes must remain distinct:

- **Triage-only feasibility:** evidence, isolated analysis, guards, authenticated review, feedback and measurement. No claim that remediation was evaluated.
- **Full experiment:** additionally, published-version resolution, constrained updates, artifact verification, restricted PR/exception publishing and deployment reconciliation.

The proposed pilot is two repositories, one dependency ecosystem, direct-dependency compatible version bumps, one designated reviewer and a configured PR cap. These are proposed limits, not confirmed organizational facts. OS packages, unsupported transitive fixes, major upgrades and base-image propagation route to humans.

## 2. Verified baseline and work to preserve

### 2.1 Existing implementation to reuse

| Area | Current files / meaning |
|---|---|
| Active UI | `app/lib/triage_web/router.ex`, `live/workspace_live.ex`, `components/workspace_components.ex`. `/`, `/workspace`, `/timeline` mount WorkspaceLive; retired case/finding routes redirect. Paths in this row after the first are under `app/lib/triage_web/`. |
| Inventory | `app/lib/triage/inventory.ex`, `inventory/{image,image_placement,finding,finding_event}.ex`. Digest identity; observations are not verified fixes. |
| Workspace | `app/lib/triage/workspace.ex`, `workspace/{query,commit,drafts,evidence_sql,ticket_operation}.ex`; `decisions.ex`, `attention.ex`, `canonical.ex` under `app/lib/triage/`. Exact target selection, canonical hashes, SQL projections, durable operations. |
| Identity | `app/lib/triage/accounts.ex`, `accounts/principal.ex`, `app/lib/triage_web/auth.ex`. Provisioned accounts, revocable sessions and application-wide roles exist. Owner/environment filters are not permissions. |
| Legacy histories | `app/lib/triage/cases.ex`, `cases/{evidence,evidence_snapshot,review}.ex`, `exceptions.ex`. Keep distinct scopes, append-only records and synthetic provenance. These are not interchangeable with workspace decisions. |
| Intelligence / exposure | `app/lib/triage/intel.ex`, `intel/{client,config}.ex`, `exposure.ex`, `risk.ex`; refresh entry `app/lib/mix/tasks/triage.intel.ex`. |
| Collection | `app/lib/triage/collection.ex`, `collection/{client,config,crawl,normalize,query,report,transport}.ex`. Production entry disabled; test loopback transport; reports never actionable. |
| Existing external work | `app/lib/triage/azure_dev_ops.ex`, `workspace/commit.ex`, `workspace/ticket_operation.ex`. Azure work-item operations, not Git PRs. Older `review_integrations.ex` is a separate wrapper/adapter. |
| AI work in progress | `app/lib/triage/ai_triage.ex` plus WorkspaceLive handlers. Direct local CLI invocation, ephemeral results, no experiment persistence. Consolidate rather than adding a third unrelated AI path. |
| Timeline / tests | `app/lib/triage/timeline.ex` is observation history, not deployed-remediation MTTR. `.github/workflows/ci.yml` tests Triage itself, not candidate service artifacts. |

Existing dirty application work at the handoff baseline:

- Modified: `app/lib/triage/daily_timeline.ex`, `app/lib/triage_web/components/workspace_components.ex`, `app/lib/triage_web/live/workspace_live.ex`, `app/priv/static/assets/css/workspace.css`.
- Untracked: `app/lib/triage/ai_triage.ex`, `app/lib/triage_web/components/daily_components.ex`, `app/test/triage/ai_triage_test.exs`, `app/test/triage/daily_timeline_test.exs`, `app/test/triage_web/live/daily_and_ai_live_test.exs`.
- Other existing changes: `IMPLEMENTATION_REPORT.md`, `.DS_Store`, `.pi/` state. Do not reset, stage, delete, reformat or claim ownership of unrelated work.

Read current files before editing them; uncommitted code is real implementation input. Do not restore a clean HEAD version over it. Subsequent agents must re-check this list for drift.

### 2.2 Confirmed safety gaps

1. The 50-entry KEV truncation is already fixed and an 80-entry regression exists. However, catalog metadata is ignored: `count: 100` with `vulnerabilities: []` is accepted and can replace the good cache with an empty set. Refresh receipts and cache replacement are separate transactions.
2. `Cases.Evidence` remains schema v1 and excludes exposure/intelligence. Its old snapshots can remain `:current` after those inputs change.
3. Workspace draft `fingerprint` includes exposure/risk, but saved-decision `evidence_hash` excludes exposure/KEV. An authenticated acceptance can remain covered after exposure expiry, exposure escalation or a KEV addition. The SQL twin also needs correction.
4. Exposure accepts future observation times and no expiry; such evidence can remain trusted indefinitely. Some existing tests explicitly assert this unsafe behavior and must be deliberately corrected, not merely supplemented.
5. `AiTriage` uses local executable discovery, inherited process context and a weak output schema. No shell interpolation does not isolate Kiro's tools, configuration, filesystem or credentials. A synthetic whitelist suggestion for an exposed Critical passes validation.
6. `WorkspaceLive.handle_info({:ai_assessment, ...})` can accept a response after switching to another CVE. It also lacks exact target/evidence/run binding and durable run history.
7. Authenticated risk acceptance permits an empty rationale. Existing `fixed` decisions can remove active work from attention without candidate/deployment verification. Partial UI wording changes do not fix those domain semantics.
8. A placement is uniquely identified by image + namespace + owner + environment, NOT a workload/service UID. Several workloads can share it. A finding's current identity lacks ecosystem/package-location detail. Neither identifier alone proves an exact live write/approval target.

Prior review evidence: an owned-database focused run reported **121 passed, 1 skipped**, including six temporary characterization probes that reproduced gaps, not safety acceptance tests. The temporary file `app/test/triage/cve_audit_probe_test.exs` and owned database were removed. Recreate durable regressions with the desired safe expectations. No live Kiro/source/SCM/remediation run was performed. Do not treat this count as certification of a later checkout or full CI.

## 3. Owner-supplied contracts and live activation gates

Create `app/docs/experiment-requirements.md` during W00. Record each contract's owner, approved non-secret values/reference, version/hash, validation evidence and status (`unresolved`, `fixture_only`, `live_verified`). Never copy credentials into the ledger.

| Gate | Required decision/evidence | What remains blocked while unresolved |
|---|---|---|
| G01 Findings source | One approved endpoint and read-only auth method; query/filter scope; timestamp semantics; coverage/completeness and bounded-response contract. Confirm whether paging actually exists. | Live collection and live eligibility. Offline adapter tests can proceed. |
| G02 Register | Approved API/export; explicit repo/build/digest/workload/service/owner/manifest joins; immutable workload IDs; freshness and complete deployment-set semantics. | Exact live assessment/remediation targeting. |
| G03 Pilot repositories | Two exact repository IDs, branches, ecosystem, package identity rules, permitted manifest/lockfile paths, supported bump shape and owners. | Live updater targets. Do not choose npm or Mix merely from Triage's own stack. |
| G04 Kiro | Approved pinned CLI/engine/runner, auth method, data-handling policy, effective no-tools configuration and verified isolation. Read current official docs for the selected release; do not guess CLI flags. | Real model calls. A fake runner is sufficient for application development. |
| G05 Verification | Existing build/smoke/CI job IDs, scanner and DB artifact identities, supported package/platform coverage, unsuppressed baseline/candidate scans and artifact provenance. | Any real verified-fix claim. |
| G06 SCM / exceptions | Actual target provider, repository/branch policies, least-privilege publisher identity, PR/branch restrictions, exception file schema and approved activation process. Azure work items or Triage's GitHub hosting do not settle this. | Live PR publication and external exception proposals. |
| G07 Review authority | Designated provisioned human accounts, exact authorized owner/environment/repo scopes, final-tag interface/receipt verification and independent dangerous-case adjudicator. | Authoritative experiment reviews. Development Skip and legacy self-declared actors do not qualify. |
| G08 Experiment protocol | Eligibility/cohort definition, baseline method, severity/exposure/KEV strata, freshness ages/clock tolerance, effort measures, PR cap, accuracy thresholds, stop thresholds and resume authority. | Baseline/evaluated collection and proposal-mode activation. |

Missing contracts do not justify mocked production success. Implement bounded interfaces, fixtures and visible blocked states; name the missing contract in the report. Never invent URLs, registry evidence, repository mappings, reviewer identities, completion times or CI receipts.

## 4. Domain design to settle before adding workflows

### 4.1 Keep navigation, assessment and remediation identities separate

- **UI grouping:** retain CVE rows and existing `{CVE, placement_id}` navigation/draft grouping.
- **Live assessment unit:** one canonical finding occurrence in one exact deployed workload/container scope. Persist a stable target ID with finding/observation identity, package identity/location, workload UID, environment, container slot and assessed image digest. Link to the legacy finding/placement where the match is exact. A changed digest creates a new assessed artifact binding; preserve the lineage for reconciliation.
- **Register binding:** a versioned evidence record connecting that target to service, source repository, build commit, manifest/lockfile and owner. An image repository name is not a source-code repository. A stable workload identity and an immutable artifact-specific assessment binding are separate fields; a rollout cannot silently change the digest inside an existing packet.
- **Remediation identity:** repository ID + target branch + manifest + ecosystem/registry/package identity + selected target version. Base/head SHA binding is separately versioned. Attach every covered assessment unit/finding through a join; never group by CVE alone.
- **Experiment unit:** a stable vulnerability incident in a declared cohort, linking all of its artifact-specific assessment targets. Prefer an approved stable source incident ID; otherwise define an explicit workload UID + environment + container slot + canonical advisory + ecosystem/package/location incident key. Digest, package-version changes, repeated scans, retries and UI appearances do not reset first detection or inflate eligibility counts. Preserve the original clock/assignment while the incident remains open; a verified closure followed by a genuine reintroduction uses an explicitly linked new incident epoch. Record first eligibility once and retain all attempts.

A single placement shared by two workloads must yield independently bound assessments, or remain blocked if the register cannot disambiguate it. Do not duplicate legacy placements to fabricate that distinction. Do not approve all packages/workloads because one child recommendation is acceptable. Parent coverage requires every current applicable child to have a usable, in-scope outcome, and complete child membership must be established.

New per-unit reviews must not be squeezed into `Commit.save/6` if their scope is narrower than that API's full CVE/placement target. Reuse its principal, explicit-selection, revision and transaction patterns; introduce an exact-scope review context and link legacy decisions only where scope truly matches. Do not blindly dual-write conflicting decisions into the case and advisory stores.

### 4.2 Evidence packet v2

Introduce `Triage.Evidence` and a persisted immutable packet schema, with adapters for legacy case/workspace readers. Keep v1 bytes, hashes, sources, reviewers and chronology unchanged. New source-run records or a packet must never relabel old synthetic/public-reference inventory as live production data.

A v2 packet contains:

- Schema version, stable target ID(s), exact finding/package identities and affected artifact digest/platform.
- Origin (`synthetic`, `public_reference`, `live_observation`), approved scope and explicit eligibility/coverage status.
- Immutable source-run/observation references; actual source scan/observation times, fetch time and ingest time as distinct fields.
- Register revision, source repo/build commit, workload/service/container identity, deployment state and evidence of complete deployment coverage where absence is asserted.
- Exposure value, source identity, observation time, bounded validity and conflict state; applicability/configuration/impact evidence only when actually supplied.
- Immutable KEV/advisory generation and record references, source status and fetch/publication times. Registry/vendor evidence is added when available; scanner `fix` remains a hint.
- Policy/schema versions, structured missing/contradictory facts, individual validity boundaries and an effective `valid_until`.

Use the existing canonical encoder with a NEW evidence-specific hash domain. Do not bump `Triage.Canonical.version/0` globally or change the v1 case encoder: unrelated draft/ticket hashes must keep working.

Keep two explicit concepts:

1. `packet_hash`: exact immutable evidence/citation/provenance binding; approvals name the packet ID and this hash.
2. `material_hash`: normalized decision-relevant facts for change detection and bounded analysis reuse; it must not replace the exact packet binding or the clock check.

Expose one decision-time contract, for example `Triage.Evidence.usability(packet, action, now)`, returning usable or structured blockers. It checks current authoritative local source/register/intel state, exact target/scope, material changes and the packet's own validity against the supplied clock. No remote fetch inside this check. Do not trust a stale asynchronously refreshed projection as the authorization check.

Required states include missing, stale, incomplete, contradictory, future_dated, out_of_scope, source_missing and legacy_unverified. A current positive KEV match retains conservative escalation even if a refresh fails; absence from missing/stale/incomplete intelligence is unknown, not not-exploited.

Rules:

- New exposure, relevant advisory/KEV or mapping facts invalidate the affected recommendation/outcome's LOCAL usability; unrelated siblings or unrelated catalog entries need not. This flags human re-review, not automatic revocation or mutation of an external security tag/exception.
- Expiry invalidates usability even if no stored bytes change. For new v2 time boundaries use `now >= valid_until`; preserve old explicit inclusive/exclusive semantics.
- A repeated same-material observation while the original packet is still valid need not create another analysis or human task. It cannot silently extend an expired packet, human exception lifetime or approval. Reuse of raw analysis for a new packet requires a new recorded validation/citation binding; never rewrite the original run/review.
- A partial/unfresh source permits urgent human investigation, never an actionable dismissal, automatic bump or a verified absence claim.
- Source-specific ages and clock tolerance are versioned policy. Production dismissal-supporting evidence without an approved bounded-age policy is blocked. Test constants are not organizational approvals.
- Freeze one `now` per operation/page and thread it through SQL, Exposure, Evidence, Decisions and Attention. Do not let Attention independently call the clock during a frozen-time evaluation.

All consumers must agree: Cases compatibility, Workspace.targets, Workspace.Query/EvidenceSQL, Attention, review submission, analysis reuse, proposal readiness and exception projections. Implement parity tests; do not materialize the whole estate or do network work while rendering to simplify the implementation.

### 4.3 Separate disposition, priority, action and outcome

`Risk` remains deterministic review priority; `Attention` remains queue/work state. Neither is an agent disposition. The new model schema has no authoritative numeric danger/confidence score.

The strict model payload is versioned, bounded and contains:

```json
{
  "schema_version": 1,
  "target_id": "server-issued-target-id",
  "packet_hash": "server-issued-packet-hash",
  "disposition": "needs_human",
  "rationale": "Required deployment mapping is missing.",
  "evidence_ids": ["server-issued-evidence-id"],
  "missing_facts": ["manifest mapping"],
  "contradictions": [],
  "next_action": "investigate",
  "exception_kind": null
}
```

Allowed dispositions: `real_threat`, `whitelist_candidate`, `needs_human`.
Allowed actions: `investigate`, `prepare_fix`, `prepare_exception`, `request_verification`.
`exception_kind`: null except for a candidate; then `non_applicability` or `risk_acceptance`.

Reject extra/unknown keys, invalid enum combinations, unbounded text/collections, fabricated evidence IDs, scope expansion and missing required bindings. Parse only the selected runner's documented final-response event, not an arbitrary greedy `{...}` substring. Transport event parsing and recommendation JSON validation are separate layers.

A candidate is not an exception approval. Non-applicability requires an approved structured justification backed by relevant positive evidence. Risk acceptance means an applicable risk an authorized human may accept under supplied policy, with owner, rationale and expiry; the model cannot invent risk appetite. Internal-only exposure is insufficient for either outcome by itself.

Deterministic guards block whitelist publication for KEV, exposed Critical, stale/unknown scope/evidence, unsupported non-applicability, internal-only justification, missing owner/expiry/policy or contradictory evidence. Route to human review at conservative urgency. Evidence IDs existing in a packet are not proof that they support an assertion: implement allowlisted justification checks; unsupported semantic claims abstain.

`real_threat` does not itself authorize a dependency bump. Fix preparation additionally requires a complete register/plan/version contract. Unsupported OS/transitive cases can be real threats and still require human remediation.

### 4.4 Records and state transitions

Use additive migrations with typed columns/foreign keys for identity, status, versions, clocks and uniqueness. JSON is for bounded payloads, not a substitute for relational identity or authorization. Proposed record groups (the implementing agent may combine closely related tables with a documented invariant-preserving rationale):

| Record group | Minimum retained information |
|---|---|
| Intelligence generations / refresh attempts | Source/version/content hash, declared/parsed/unique counts, times, completeness, failure, successful-generation pointer. Old referenced content retained. |
| Source runs / observations | Scope/query version, scan identity/time, fetch/ingest times, pages or explicit no-paging contract, counts, budgets, completeness, source finding identity and immutable digest. |
| Register revisions / deployment bindings / assessment targets | Explicit graph edges, workload identity, package type/location, artifact/repo/build/manifest links, validity, ambiguity and provenance. |
| Evidence packets / validation receipts | Exact packet hash, material hash, source refs, validity/blockers and recorded revalidation where applicable. |
| Agent runs / recommendations | Target, packet, trigger/cohort, pinned runner/model/prompt/schema/policy versions, start/end, attempt lineage, bounded raw output/hash, errors, guard result, tokens/cost if supplied (unknown is null). |
| Human reviews / external decision receipts | Exact recommendation/target/packet, principal/session provenance, right/wrong/unsure, chosen disposition, reason/correction, active effort, upstream-fix confirmation; separately verified external tag/merge actor/receipt. |
| Remediation plans / candidate attempts / verification runs | Repo/base/head, exact dependency and allowed paths/hashes, latest and selected fixed version, per-finding coverage, artifact/SBOM/scan/test/CI receipts and readiness blockers. |
| Proposals / proposal findings / publication attempts | Unique remediation identity, immutable candidate versions, draft/ready state, remote ID/marker, head binding, uncertainty/reconciliation and per-finding association. |
| Experiment cohorts / events / adjudications / safety control | Eligibility/assignment, failed and blocked attempts, effort intervals, lifecycle milestones, adjudicator, incident/category pause, generation and human resume audit. |

Immutable facts/history use append-only storage constraints, extending the existing pattern where appropriate. Operational job/claim rows may transition only through guarded allowed states. A run's final receipt is immutable; retries are new attempts, not overwritten failures. Store bounded sensitive payloads with access control and retention rules; logs must not include credentials or unrestricted source/model text. A truncated raw-output capture is marked truncated, never represented as the complete response.

Suggested transitions:

- Analysis: queued -> running -> succeeded / invalid / failed / timed_out / cancelled. Successful parsing still requires a separately recorded guard result.
- Recommendation: human_review / fix_preparation_eligible / exception_preparation_eligible / blocked; usability may subsequently become stale or paused without rewriting the original suggestion.
- Candidate: planned -> prepared -> built -> verification_passed / failed / incomplete. A later head invalidates readiness, not historical verification receipts.
- PR: claimed -> publishing -> remote_created / outcome_unknown -> reconciled; remote draft or ready status is explicit. An unverified draft is never called fixed.
- Remediation lifecycle: first_detected -> proposed -> candidate_verified -> human_merged -> deployment_observed -> remediation_verified. Keep missing stages unknown, and record when the deployed digest differs from the candidate and needs its own verification.
- Exception: proposed -> PR_open -> human_merged -> externally_activated (only if observed in the approved existing process), expired / revalidation_required. Triage performs no activation.

## 5. Execution and credential boundaries

Use one Phoenix application and the existing PostgreSQL database for durable coordination. Preferred job implementation: **Oban**, pinned to a compatible release in `app/mix.exs` / `app/mix.lock`, with a small fixed worker set and concurrency one per pilot stage initially. It is an application library, not a second orchestration platform. If that dependency is prohibited, record the conflict and obtain a durable-job decision; do not silently substitute detached Tasks, ETS or an in-memory queue.

Job delivery is at-least-once. Business uniqueness belongs in domain storage, not only a job queue option. Persist intent before external effects; do not hold DB/table locks during HTTP/model/build/SCM operations. Supervised workers may poll or invoke existing isolated CI jobs. Manual CLI/request paths come before scheduled polling.

| Role | Allowed | Must not receive |
|---|---|---|
| Source/register reader | Exact approved read-only queries; bounded responses | SCM write, source mutation or model-directed destinations |
| Kiro analyst | Minimal staged evidence and model auth only; approved model-service egress | Production/DB/SCM tokens, host home/config, writable repo, inherited MCP/tools/powers, arbitrary network or shell capabilities |
| Updater | Exact checkout/plan; approved registry access | Production/model/publisher credentials; arbitrary patch/command input |
| Verifier | Candidate build and unsuppressed scan/test execution in approved isolation | Publisher/merge privileges; authority to edit scanner/CI policy |
| Publisher | Approved proposal branch/file/PR operations and remote reconciliation | Security source mutation, suppression activation, merge, branch-policy bypass or arbitrary repository paths |
| Human reviewer | Assigned scopes; explicit review/merge in authorized tools | Authority inferred from a submitted name or a model suggestion |

Do not execute untrusted repository/package scripts with a read token or other secret still present. Materialize allowed dependencies using the approved credential boundary; strip credentials before untrusted scripts/build steps. Do not place SCM secrets in Git remotes, artifacts or logs. Build isolation is required even if the model has no shell.

For Kiro: pin runner image/binary/engine, use a disposable unprivileged sandbox with a read-only evidence mount, no host home/workspace/config mount, allowlisted environment, explicit disabled tool inheritance and only approved model egress. Bound input/output/time/process count/resources; cancellation destroys the entire sandbox/job, including grandchildren. A direct Port plus `pkill -P` is not that guarantee. Use the existing CI/runner facility approved in G04; no unrestricted host fallback.

Proposed runtime entries, to be implemented and documented with startup validation:

| Entry | Default / meaning |
|---|---|
| `TRIAGE_EXPERIMENT_MODE` | `off`; only `off`, `shadow`, `proposal`. Shadow may collect/analyze with approved readers but never publishes PRs/actionable exceptions. |
| `TRIAGE_COLLECTION_ENABLED` | false; separate approved live transport, never enables the test loopback transport in production. |
| `TRIAGE_POLLING_ENABLED` | false; only after manual ingestion validation. |
| `TRIAGE_ANALYSIS_ENABLED` | false; executable presence alone never enables analysis. |
| `TRIAGE_PR_PUBLISHING_ENABLED` | false; requires proposal mode, verified contracts, readiness and unpaused control. |

Endpoint, repo, ecosystem, scope, required checks, runner version and credential references are administrator-owned validated configuration, never browser/model fields. Preserve and document existing `ADO_*`, `TRIAGE_AZURE_*` and legacy AI settings; do not silently repurpose them for new credentials. Retain loopback-only listening and production account restrictions.

Persistent safety controls must exist before recommendations are published. Check a stored global/category pause and generation when creating work AND immediately before publication/retry. Missing/unreadable safety state fails closed. Pause preserves findings, source ingestion, existing scanner alerts, human investigation and auditable backlog. Confirmed unsafe raw whitelist suggestions trigger the same stop policy even when blocked by guards. Record the incident and pause atomically before another queued publication is eligible. Already-issued external requests may finish: reconcile and flag them; do not promise a cross-system atomic cancellation. Resume requires the designated human authority and a reason; worker restart never resumes automatically.

## 6. Work packages and dependency order

A package is a reviewable milestone, not permission to combine thousands of lines into one PR. W01 has explicit sub-checkpoints. Implement one coherent slice end to end, including migration/readers/UI/tests where needed. New filenames are proposed; keep existing contexts where semantics fit.

```text
W00 -> W01a -> W01b -> W01c
                         |-> W02 (source) --|
                         |-> W03 (register)|-> live evidence qualification
                         |-> W04 (records, guards, jobs, metrics, pause) -> W05 (Kiro + reviews)
W03 + W04 -> W06 (versions/updater) -> W07 (verifier)
W05 + W07 -> W08 (publisher/exceptions)
W02 + W03 + W05 + W08 -> W09 (reconciliation/report/controlled pilot)
```

W03/W04 and isolated version/verifier fixture development need not wait for live credentials. Live activation depends on the G01-G08 gates, regardless of code dependency readiness. Baseline instrumentation begins in W04, not W09. The full pilot cannot start while its verifier/publisher or report is still hypothetical.

### W00 — Reconcile checkout and freeze the implementation ledger

**Modify/add:** `app/docs/experiment-requirements.md`; use a new experiment-specific progress log, not a blanket rewrite of `IMPLEMENTATION_REPORT.md`.

- Read `app/AGENTS.md`, `app/README.md`, `app/OWNED_DB_VERIFICATION.md`, `app/docs/WORKSPACE.md`, relevant domain/runtime/integration docs and current migrations.
- Record actual HEAD/dirty paths, existing APIs and authority boundaries. Resolve instruction conflicts and G01-G08 statuses.
- Trace read -> evidence -> analysis -> review -> queue coverage -> external effect. Confirm current symbols/config/routes before proposing replacements.
- Turn Section 7 into an acceptance ledger with columns: ID, package, current behavior, permanent test path/name, execution evidence, live-contract evidence, status. Initial statuses are unresolved/partial, not passed from this document.
- Select the first slice W01a and name the exact existing tests to retain/update. Do not start unrelated UI redesign, deployment, historical export migration or live provider setup.

**Exit:** reproducible scope/source map, protected worktree list and ledger; blockers named without preventing independent offline work.

### W01a — Contain the current AI/decision hazards

**Modify:** `app/lib/triage/ai_triage.ex`, `app/lib/triage_web/live/workspace_live.ex`, `app/lib/triage_web/components/workspace_components.ex`, `app/lib/triage/workspace/commit.ex`, `app/lib/triage/decisions.ex`, `app/lib/triage/attention.ex`, matching SQL readers and runtime config as required.

- Make analysis explicitly disabled by default; remove automatic enablement from `System.find_executable`. Until W04/W05, no real CLI execution qualifies as experiment-safe. Preserve a fake-runner seam for tests and honest manual/unconfigured UI behavior.
- Match asynchronous delivery to server-issued request ID, focused target set, packet/fingerprint binding and current authorization. Discard stale/out-of-order/after-navigation responses; never overwrite user-edited drafts. Bound duplicate triggers and cancel superseded work. Durable jobs replace transient state in W04/W05.
- Require a nonblank rationale for new risk acceptance at context level, not just in HEEx. Preserve original historical values; do not manufacture missing justifications.
- Treat unverified `fixed` as reported remediation requiring verification attention, not resolution. Preserve observation rows and decision chronology. Derive the verification-needed reason read-only; do not create jobs or decisions on navigation. If a human requests verification, use the compatible existing work action and recognize current work rather than generating duplicates. Keep an urgent risk reason visible independently of workflow status.
- New model safety boundaries must not be implemented solely as prompt wording or disabled buttons. Do not add the new whitelist-candidate publishing route until W04's guards and evidence contract exist.

**Permanent tests:** extend `ai_triage_test.exs`, `daily_and_ai_live_test.exs`, `workspace_test.exs`, `workspace_query_test.exs`, `auth_test.exs` and relevant LiveView/attention tests. Recreate the stale cross-CVE response probe as a failing-then-fixed regression. Keep daily-feed work intact.

**Exit:** explicit-off configuration, stale/out-of-order result rejection, nonblank-rationale validation and truthful reported-fix attention have permanent tests; manual review remains usable and no real provider was invoked. Record the corresponding A11-A13/A24 subchecks as partial where later packages own remaining conditions. A07's guarded-and-recorded raw-output acceptance is NOT complete merely because analysis is disabled. Stop for a coherent patch checkpoint before W01b.

### W01b — Immutable intelligence generations and bounded exposure

**Modify:** `app/lib/triage/intel.ex`, `intel/client.ex`, `intel/config.ex`, `app/lib/mix/tasks/triage.intel.ex`, `app/lib/triage/exposure.ex`; corresponding tests and additive migrations.

- Split KEV catalog-level validation from per-CVE NVD response validation. Validate documented catalog metadata, declared/actual unique counts, dates and duplicate/invalid entries; reject incomplete/count-mismatched or unverified empty KEV success. A genuinely empty per-CVE NVD result is not the same contract.
- Retain the full authoritative KEV set; limit only UI pagination. Keep response/streaming bounds and fail rather than truncate. Retain previous valid generations after failed/stale/incomplete refresh.
- Introduce immutable generation storage and a current-success pointer. Store row/content hashes, counts/completeness and source/version/times. Update successful generation + receipt atomically; failures append receipts without moving the pointer. Preserve referenced historical content. Concurrent/older refresh completion cannot replace a newer valid generation.
- Preserve existing `cached_kev`, `kev_index`, receipt and UI call sites through explicit compatible readers. Unproven pre-migration rows are legacy, not retroactively certified complete catalogs.
- Add source-specific exposure policy and structured current evidence, validating observation times, expiry ordering, maximum ages and approved clock tolerance. Unknown source policy cannot support dismissal. Equal-time conflicting assertions cannot be silently resolved by highest database ID. If Impact is admitted to decision evidence, apply equivalent provenance/freshness constraints there.
- Update old tests that intentionally trusted future/nil-expiry evidence. Include the 51st/80th entry flowing through cache lookup and Risk, not only parsing.

**Exit:** A01-A03, A08; no false complete/negative exploitation assertion; original cache/history and offline behavior preserved where safe.

### W01c — Shared evidence v2 and current-usability projections

**Modify:** `app/lib/triage/cases.ex`, `cases/{evidence,evidence_snapshot}.ex`, `workspace.ex`, `workspace/{query,evidence_sql,commit}.ex`, `decisions.ex`, `attention.ex`, exception/read projections and matching tests. Add `app/lib/triage/evidence.ex`, `evidence/packet.ex` and narrowly scoped builder/policy helpers.

- Implement Section 4.2, initially with synthetic fixtures and explicit unavailable live edges. Capture available exposure/intel evidence with immutable provenance; missing run/register fields remain blockers, not fabricated data.
- New packets have their own schema/hash domains. Preserve v1 histories and readers. Old nil/legacy hashes are not valid production approvals; expose legacy_unverified/review-needed rather than promoting them.
- Fix the saved acceptance gap in BOTH application and SQL coverage. A change/expiry must affect current usability even when no review form is open. Protect source-missing/out-of-scope error ordering and readable history.
- Thread one clock through projections and revalidation. Preserve chronological supersession: expiry of a newer decision never revives an older acceptance.
- Writes re-check principal, complete selected target membership, material revisions, validity and operation identity in a transaction. Ensure concurrent source/intel/exposure changes participate in the locking/revision protocol; expanding existing locks without testing is not sufficient. No remote effect under locks.
- Do not mark packets live eligible until W02/W03 supply actual verified provenance. Avoid unbounded hydration/N+1 evidence reads; preserve bounded page/count/drilldown parity.

**Exit:** A04-A06, A09-A10, A25. Prove the previously reproduced saved-acceptance gap is closed and legacy rows are byte/identity stable through upgrade/restart.

### W02 — Approved live collection and observation ingestion

**Reuse:** `app/lib/triage/collection/` query/crawl/normalization and `app/lib/triage/http.ex` where their verified contracts fit. Add a separate live transport/entry, `app/lib/triage/observations.ex`, source-run/observation schemas and a bounded `mix triage.collect` task.

- Keep the compile-time test-loopback/offline entry contract unchanged. No generic arbitrary-host or arbitrary-transport escape hatch.
- Implement G01's exact read-only request vocabulary. GraphQL may use HTTP POST for reads; test absence of mutation operations, not an inaccurate GET-only rule. No browser credential scraping, redirects with credentials or model-supplied URLs/queries.
- Enforce TLS/endpoint restrictions, time/request/byte/depth bounds, cancellation, credential redaction and bounded read retries. Current Crawl has two phases and no pagination contract; implement actual paging only if supplied, otherwise record its absence and coverage limitations honestly.
- Persist scan/source timestamps separately from collection and ingestion times. An observational `lastClusterScan` marker is not automatically a complete scan ID or freshness proof.
- Idempotency key: source + scope + verified scan identity, or an explicitly documented content-identity fallback when the source lacks one; do not fabricate source scan provenance. Duplicate/reordered runs cannot rewind current state or create duplicate eligibility/work.
- Store partial observations with blockers; admit authorized new positive findings to human attention. Quarantine wrong-scope data. Partial/error runs never retire workloads, resolve findings or infer absence. Complete-source disappearance remains an observation, not remediation.
- Use one manually invoked run first. Add serialized scheduled polling only after manual live validation and W04's durable-job foundation, separately enabled. Source ingestion and scanner alerts remain independent of model failures/pauses.

**Exit:** A14-A16, A32; replay/concurrency tests plus G01 owner evidence for live enablement. No source mutation capability exists.

### W03 — Register joins and exact live evidence

**Add:** `app/lib/triage/register.ex`, `register/{adapter,validation}.ex`, versioned register/deployment/target schemas; extend `Triage.Evidence` and workspace drilldowns.

- Implement G02/G03 explicit joins using source IDs, repository IDs, build commit and immutable digest, not name similarity. Bind workload UID/service/container, owner/env, manifest/lockfile and package ecosystem/location.
- Distinguish direct application dependencies, transitive dependencies, OS packages and inherited base-image packages. Only the approved direct-dependency case qualifies for automated updating.
- Model multiple workloads sharing a placement, tag reuse, moving ownership, one digest deployed in multiple environments, conflicting mappings and missing edges. Missing namespace/workload identity is not a guessed wildcard scope.
- Require complete, fresh register deployment coverage for a not-deployed assertion. `placement.active == false` or scanner absence alone is insufficient.
- Build live v2 packets with exact finding-to-workload targets and authorized evidence refs. UI rows may aggregate, but per-target decisions and metrics must remain separable. Match current source/register revisions at action time.

**Exit:** A17-A18, A25; correct exact joins for both approved pilot repositories when available. Ambiguous cases are visibly human-only, with no write destination.

### W04 — Durable recommendations, deterministic policy, measurement and pause

**Add:** `app/lib/triage/{analysis,recommendations,policy,experiments,safety_controls}.ex`, fixed worker modules, Oban configuration/migration, schemas from Section 4.4 and a strict versioned recommendation JSON contract. No real model required yet.

- Implement pure schema/citation/guard validation over packets with fake analyst outputs. Guard result is separate from raw disposition and priority; preserve unsafe raw suggestions and parse failures as measured attempts.
- Persist evidence-bound run intent before enqueueing, attempts/final results, recommendation versions and invalidation. A canonical analysis key binds target/material evidence and runner/model/prompt/policy versions; enforce uniqueness in storage. Exact packet/citation checks still apply on reuse.
- Implement bounded concurrency/retry/deadline/cancellation and recovery after restart. Do not rerun completed work or suppress failed attempts from denominators.
- Implement global/category pause, incident and authorized resume audit now. Both recommendation publication and later PR publisher call the same fail-closed control. Every retried/restarted job checks it. Paused categories retain visible backlog.
- Create cohort/eligibility, manual/rules-only/AI-assisted mode, effort, review-feedback and lifecycle-event records before baseline data collection. Capture human review and correction effort, not only elapsed model time.
- Add a minimal export/CLI showing complete stored denominators, invalid/blocked runs and pause status. A polished scorecard may wait; usable baseline instrumentation cannot.

**Exit:** A19-A23, A26-A27; fake runner positive/negative fixtures pass and restart tests prove pause/idempotency. No source/SCM writer is granted to the model role.

### W05 — Isolated Kiro and authenticated evidence-bound review

**Add/reuse:** `app/lib/triage/agents/kiro.ex` as the approved runner adapter; consolidate the relevant `ai_triage.ex` and `review_integrations.ex` analysis paths behind the new context. Extend WorkspaceLive/shared components, Accounts scope authorization and an exact-scope review API.

- Implement the runner contract in Section 5 against G04's pinned documentation/configuration. Use a fake runner in default tests; actual isolation tests must inspect denied capabilities, inherited configuration, whole-process teardown and credential separation, not just JSON output.
- A model receives one exact assessment unit per request initially. If transport batching is later used, require a result and independent guard/review for every expected unit; missing results are not blanket approval.
- Display exact workload/artifact/package, source scope/age/completeness, exposure provenance, KEV state, advisory/registry evidence when available, missing facts and guard explanations beside the recommendation. Keep manually entered rationale separate; no auto-selected mutation targets.
- Implement unconfigured/queued/running/cancelled/timeout/invalid/stale/paused/usable states and durable reconnect/retry behavior. Revalidate authorization and scope on enqueue, retrieval and submission, including changed roles while a job runs.
- Human feedback is right/wrong/unsure plus corrected disposition/reason, optional uncertainty, active effort and an independently stored adjudication. Every final review names recommendation ID, exact target, packet ID/hash, expected revision and policy; stale forms fail closed.
- Do not let the analyst service identity call human-decision APIs. Reject development Skip/legacy self-declared identity as authoritative pilot approval without disabling unrelated local demo behavior. Verify external receipts by the approved authenticated provider/read path; arbitrary form/JSON actor claims are not receipts.
- Record upstream-fix confirmation as an explicit reviewer item for fix proposals. Final security-tag application remains in the existing authorized interface; local review and external tag receipt are distinct events.

**Exit:** A07, A11-A13, A19-A23, A28. Live Kiro requires G04; authoritative reviews require G07/G08. Triage-only readiness also needs live G01/G02 evidence and no claims about remediation effectiveness.

### W06 — Published fixed versions and deterministic constrained updater

**Add:** `app/lib/triage/remediation/{plan,versions,registry,updater}.ex`, version/plan/candidate records and one ecosystem-specific isolated updater.

- Resolve correct package ecosystem, registry, aliases, platform/distribution and advisory identity. Record latest published version separately from the selected supported compatible fixed version. Publication plus applicable advisory/vendor affected/fixed evidence must support the target; scanner strings, search results and LLM claims alone do not.
- Use ecosystem-correct version/range rules, including vendor backports where supported. Unsupported vendor/OS/transitive cases abstain; do not approximate every ecosystem with semver.
- Plan fields: repository ID, branch, base SHA, manifest/lockfile paths and hashes, exact direct dependency/current/target versions, associated assessment units/CVEs, registry/advisory evidence IDs, policy and validity.
- Validate a plan independently of its producer. No model-written patches, shell commands, registry overrides, path traversal, symlink escapes, CI/workflow/scanner/policy edits or unrelated source changes.
- Run the fixed package tooling in isolation, with lifecycle scripts disabled where possible and an approved dependency-fetch boundary. Allow only the intended manifest edit and package-manager-required lockfile dependency closure; unrelated direct-dependency changes are not allowed. Check final diff and resolved dependency, not only file names.
- A moved base commit or changed manifest/lockfile hash invalidates the plan. Do not silently rebase it or refresh the approved input under the same plan identity.

**Exit:** A29-A31; safe direct bump produces the intended resolved lockfile diff, unsafe targets fail before a fix claim. No publisher/production credentials in this runner. Live enablement needs G03 and registry/advisory contract evidence.

### W07 — Artifact verifier before review-ready fixes

**Add:** `app/lib/triage/remediation/verifier.ex`, verification run/receipt schemas and one adapter to G05's existing build/scan/smoke/CI system. These are not the repository's historical `app/PR7_*` synthetic-replay features.

- Build the recorded candidate head in isolation; retain source-to-build-to-artifact provenance and exact digest/platform. Inspect the resolved dependency/SBOM, not a changed manifest string.
- Obtain complete unsuppressed baseline and candidate scans using the same pinned scanner and vulnerability DB artifacts, relevant configuration and package coverage. Retain content hashes, versions, timestamps and completeness metadata. Failed/empty/truncated scans are not implicitly clean.
- Establish that each target finding is represented in the baseline at the correct package/location/platform, and absent from the correct candidate consistently with the claimed fixed-version evidence. A no-op bump or ignore/exclusion-only disappearance fails.
- Compare normalized vulnerability identities/aliases plus package/location/platform, not just counts, to reject newly introduced High/Critical findings. An unrelated pre-existing High is not automatically new.
- Require explicit passed states for every configured smoke/CI check at the exact head SHA. Skipped, neutral, unsupported, pending, missing or failed required checks do not pass. Verify callback/receipt origin against the approved provider; never trust model-supplied results.
- Keep per-finding verification when one update covers multiple CVEs. Missing verification for one covered CVE prevents claiming that CVE fixed.
- Candidate verified is not merged or deployed. A different merge/rebuild artifact needs fresh provenance and verification before deployment closure.

**Exit:** A33-A37; all unsafe fixtures fail and a valid positive control passes. Candidate readiness cannot be set by Triage's own CI or publisher alone.

### W08 — Restricted fix/exception PRs and durable deduplication

**Add:** `app/lib/triage/{scm,proposals}.ex`, a single approved SCM adapter and proposal/publication schemas. Extend exception presentation/domain contracts without converting legacy local exceptions into externally activated ones.

- Reuse the durable intent/marker/reconciliation pattern in `Workspace.TicketOperation`, not its work-item API as a Git PR adapter. Persist business identity and exact candidate payload before any network request; enforce unique remediation identities and bounded volume in storage.
- On retry, concurrent request, timeout or interrupted publication, find/reconcile the persisted remote marker/branch/PR. No blind second create after an uncertain outcome. Enforce one active intent for a dependency scope when target-version changes would otherwise create competing proposals; resolve supersession explicitly.
- Prefer verification before a review-ready PR. If the existing CI requires a PR, create only an explicitly unverified draft for the exact candidate; mark ready only after all required receipts pass. Mode/contract/pause checks apply to draft creation as well as readiness.
- Publish selected/latest version distinction, release/registry/advisory links, exact allowed diff, base/head, artifact/SBOM/scan/test/CI receipts, per-CVE coverage and limitations. Resolve evidence links server-side; do not accept arbitrary model HTML/URLs as trusted evidence.
- Publisher cannot merge or bypass protected-branch requirements. A new commit invalidates old readiness/approval binding and requires current verification. Keep PR sync and merge observation read-only after creation except explicitly allowlisted proposal updates.
- Generate an exception proposal file only in the approved exception repository/path/schema: exact CVE/advisory/package/asset/workload/environment, kind (non-applicability versus risk acceptance), justification, evidence hash, owner/reviewer requirements, expiry and revalidation conditions. No wildcard CVE suppression, automatic renewal or activation on save/recommendation/PR creation.
- Human merge and the existing approved exception process govern activation; observe that process read-only if available. A merged proposal alone is not proof of activation. If the existing whitelist format supports only global CVE entries and cannot represent required scope/expiry, block this integration pending an approved compatible schema/process; do not drop fields or pretend a sidecar is enforced. Revalidate evidence before readiness; later exposure changes flag human review, not automatic source mutation.

**Exit:** A38-A42; repeated/concurrent publication converges, unsafe writes denied, unknown outcomes survive restart, draft/readiness labels truthful. Live publication requires G01-G08 and the explicit proposal-mode configuration.

### W09 — Deployment reconciliation, scorecard and controlled pilot

**Extend:** `Triage.Experiments`, reporting/export CLI and workspace evidence/history; add read-only deployment reconciliation using W03's register and approved scan/build receipts. Do not add a new dashboard platform.

- Record source detection, first eligibility, proposal, candidate verification, PR, human review/merge, deployment observation and verified-remediation events independently. Never use import/fetch time as an invented historical detection time.
- Closure requires the actual affected workload/container running the verified replacement artifact, with evidence adequate for that exact digest/platform. If merge CI rebuilt a different artifact, verify it rather than assuming equivalence. Mixed/partial rollout closes only the observed remediated units.
- Missing/partial/stale deployment data is unknown, not closure; scanner disappearance, ticket closure and human `fixed` claims remain separate dimensions. Preserve still-open units in reports.
- Export stored counts/denominators, disposition confusion matrix, unsafe raw versus published suggestions, blocked/failed/unsupported/unsure cases, effort distribution, PR usefulness/duplication, verifier outcomes and lifecycle intervals.
- Require reproducible report fixtures and pilot protocol signoff before collecting the baseline. Keep independent adjudication for dangerous/disputed cases; agreement is not automatically ground truth.
- Run the pilot sequence in Section 9 only after the appropriate entry gates. Provide go/no-go/inconclusive separately for triage, PR preparation, verifier and deployed remediation. Do not substitute earlier milestones for unobserved production MTTR.

**Exit:** A23, A26-A28, A43-A44 plus documented live-contract evidence. No auto-tagging, auto-whitelisting or auto-merge authorization follows from a successful pilot.

## 7. Required acceptance ledger and fixture matrix

Implement permanent synthetic fixtures under `app/test/fixtures/experiment/` where useful, and focused ExUnit suites in `app/test/triage/` / `app/test/triage_web/`. These are desired results, not current pass claims. Each ID needs an executable test/probe or an explicitly owner-run live-contract check, not merely a documentation assertion. Split multi-condition IDs into named subchecks in the working ledger; mark an ID passed only when every applicable condition is evidenced. Also track each proposed runtime default and invalid configuration combination with a test; the first slice must prove that executable presence and page navigation cannot enable real analysis.

| ID | Fixture / check | Required result | Owner package |
|---|---|---|---|
| A01 | KEV entry 51/80 through parser -> persisted cache -> Risk | Recognized and conservatively escalated; UI limits do not truncate truth | W01b |
| A02 | KEV declared-count mismatch, invalid/duplicate row, truncated response or suspicious unverified empty feed | Refresh fails/incomplete; prior valid generation remains; no false successful complete receipt | W01b |
| A03 | Refresh failure, older concurrent refresh completing last, generation restart/read | Last valid current generation and cited history retained atomically | W01b |
| A04 | Exposure internal -> internet-exposed after recommendation/acceptance | Old outcome unusable; affected target gets review attention in SQL and Elixir | W01c |
| A05 | New KEV/advisory fact or deployment/repo/manifest mapping change | Affected binding invalidated; no guessed destination or stale approval | W01c/W03 |
| A06 | Clock reaches validity without any hash change | Usability fails at exact new boundary; no older acceptance resurrection | W01c |
| A07 | Internal-only Critical or exposed Critical fake whitelist suggestion | Guard blocks usable whitelist publication; raw output counted, urgent human route | W04/W05 |
| A08 | Future-dated, no-policy/no-bounded-age, expired or conflicting exposure | Explicit invalid/unknown/conflicting state, no dismissal support | W01b |
| A09 | v1/legacy/nil evidence hashes across migration/restart | History unchanged and readable; not retroactively live/verified | W01c |
| A10 | Source missing/out of scope; unrelated sibling changes; identical fresh observations | Preserve conservative scope behavior; no unrelated scope expansion or needless repeated analysis | W01c |
| A11 | Forged actor, legacy/Skip identity, analyst identity, revoked or wrong-scope principal | No authoritative pilot approval; account/scope rechecked server-side | W01a/W05 |
| A12 | Old/out-of-order AI response after CVE/target/evidence change or disconnect | Not shown as a current usable suggestion; manual draft preserved | W01a/W05 |
| A13 | Empty acceptance rationale; one approved child inside multi-package/workload parent | Save rejected / no blanket parent approval | W01a/W03/W05 |
| A14 | Authorized new positive finding from approved run | Queued once with honest source/scan/ingest provenance | W02 |
| A15 | Partial/stale/wrong-scope run, missing page or detail budget cutoff | No retirement/resolution/dismissal; authorized positives remain human-visible | W02 |
| A16 | Identical/reordered/concurrent ingestion | No duplicate eligibility/work; no time rewind or fabricated history | W02 |
| A17 | Exact joins in two pilot repos, shared placement with two workloads, reused image tag | Separate correct digest/workload/package/repo bindings | W03 |
| A18 | Missing/ambiguous edges or unsupported transitive/OS/base-image package | Human-only route; no guessed write target or not-deployed assertion | W03 |
| A19 | Malformed/extra output fields, nonexistent or irrelevant citations, unsupported applicability | Invalid/blocked recorded; no safe fallback or schema-only approval | W04/W05 |
| A20 | Injection text in finding/register/advisory/repository content | No unauthorized runner tool, network, file, credential or SCM effect; sandbox negative tests witness denial | W05 |
| A21 | Timeout, oversized output, grandchildren, cancellation, repeated Analyze | Whole sandbox/job bounded; durable terminal attempt; no orphan/unbounded work | W04/W05 |
| A22 | Crash/retry before and after storing analysis/guard | Idempotent intent; attempts retained; raw unsafe output not lost/relabelled safe | W04 |
| A23 | Confirmed unsafe raw/published whitelist; paused category; restart and queued retry | Incident/pause durable; subsequent publication denied; scanners/human backlog remain available | W04/W09 |
| A24 | Legacy/new reported fixed, closed ticket or scanner disappearance | Not verified remediation; verification-needed work remains correctly represented | W01a/W09 |
| A25 | Concurrent source update/review, selected-target cardinality, SQL/Elixir page counts and clock | Stale write refused; exact authorized membership and queue parity; bounded reads | W01c/W03 |
| A26 | Baseline/rules-only/AI-assisted cohorts; fails, blocks, unsure and retries | Stored reproducible denominators; no cherry-picking or duplicate units | W04/W09 |
| A27 | Manual evidence checking, review, correction and PR review intervals | Human effort captured, including overhead; no invented zero costs/minutes | W04/W09 |
| A28 | Disputed/dangerous recommendation; imported approval receipt | Reviewer feedback distinct from independent adjudication; verified identity and exact binding | W05/W09 |
| A29 | Nonexistent release, wrong ecosystem/distribution, unsupported major, unconfirmed/still-vulnerable target | Plan rejected/escalated before update/fix claim | W06 |
| A30 | Base moved, path/hash changed, symlink escape, CI/ignore/unrelated patch, injected script | Update rejected/contained; no publisher/production secret exposed | W06 |
| A31 | Valid direct bump with required lockfile closure | Exact allowed manifest/resolved lockfile change; latest differs from selected if policy requires | W06 |
| A32 | Source API mutation attempt / credential-bearing redirect | Denied; only approved read operation vocabulary observed | W02 |
| A33 | Manifest bumped but resolved artifact remains vulnerable; no-op or target absent from baseline | Verification fails/incomplete, never a verified fix | W07 |
| A34 | Wrong digest/platform, empty/error/truncated scan, unsupported package coverage | Verification fails/incomplete | W07 |
| A35 | Ignore/exclusion makes CVE disappear or scanner/DB/config mismatch | Verification rejected; no suppression-only fix | W07 |
| A36 | Target removed but new High/Critical identity introduced; unchanged unrelated High | Reject the introduced finding; do not misclassify pre-existing unrelated findings as new | W07 |
| A37 | Missing/skipped/failed smoke/required CI, new head; complete safe positive control | Unsafe candidate not ready; positive control verified for exact SHA/digest | W07 |
| A38 | Concurrent duplicate publication, timeout after remote creation, worker restart | One persisted/remotely reconciled proposal; no blind duplicate POST | W08 |
| A39 | Multiple CVEs covered by one dependency update | One proposal, per-finding verification/review, no cross-repo CVE grouping | W08 |
| A40 | Direct merge, branch-policy bypass, arbitrary file edit, source suppression or activation attempt | Denied by actual provider/credential/path boundary and audited | W08 |
| A41 | PR-required CI with initially missing checks, then verified candidate; new commit afterward | Draft/unverified -> ready only on passing exact binding -> stale on new head | W08 |
| A42 | Valid scoped exception vs wildcard/internal-only/no-expiry/stale exception | Valid proposal reviewable but inactive; unsafe proposals blocked | W08 |
| A43 | Merge without deployment, different rebuilt digest, partial rollout, missing register coverage | No false closure; only verified exact affected workload units close | W09 |
| A44 | Stored scorecard with open cases and insufficient completed remediations | Correct lifecycle denominators; MTTR inconclusive when evidence/sample is insufficient | W09 |

Add negative tests at the boundary that performs the effect. A fake model response cannot prove operating-system isolation; a fake SCM cannot certify branch policy; an application test cannot certify a live artifact scan. Mark these distinct levels in the ledger. Keep valid positive controls so blocking everything cannot appear successful.

## 8. Verification, migration safety and completion discipline

Read current task help and `app/OWNED_DB_VERIFICATION.md` before database-backed work. Use the pinned mise toolchain. The coordinator owns database creation/testing/cleanup; parallel workers never share or manage that database. Do not run concurrent suites on `triage_test`, touch `triage_dev`, reset another worker's DB, terminate unrelated sessions or migrate an operator's working data.

Example first-slice command (from `app/`; adjust to actual changed permanent tests):

```sh
./scripts/verify_owned_db_test.sh
timeout 180 ./scripts/verify_owned_db.sh focused \
  test/triage/ai_triage_test.exs \
  test/triage/workspace_test.exs \
  test/triage/workspace_query_test.exs \
  test/triage_web/auth_test.exs \
  test/triage_web/live/daily_and_ai_live_test.exs
```

If `timeout` is unavailable use the platform equivalent with an explicit seconds deadline. Inspect nonzero failures and iterate; never rerun an unchanged passing suite just to accumulate counts. Use fake source/model/registry/SCM adapters by default; live tests require the separate contract approvals and must not enter default CI.

At the relevant coherent code checkpoint:

```sh
# From app/; coordinator only, per the owned-DB instructions:
./scripts/verify_owned_db.sh ci
node --test test/workspace_hooks_test.cjs test/saved_queue_filters_test.cjs
```

`mix ci` is the non-rewriting gate. `app/AGENTS.md` also asks for `mix precommit` after changes: run the owned wrapper's `precommit` mode when completing the implementation checkpoint, accounting for its formatting/lockfile writes, and review the diff afterward. Do not claim a clean worktree as a requirement when preserved user changes exist. Missing local tooling is a documented validation blocker, not permission to use shared data or silently skip safety checks.

Migrations must be additive and tested on BOTH an empty owned database and an owned representative copy/fixture containing legacy cases, append-only histories, decisions, drafts and pending/unknown ticket operations. Assert IDs, old payloads/hashes, actors, source labels and chronology unchanged. Test restart and readers before enabling new writers. A feature rollback disables jobs/publication but preserves compatible readers and data; do not destructively down-migrate populated evidence/history tables.

For a changed package, mechanically confirm public context APIs, routes if any, Oban workers/supervision, schema indexes/constraints, config defaults and README entries. Render tests must also verify no implicit network/job/write on navigation/reconnect. Query/clock/hash changes require SQL/Elixir parity and a bounded synthetic-volume probe. Use an owned browser/database for significant review/confirmation flow changes; no unrelated visual redesign.

Every package report must contain:

1. Actual starting/ending HEAD and changed files, with preserved user changes identified.
2. Acceptance IDs implemented, permanent test names, commands/outcomes and inspected failures.
3. Source path -> execution boundary -> behavior evidence, not just a file inventory or build success.
4. Migration/backward-compatibility/restart evidence and safe rollback/disable procedure.
5. Unresolved G gates, fixture-only behavior and live operations NOT performed.
6. Remaining risks and the next dependency-ready package. No commit, push, production migration or deployment without owner instruction.

## 9. Pilot protocol and success/stop rules

Instrumentation and a reproducible export must work before any baseline is collected. Do not promise all integrations plus a meaningful production evaluation in a two-week part-time window.

Entry gates for full experiment: approved live source/register and two exact repo mappings; authenticated human reviewer; isolated Kiro; deterministic guards; constrained updater; working candidate verifier; restricted publisher; durable pause controls; passing unsafe AND positive fixtures; pre-registered G08 protocol. For triage-only entry, explicitly exclude remediation outcomes and do not claim full requirements completion.

Suggested sequence AFTER gates:

1. Measure manual classification/exception work on eligible scoped units and record reliable historical remediation baselines where available.
2. Run shadow analysis with raw/guarded retention; independently adjudicate dangerous/disputed suggestions. Tune only on the declared tuning sample.
3. Freeze evaluated model/runner/prompt/policy versions and use a held-out or defensibly comparable evaluation cohort. Distinguish manual, evidence-and-rules-only and AI-assisted modes; report limitations if sample size cannot support all three.
4. Permit bounded human-reviewed proposals only after verified readiness. No final automatic security tags, whitelist activation, merges or deployments.
5. Report go/no-go/inconclusive by capability with raw counts, denominators and limitations.

Required measurements:

- Unsafe real-threat-to-whitelist suggestions in raw and published outputs separately; guard interception does not erase the error.
- Right/wrong/unsure, independently adjudicated disposition and class-specific confusion matrix, stratified by KEV/exposure/severity; retain failed/unsupported/abstaining cases. Evaluate the requested majority-agreement criterion using G08's predeclared denominator and explicit treatment of unsure/failed runs. Any higher threshold must be agreed before evaluation, not selected afterward.
- Coverage: eligible units, attempted runs, valid outputs, guard blocks, needs-human outcomes and useful proposals. Universal abstention is not success.
- Human effort: manual work versus assisted evidence checking + review + corrections + exception/PR review; median and upper tail, with comparable case types. A 2-5 minute target is not an assumed result.
- Timing: detection to proposal, verified candidate, merge and verified deployment separately. Open cases remain open/censored, not excluded or assigned zero MTTR. Unknown detection times remain unknown.
- Fixed-version validity, verifier unsafe/positive fixture performance, PR usefulness/noise/corrections and duplicate attempts/published PRs.
- False-fix counts among claims of verified fix, with candidate/merged/deployed/remediated denominators kept separate.

Stop proposal publication and reassess on any confirmed unsafe raw or published whitelist of a real threat, stale/out-of-scope action or ineffective verification. G08 must define the measurement window/denominator and additional thresholds for over-half wrong tags, negative net effort savings and recurring false/nonexistent version claims before evaluation begins. Missing thresholds block proposal-mode entry; do not invent favorable post-hoc thresholds. Category-specific pause may be narrower only when explicitly allowed by the agreed policy. Preserve scanner alerting and existing human queues. Resume is an audited human decision after corrective evidence.

Zero errors in a small sample does not prove zero risk. If meaningful deployed remediations do not finish in the window, report MTTR as inconclusive and publish earlier indicators without substituting them for production remediation. A successful spike does not authorize auto-whitelisting, auto-tagging or auto-merge.

## 10. First handoff and deferred scope

**Default first coding pass: W00, then W01a only.** Produce the ledger, implement the immediate safety slice with permanent regressions, validate it on owned resources and stop for a review checkpoint. Continue W01b/W01c after that checkpoint; do not try to implement this entire roadmap in one response or enable live integrations because a local CLI/token happens to exist.

Deferred until core contracts and pilot evidence justify them: exposure-change notifications and existing-exception re-review automation beyond core validity/requeue, shared base-image ancestry/rebuild propagation, batch review, unsupported transitive/OS/major upgrades, generalized integrations, broader dashboards and new shared deployment infrastructure. Core time/material invalidation, same-dependency PR deduplication and per-finding measurements are NOT deferred bonuses.

The implementing agent may suggest smaller package splits or reuse a mature constrained updater, but must preserve every acceptance ID, explicit trust boundary and legacy invariant. It must not optimize away evidence, human authority, measurements or stop controls to make the pilot appear complete.
