# CVE Triage & Remediation — Architecture and Implementation Plan

**Prepared for:** VP Engineering, Engineering Managers, Security reviewers  
**Status:** Proposed architecture; internal integration details pending source-code review  
**Updated:** 9 September 2026  
**Implementation language:** Go  
**Pilot:** Two weeks, one engineer part-time, approximately 2–5 minutes of reviewer time per finding  
**Deployment decision:** Azure Pipelines first; an event-driven AKS coordinator is optional later

> Build a controlled security workflow with an LLM inside it—not a privileged agent that controls the security process. The system prepares evidence, recommendations, and constrained changes. Humans make every final classification, exception, and merge decision.

## Contents

1. [Executive decision](#1-executive-decision)
2. [Scope, assumptions, and non-negotiable controls](#2-scope-assumptions-and-non-negotiable-controls)
3. [Technology stack](#3-technology-stack)
4. [Architecture and execution model](#4-architecture-and-execution-model)
5. [Extract the existing security integration first](#5-extract-the-existing-security-integration-first)
6. [Evidence and domain contracts](#6-evidence-and-domain-contracts)
7. [Classification and deterministic safety policy](#7-classification-and-deterministic-safety-policy)
8. [Triage pipeline](#8-triage-pipeline)
9. [Kiro integration and isolation](#9-kiro-integration-and-isolation)
10. [Remediation planning and Renovate](#10-remediation-planning-and-renovate)
11. [Artifact verification and remediation closure](#11-artifact-verification-and-remediation-closure)
12. [Exception proposals and human review](#12-exception-proposals-and-human-review)
13. [Azure DevOps configuration](#13-azure-devops-configuration)
14. [Identity, secrets, and trust boundaries](#14-identity-secrets-and-trust-boundaries)
15. [State, deduplication, retries, and reconciliation](#15-state-deduplication-retries-and-reconciliation)
16. [Go application structure](#16-go-application-structure)
17. [Optional event-driven AKS worker](#17-optional-event-driven-aks-worker)
18. [Observability and operational controls](#18-observability-and-operational-controls)
19. [Test strategy and unsafe fixtures](#19-test-strategy-and-unsafe-fixtures)
20. [Two-week implementation plan](#20-two-week-implementation-plan)
21. [Experiment evaluation and go/no-go](#21-experiment-evaluation-and-gono-go)
22. [Decisions to confirm before implementation](#22-decisions-to-confirm-before-implementation)
23. [Definition of done and subsequent phases](#23-definition-of-done-and-subsequent-phases)
24. [References](#24-references)

## 1. Executive decision

Implement a small Go application, provisionally named `cveflow`, around the existing security platform and meta-index/register. Do not replace the scanner, service inventory, Grafana, or application CI.

The pilot uses one new automation repository, two automation pipelines, existing application repositories, and their existing CI. Store exception proposals in the existing exception repository; where none exists, use a protected proposals directory in the automation repository.

| Decision | Chosen approach | Reason |
|---|---|---|
| Custom application | Go | Fits API integration, explicit policy checks, durable state, and bounded external-tool execution. |
| Initial runtime | Short-lived Azure Pipeline jobs | Reuses CI infrastructure without introducing a permanent service during the spike. |
| Trigger | Scan-completion event where convenient; otherwise scheduled polling | Event-driven execution does not require a permanent pod. |
| Security integration | Read the API behind Grafana | Reuse the platform's data instead of interpreting dashboard presentation. |
| AI | Isolated Kiro adapter | Explain evidence and propose an assessment; never control credentials or arbitrary commands. |
| Dependency changes | Constrained, self-hosted Renovate | Reuse supported manifest and lockfile update behavior. |
| Verification | Existing build, SBOM, tests, and scanner | Verify the candidate artifact rather than trusting the proposed version bump. |
| State | Existing suitable storage; otherwise Azure Blob Storage for the serialized pilot | Avoid a new database server solely for the experiment. |
| Human interface | Existing security UI, Azure Boards, and Azure Repos | Keep decisions in the tools reviewers already use. |
| Later runtime | Queue-consuming Go coordinator in AKS, only when justified | Reuse the application logic while keeping builds and privileged changes in isolated jobs. |

The previous TypeScript/Zod option is superseded by Go. No TypeScript application, agent framework, Fabric runtime, vector database, new graph database, or custom frontend is required. Renovate and Kiro remain separately packaged tools; they are not rewritten in Go.

## 2. Scope, assumptions, and non-negotiable controls

### 2.1 Purpose

Reduce the time people spend collecting context, classifying findings, reviewing justified exceptions, and preparing straightforward fixes. Preserve existing alerting so genuine threats are never delayed by model execution or experiment failures.

The experiment should determine whether the combined workflow saves effort, whether the LLM adds value beyond evidence assembly and rules, and whether the verifier reliably rejects the predefined unsafe cases.

### 2.2 Assumptions—not confirmed internal facts

This plan assumes Azure DevOps Services, Azure Repos Git, YAML pipelines, an approved Kiro authentication path, and machine-readable access to the custom security platform. Azure DevOps Server requires separate compatibility and authentication checks.

The company has an existing working application that connects to the security stack. Its code has **not yet been supplied or inspected**. Actual endpoints, queries, authentication, freshness guarantees, repository mappings, and candidate-scan capabilities remain unverified.

The platform/register is expected to connect:

```text
repository → source/build revision → image digest → workload
           → service → exposure → owner → dependency manifest
```

A missing edge is an explicit integration gap, not a relationship the model may invent.

### 2.3 Pilot boundary

Limit the initial commitment to two suitable repositories, one dependency ecosystem, and one straightforward direct-dependency update type. Choose repositories with reliable provenance and working CI rather than trying to cover every language.

Production data access is read-only. Writes are limited to isolated workflow state, review items, proposal branches/PRs, and approved non-production build/scan resources.

**No automatic final tagging, whitelisting, exception activation, merging, or deployment.** Preparing a proposed tag or PR is allowed; applying an authoritative security disposition is not.

Do not include arbitrary code changes, unrestricted transitive upgrades, major-version migrations, or shared-base-image propagation in the initial implementation commitment.

### 2.4 Required corrections to the original wording

**Internal-only is not equivalent to not affected.** Internet exposure is one risk input. Vulnerabilities can require network, adjacent, local, or physical access; absence of internet exposure does not establish non-applicability. [S01]

**A fixed version is not necessarily the newest version.** Select a published, supported, policy-allowed version confirmed to contain the fix. Distribution vendors may backport fixes without adopting the upstream version number. [S02]

**A merged PR is not a remediated deployment.** The workflow must track whether the affected runtime actually uses the replacement artifact.

**Human approval does not eliminate model risk.** Evidence must remain independently inspectable, and unsafe raw model recommendations must be counted even when a validator blocks them.

## 3. Technology stack

| Layer | Pilot choice | Implementation notes |
|---|---|---|
| Application | Go | Pin an organization-approved supported toolchain and module versions at implementation time. |
| HTTP integration | `net/http`, `context` | Small typed REST/GraphQL adapters; explicit deadlines, paging, response limits, and retry classification. |
| Contracts | `encoding/json`, domain structs, explicit validators | Required fields, allowed values, cross-field checks, and evidence references are validated in code. |
| Process execution | `os/exec` | Trusted executable path and explicit argument list; no model-generated shell command. |
| Logging | `log/slog` | Structured operational records with secrets and sensitive content excluded. |
| Azure authentication | Azure SDK `azidentity` | Use the credential appropriate to the approved pipeline or pod identity configuration. |
| Pilot persistence | Existing store or Azure SDK `azblob` | Case records, immutable evidence snapshots, cursors, and conditional updates. |
| Model runtime | Pinned Kiro CLI package/container | Separate analyst job; adapter is replaceable. |
| Updater | Pinned Renovate container | Centrally controlled configuration; one allowlisted update path initially. |
| Verification | Existing scanner, SBOM generation, build/test tooling | Candidate-image support is a prerequisite for verified remediation. |
| Review integration | Azure DevOps REST APIs | Review items, PR references, pipeline results, and reconciliation. |
| Optional queue | Existing message bus; otherwise Azure Service Bus with `azservicebus` | Only needed for the later worker architecture. |
| Optional orchestration | AKS Deployment, workload identity; KEDA when useful | Do not add this infrastructure merely to prove triage quality. |

Azure publishes the Go identity, Blob Storage, and Service Bus clients used by these choices. [S03] [S04] [S05]

The Go executable simplifies distribution of custom code, not the entire toolchain. Kiro, Renovate, package managers, and scanners retain their own dependencies. Language choice does not establish model accuracy, evidence quality, or fix correctness.

## 4. Architecture and execution model

### 4.1 Pilot deployment

```text
EXISTING SECURITY PLATFORM / REGISTER
Findings • package occurrences • image digests • deployment/exposure evidence
                         |
              Event or scheduled read
                         v
                 TRIAGE PIPELINE
   +----------------------------------------------------------+
   | Collect evidence       Go / read-only source credentials  |
   | Analyze evidence       Kiro / isolated model credentials  |
   | Validate and publish   Go / limited publishing identity   |
   +----------------------------------------------------------+
                |                         |
                v                         v
       Human review item          Validated change plan
       in Azure Boards                    |
                |                         v
                |              REMEDIATION PIPELINE
                |              Go plan validation + Renovate
                |                         |
                |                         v
                |                   Proposal PR
                |                         |
                |                         v
                |              EXISTING APPLICATION CI
                |              Build + SBOM + scan + tests
                |                         |
                v                         v
      Human final classification     Human merge decision
      in security platform                   |
                                             v
                               Existing deployment process
                                             |
                                             v
                                Read-only reconciliation
                                verifies affected runtime
```

A parallel exception path creates a scoped exception-proposal PR, which Security and the owner review. The new application does not activate it in the security platform.

### 4.2 What runs on the pipeline agent

The Go command starts, reads durable state, processes a bounded batch, persists results, and exits. The analyst runs in a separate isolated job. Human waiting states are records in storage, not sleeping processes or pipeline approvals that hold an agent indefinitely.

Use an approved agent pool with access to the private security API. Do not expose the platform publicly to make connectivity easier. Reuse an established ephemeral execution pattern where available; different steps on one persistent machine are not a strong isolation boundary.

### 4.3 Triggering is separate from hosting

A security event may trigger a pipeline directly through the Run Pipeline API. Azure Pipelines also supports incoming-webhook resources and pipeline-completion triggers. None requires the Go application to run as a permanent HTTP listener. [S06] [S07] [S08]

Prefer one run per completed scan or bounded batch, not one run per CVE. Add periodic reconciliation even when events work, to recover missed events and revisit relevant changes.

## 5. Extract the existing security integration first

### 5.1 Input to inspect

Review a company-approved, sanitized source archive or the relevant client, authentication, configuration, query, mapping, and deployment files. Include an `.env.example`, dependency files, and sanitized response fixtures where available.

Exclude real tokens, passwords, private keys, production dumps, real `.env` files, and Git history. Preserve variable names, response structure, and identifier relationships when sanitizing.

Static inspection does not authorize executing the application or contacting production. Any later live validation needs approved credentials, scope, and execution location.

### 5.2 Extraction deliverable

| Area | Evidence to extract from the working app |
|---|---|
| Connectivity | REST/GraphQL endpoint configuration, routes, proxy requirements, TLS/custom CA settings, private-network assumptions. |
| Authentication | Token acquisition/refresh, header construction, scopes, identity source, secret references. |
| Queries | Finding filters, pagination, image/package lookups, scan results, fixed-version and advisory fields. |
| Relationships | Mapping from image to workload/service/repository/build/manifest and owner. |
| Data quality | Observation timestamps, scan completion, source revisions, inventory completeness, error handling. |
| Runtime behavior | Polling/event integration, timeouts, retry behavior, rate limits, cache semantics. |
| Remediation verification | Any existing way to obtain a scan for a candidate image before deployment. |

Produce a file/function-backed integration map and classify each conclusion as **confirmed by code**, **inferred**, or **requires confirmation**. Reuse proven behavior, not credentials or unnecessary application features.

### 5.3 Proposed adapter operations

These are application interfaces to implement over the discovered API, **not assumed vendor endpoints**:

```text
ListChangedFindings(scope, cursor) → page + next cursor + completeness
GetFindingEvidence(findingID) → finding + package occurrence + scan metadata
GetRuntimeContext(imageDigest) → observed workloads + exposure + inventory scope
GetRemediationTarget(imageDigest, packageIdentity) → source/build/manifest mapping
GetScanResult(imageDigest) → scan completion + SBOM + unsuppressed findings
```

A missing operation should be reported as a capability gap. Triage may proceed with explicit uncertainty; remediation verification must not be claimed without candidate-artifact evidence.

## 6. Evidence and domain contracts

### 6.1 Evidence bundle

Every assessment uses a versioned, immutable evidence snapshot. Facts are rendered by trusted code; AI interpretation is stored separately.

| Group | Required content |
|---|---|
| Finding | Source finding ID, CVE/advisory aliases, severity/vector where supplied, first-seen and last-change times. |
| Package occurrence | Ecosystem/distribution, package name and qualifiers, installed version, path/occurrence identifier, direct/transitive/base-image origin where known. |
| Artifact | Image repository, immutable digest, platform/architecture, SBOM and scan references. Resolve multi-platform indexes to the relevant scanned platform artifact. |
| Runtime | Workload, environment, service, deployment observation, inventory scope and completion status. |
| Exposure | Explicit classification, supporting observations, observation time, confidence limitations. |
| Source | Azure repository ID, target branch, producing source commit/build, manifest or Dockerfile path, owner. |
| Fix intelligence | Vendor advisory, affected/fixed ranges, published-release verification, KEV status and feed freshness. |
| Quality | Collection status, source revision, observation time, retrieval time, missing fields, contradictions. |
| Audit | Schema version, evidence ID/hash, collector version, policy version, correlation identifiers. |

Treat timestamps independently. A recent API retrieval does not make an old scan current. A complete scan does not establish complete deployment inventory. A false KEV Boolean is not trustworthy when the KEV feed failed or is stale.

Use explicit unknown values. In Go, a newly allocated Boolean field omitted from JSON remains false; decoding must not turn missing exposure into evidence of no exposure. Reject invalid enums and validate required fields. `DisallowUnknownFields` is useful for model/internal contracts but does not replace semantic validation. [S09]

### 6.2 Separate applicability, priority, action, and approval

| Dimension | Proposed values |
|---|---|
| Applicability | `affected`, `not_affected_with_evidence`, `unknown` |
| Priority | `expedited_review`, `normal_review`, `insufficient_context` |
| Next action | `dependency_update`, `base_image_update`, `rebuild_or_deploy`, `mitigation_review`, `exception_proposal`, `investigation` |
| Human approval | `pending`, `accepted`, `rejected`, `unsure` |

These values describe a proposal until a human decides. For a compact review UI, derive `remediate`, `exception_review`, or `needs_human`; never present the second category as an already approved “safe to whitelist.”

### 6.3 Model proposal example

The following is a synthetic contract example. IDs and versions throughout this plan are placeholders, not actual findings or confirmed releases.

```json
{
  "schema_version": "1",
  "case_id": "case-example",
  "evidence_snapshot_id": "evidence-example",
  "proposed_applicability": "affected",
  "proposed_priority": "normal_review",
  "proposed_action": "dependency_update",
  "reason_codes": ["DEPLOYED", "CONFIRMED_FIX_AVAILABLE"],
  "evidence_ids": ["deployment-example", "advisory-example"],
  "candidate_id": "candidate-example",
  "unknowns": [],
  "summary": "The supplied evidence supports preparing a dependency update."
}
```

The model may reference a candidate or evidence ID. Trusted code resolves the actual version, repository, path, and source link. The model cannot supply authoritative approval fields, executable instructions, or arbitrary publication destinations.

### 6.4 Remediation plan

A trusted plan binds the case IDs, repository ID, base commit, branch, manifest, package identity, installed and target versions, allowed changed files, advisory/release evidence, policy version, expiry/revalidation condition, and plan hash.

### 6.5 Independent review record

Store the reviewer identity and timestamp, reviewed proposal/evidence version, correct/wrong/unsure rating, final applicability/action, explanation for corrections, review time, and reference to the authoritative security-platform decision. Automation must not manufacture a reviewer outcome.

## 7. Classification and deterministic safety policy

Apply hard policy before model execution to determine eligible preparation paths and after execution to reject unsupported recommendations.

| Condition | Pilot behavior |
|---|---|
| Stale, incomplete, contradictory, or out-of-scope evidence | Preserve visibility; route to investigation; prohibit exception preparation and unsupported remediation actions. |
| KEV finding | Expedited human review; no exception proposal in this spike. |
| Internet-exposed Critical | Expedited human review; no exception proposal in this spike. |
| Internal-only service | Include the exposure evidence; do not infer non-applicability or accept risk. |
| Image not observed in inventory | Confirm scope/completeness; do not dismiss globally or claim the package is not affected. |
| Specific, current applicability evidence supports non-applicability | May prepare a scoped exception for review, unless a stricter pilot rule prohibits it. |
| Applicable finding with no supported fix | Route mitigation decisions to a human; do not downgrade or dismiss it. |
| Repository, provenance, or dependency origin uncertain | No automated version-bump preparation. |
| Current source already fixes the deployed vulnerability | Propose a rebuild/deployment investigation, not another dependency bump. |
| Model unavailable, malformed, or outside allowed actions | Preserve facts and route to human handling; do not block existing alerts. |

CISA identifies KEV as an input to vulnerability prioritization. The stricter exception ban here is a proposed experiment policy, not a claim about a universal regulatory requirement. [S10]

Freshness limits, permitted upgrade ranges, scope, PR caps, and proposal expiry belong in version-controlled policy reviewed by Security. Do not invent universal thresholds: derive them from actual collection cadence and risk requirements before enabling actions.

A self-reported model confidence score cannot authorize an exception, bypass a check, or substitute for evidence. A valid evidence reference proves only that the referenced record exists, not that the interpretation is correct.

## 8. Triage pipeline

### 8.1 Collect evidence

Acquire a processing claim, read changed findings, assemble source mappings and quality metadata, and persist the evidence snapshot. Preserve partial/error states rather than treating empty results as proof of absence.

Group work before calling the model. The same dependency may create multiple scanner rows; multiple deployment contexts may still need separate assessments.

### 8.2 Prepare assessments

Render mandatory facts and warnings independently of the model. Run deterministic policy, then invoke Kiro only for cases where an explanation can help. Cache assessments by substantive facts, policy, prompt, and model/runtime version rather than rerunning on an unchanged collection timestamp.

Recheck freshness separately even when the substantive evidence hash is unchanged.

### 8.3 Validate and publish

Validate the model payload, candidate references, and policy. Publish or update one meaningful review item per case/group, with per-context details where grouped. Persist raw recommendations and validation outcomes separately for evaluation.

A safe, validated remediation candidate may trigger automatic PR preparation while the authoritative classification remains pending. This is preparation—not a human decision. Only humans apply final source-system tags and merge changes.

### 8.4 Handoff

Persist eligible plans and reference them by producer run and plan ID. The remediation pipeline consumes the artifacts from that specific trusted run, never an unrelated “latest” artifact. Revalidate the plan before any write because source revisions and advisory data may have changed.

## 9. Kiro integration and isolation

### 9.1 Bounded role

Kiro explains the supplied facts, identifies uncertainties, and proposes a permitted assessment. It does not discover production resources, browse arbitrary URLs, select credentials, choose arbitrary pipelines, or edit repositories.

Collect advisories through a trusted fetcher using allowlisted sources, bounded responses, redirect checks, and no credential forwarding to unrelated hosts. Treat advisory text, repository content, and scanner descriptions as untrusted data, not instructions.

### 9.2 Runtime contract

Current Kiro documentation describes headless operation with `KIRO_API_KEY`, `--no-interactive`, and `--output-format stream-json`; the event-stream option requires the documented V2/V3 engine support. Pin and test the selected CLI/engine combination. Parse events separately from the final assessment JSON. [S11]

Implement the Go adapter as a narrow `Assess(context, evidence) → proposal/error` operation. Use `exec.CommandContext` with explicit arguments and a trusted binary path, not a shell string. Bound input/output, set deadlines, avoid leaking prompts or tokens through logs, and enforce container/job termination as well as process cancellation. [S12]

Authentication, entitlement, model choice, data handling, and cost allocation must be approved for the company account. Do not copy a developer's authenticated home directory into CI.

### 9.3 Isolation requirements

Use a clean analyst workspace, protected agent configuration, no application-repository checkout, no inherited hooks/MCP configuration, no production credential, and no repository/state-write credential. Start with no agent tools; provide the bounded evidence in the prompt. If a file-read tool is necessary, allow only the staged evidence directory.

Kiro agent configuration is version-sensitive. The current reference covers CLI 3.0 and includes changes to permissions configuration; implement against the pinned release rather than copying legacy settings. Disable inherited MCP/power/tool access explicitly and verify effective behavior with negative tests. [S13]

The analyst returns only untrusted output. The trusted publisher uses the original collector-produced evidence, not a model-modified copy. Hashes detect content changes; authenticated producer identity and protected artifact access establish provenance.

### 9.4 Failure handling

A timeout, schema error, unsupported citation, disallowed recommendation, or contradictory claim produces a visible abstention or blocked proposal. Preserve the raw result for the experiment and continue the pre-existing manual security process.

## 10. Remediation planning and Renovate

### 10.1 Resolve the correct source action

| Dependency situation | Proposed response |
|---|---|
| Direct application dependency | Update its declaration and required lockfile using the selected supported manager. |
| Transitive dependency | Locate the controlling parent/constraint; hand complex cases to a human during the pilot. |
| Base-image package | Identify the approved base-image definition/replacement; route outside the initial direct-dependency path. |
| Source already fixed, old artifact deployed | Create a rebuild/deployment action; do not generate a no-op bump. |
| Shared base image | Later, prepare one upstream fix and track each consumer's rebuild/deployment independently. |
| Ambiguous occurrence or build-stage mapping | Stop automated change preparation and request investigation. |

### 10.2 Resolve a real fixed version

Trusted code must verify the exact package identity, an authoritative affected/fixed statement, an existing published release in the applicable registry/mirror, supported version policy, and compatibility with the current dependency declaration.

Use vendor/distribution semantics for operating-system packages and established ecosystem version handling rather than a generic string or semantic-version comparison. Backports are a documented reason upstream version numbers can mislead. [S02]

OSV package/version queries can provide an additional cross-check where covered; a missing record is not proof of safety. [S14]

Kiro may summarize supplied release notes. It is not the authority for whether a version exists or fixes the vulnerability. Conflicting advisories or unavailable registry evidence block automatic preparation.

### 10.3 Constrain Renovate

Renovate supports Azure DevOps and documented Entra bearer-token authentication for Azure DevOps Services. Confirm the selected version and identity configuration in the organization. [S15]

Translate the validated plan into centrally controlled configuration. Restrict repositories, package managers, files, dependency identities, target versions, and PR concurrency; disable automerge, broad maintenance work, and onboarding noise. Ignore repository-provided Renovate configuration for this controlled pilot. Disable install scripts/plugins and unapproved post-upgrade execution. These behaviors have documented configuration controls, but the effective configuration must be tested. [S16] [S17]

Do not assume Renovate's GitHub vulnerability-alert integration consumes the custom platform's findings. The Go resolver supplies the plan; Renovate supplies the update mechanism. [S17]

Before live use, prove that the pinned Renovate version can make the exact permitted update and no unrelated changes. If not, narrow the pilot or hand the case to a human; do not replace it with unrestricted AI editing.

### 10.4 Publish a proposal, then verify it

Create a normal PR labeled **awaiting verification** so existing required CI can run. A trusted diff check rejects files and semantic changes outside the plan. Request human review when evidence is ready; failed preparations remain visibly unverified and are updated rather than duplicated.

Renovate is a privileged updater and is not a sandbox. Repository/package-manager behavior can execute code, so run it in an isolated environment with narrowly scoped credentials and egress. Do not execute application builds with the updater's repository-write credential. [S18]

## 11. Artifact verification and remediation closure

### 11.1 Verification gate

Use the existing application build and scanner, with a protected verifier that evaluates their outputs. A manifest diff alone is not a fix.

| Check | Required evidence |
|---|---|
| Planned dependency changed | Resolved graph/SBOM contains the intended package version; a lockfile did not preserve the vulnerable version. |
| Correct artifact | Candidate scan belongs to the digest built from the recorded PR revision and relevant target/base revision. |
| Target finding addressed | CVE and advisory aliases are absent from relevant package occurrences in an unsuppressed, complete candidate scan. |
| Positive fix evidence | Applicable vendor/advisory evidence identifies the installed candidate version as fixed. |
| Comparable baseline | Unmodified target baseline and candidate are evaluated with the same scanner, vulnerability database snapshot, configuration, platform, and scope. |
| No introduced High/Critical findings | Compare normalized findings with the baseline. Existing unrelated findings are not misreported as newly introduced ones. |
| Functional validation | Existing required build/tests and the agreed smoke test pass. |
| Change boundaries | Only approved dependency/lockfile changes occur; tests, pipeline definitions, scanners, suppressions, and package sources are unchanged. |
| Complete execution | No timeout, partial scan, unsupported platform, missing package coverage, or failed collection is treated as a clean result. |

The deployed vulnerable artifact and the unmodified PR target may differ. Preserve both identities: use the appropriate pre-change target build for introduced-findings comparison, and link the deployed vulnerable occurrence to the replacement artifact. If current source already fixes it, do not create another bump.

### 11.2 Verification report

Record the remediation plan/evidence IDs, repository and source/base commits, built merge revision where applicable, candidate and baseline digests, SBOM references, scanner/database/configuration versions, scan completion, fixed-version evidence, normalized vulnerability differences, test results, verifier version, and final pass/fail/unverified status.

Use protected verifier code and source artifacts. A model-written report or a success string from arbitrary repository code cannot satisfy the security gate.

A missing scan, inability to establish the baseline, or lack of supported database reproducibility is a capability gap. Mark the result **unverified** and fail the automated remediation gate rather than claiming success. A pinned database makes a comparison repeatable; recheck current advisories and invalidate stale verification before merge.

A clean scan is evidence within its coverage—not proof of universal non-exploitability.

### 11.3 Revalidation and runtime closure

Any material PR update, relevant target-branch movement, evidence/advisory change, or expired verification must trigger revalidation. Human approval is bound to the reviewed revision; it cannot silently authorize later changes.

After merge, the normal human-controlled deployment process continues. Reconciliation confirms the replacement digest and scan status for each affected workload/environment. Close only the verified runtime scopes; a shared PR can leave some deployments outstanding.

Do not automatically modify the source finding's final disposition during the pilot. Record verified evidence locally and let the established security workflow apply closure. Exception-approved or not-deployed outcomes must not be counted as successful runtime fixes.

## 12. Exception proposals and human review

### 12.1 Review card

Render this information consistently in the existing work-item process; avoid a new frontend or a new ticket for every scanner row:

```text
Suggested decision: <proposal> — awaiting human decision

Verified input facts
  Finding/package occurrence, image digest, workloads, environment
  Exposure observations and timestamps
  Evidence completeness/freshness and mandatory warnings
  Advisory/release references and supported candidate, if any

AI interpretation
  Proposed applicability, priority, next action
  Evidence references and explicit uncertainties

Prepared change
  PR or exception-proposal link
  Awaiting verification / verified / failed / unavailable

Human outcome
  Correct / Wrong / Unsure
  Final decision, correction reason, reviewer, review minutes
  Security-platform decision reference
```

“Verified input facts” means authenticated facts returned by the source and checked for contract/quality consistency, not independently established truth about every production condition. Display that limitation when important.

The reviewer confirms the evidence and applies the final tag in the security platform. For remediation, the code owner reviews the diff and CI; Security confirms security claims according to existing responsibility rules.

### 12.2 Exception contents

Require a specific finding/CVE, package occurrence, image digest, workload/environment, justification category, supporting observations, owner, approver, evidence snapshot, expiry or reassessment conditions, and proposed platform action.

Distinguish **not affected**, where evidence supports non-applicability, from **risk accepted**, where an authorized human accepts an applicable risk. Neither is synonymous with internal-only or low priority. CISA's VEX material documents justifications for not-affected assertions. [S29]

No broad CVE-wide exception, inherited wildcard scope, or indefinite approval is generated by default. An approved exception must not silently carry to another image, exposure state, or workload.

### 12.3 Approval versus activation

Security and the owner review the proposal PR. Under the pilot's read-only production constraint, merging records approval and Security activates the exception through the existing process.

If a pre-existing, human-reviewed Git workflow already activates exceptions, reuse it only after Security explicitly confirms that boundary. The new application still receives no direct exception-write permission.

When scope, exposure, advisory evidence, or expiry changes, create/update a reassessment item. Do not automatically remove an exception or apply a new authoritative tag. Batch approval and automatic exception handling remain outside the experiment.

## 13. Azure DevOps configuration

### 13.1 Repositories and pipelines

The automation repository contains Go code, contracts, policy, protected agent configuration, pipeline definitions, fixtures, and optional exception proposals. App repos keep their existing build/test definitions.

`cve-triage` has collection, isolated analysis, and trusted validation/publishing jobs. `cve-remediate` validates plans, prepares changes through Renovate, and links the PRs. Existing app CI supplies required build/scan validation. The triage schedule can also run bounded reconciliation; a separate reconciler deployment is unnecessary initially.

Do not put business policy in long inline shell scripts. Do not let an application PR choose the privileged automation template, policy, service connection, or pipeline definition.

### 13.2 Trigger options

| Upstream capability | Selected integration |
|---|---|
| Approved authenticated API caller | Run Pipeline API with a scan/batch ID and fixed allowlisted pipeline/ref. [S06] |
| Compatible webhook | Verified incoming-webhook resource; reject unverified requests and never interpolate payload text into shell/YAML instructions. [S07] |
| Scan occurs in Azure Pipelines | Completion trigger from the trusted scan pipeline. [S08] |
| No practical event integration | Scheduled incremental read matching the actual scanner cadence. [S25] |

Prefer an authenticated API call over building a receiver just for the pilot. Built-in incoming-webhook verification must match the sender's supported scheme; otherwise use the API path or the later authenticated receiver/queue pattern.

The following are **trigger fragments, not runnable pipeline implementations**. Job definitions, secure identity setup, artifact handling, and organization-specific resource names still need implementation.

```yaml
# cve-triage.yml: schedule fallback / reconciliation
trigger: none

schedules:
  - cron: "0 * * * *"
    displayName: Hourly pilot reconciliation
    branches:
      include:
        - main
    always: true
```

Azure cron schedules use UTC. `always: true` permits runs despite unchanged Git content and can permit overlaps even when `batch: true`; application-level coordination is still required. Hourly is a proposed starting schedule, not a freshness guarantee. [S25]

```yaml
# cve-remediate.yml: completion-trigger option
trigger: none

resources:
  pipelines:
    - pipeline: triage
      source: cve-triage
      trigger:
        branches:
          include:
            - refs/heads/main
```

Consume the triggering run's artifact and no-op when it contains no eligible plans. API-started runs must likewise identify a trusted producer run; do not accept caller-selected arbitrary artifacts. [S08]

### 13.3 Branch policies and CI

For Azure Repos Git, configure PR validation as target-branch build policies, not YAML `pr:` triggers. Draft PRs do not trigger these policy builds, so use normal proposal PRs with required validation and auto-complete disabled. [S19]

Require human reviewers, independent Security/owner review for exceptions, CI and security verification, and renewed approval after relevant source changes. Configure required validations to expire/re-run when the target or evidence changes. Do not allow the requestor's vote or a bot vote to satisfy the intended independent review. [S20]

No code path enables auto-complete, invokes merge, or sets an authoritative final security tag. Enforce branch permissions as well as application behavior; test the actual bot permissions in a disposable pilot repository before live use.

## 14. Identity, secrets, and trust boundaries

### 14.1 Permission matrix

| Role | Required access | Explicitly excluded |
|---|---|---|
| Collector | Read security API, scoped metadata, approved advisories; write collector-owned evidence/state | Production mutation, repo writes, model/publisher credentials |
| Kiro analyst | Read staged evidence; approved model authentication | Security API, Azure DevOps writes, durable-state writes, arbitrary shell/network tools |
| Review publisher | Read trusted evidence/proposals; write selected review items and workflow state | App execution, protected-branch changes, classification/exception activation |
| Renovate updater | Read allowlisted app repos; write permitted proposal branches/PRs; scoped package-feed access | Policy bypass/admin, protected-target mutation, production deployment |
| Build and verifier | Read PR source and needed packages; isolated candidate build/scan resources | Renovate/publisher credentials, production deployment, arbitrary security writeback |
| Later queue coordinator | Queue consume, case state, fixed pipeline dispatch and status reads | Model execution with coordinator credentials, arbitrary repo edits or production mutation |
| Humans | Existing authorized classification, exception, review, merge, and deployment actions | No new implicit privileges created by the experiment |

When practical, separate the candidate builder from the trusted verification publisher. Candidate images belong in an isolated registry namespace with bounded retention, not the production release namespace.

### 14.2 Azure identity choice

Prefer dedicated Entra identities and narrowly authorized service connections. Azure DevOps documents a workload-identity service connection for PAT-free access; its availability, task versions, identity membership, and effective permissions must be confirmed in the organization. Do not assume `azidentity` alone configures pipeline federation. [S21]

If that path is unavailable, use the company's approved least-privilege alternative. Avoid a developer's PAT and do not broaden a shared Build Service account just to make publishing work.

Azure job-token permissions depend on authorization scope and the build-service identity. Separate jobs do not automatically create separate authorization identities. Limit repository access and service-connection authorization explicitly. [S22]

Deny target-branch contribution as appropriate, bypass permissions, force-push outside permitted proposal maintenance, and permission/policy administration. Azure branch creation can carry additional branch-level permissions; verify effective permissions and inheritance rather than assuming a branch-name convention enforces security. [S23]

### 14.3 Process, network, and data protections

Use isolated agent/VM/container boundaries appropriate to the credentials. Do not run untrusted application code on the same persistent host as privileged automation. Do not expose a Docker host socket or mount credentials merely to simplify tooling.

Minimize outbound destinations, restrict callback/fetch URLs, verify TLS, bound redirects/responses, and do not forward credentials across origins. Never fetch URLs supplied directly by model output.

Stage only approved evidence for Kiro. Confirm corporate rules for transmitting vulnerability inventories, internal names, and source snippets to the selected model service. Redact/minimize where required; stop model execution when data approval is missing.

Apply separate write permissions to source evidence, untrusted model output, trusted plans, and reviewer records. Keep secrets out of artifacts, logs, shell tracing, PR bodies, and serialized case records. Define retention/access rules with Security before the live pilot.

## 15. State, deduplication, retries, and reconciliation

### 15.1 Durable records

Use existing suitable workflow storage or a dedicated Blob container. Suggested logical records:

```text
evidence/<snapshot-id>.json       immutable collector evidence
cases/<case-id>.json              assessment/action state and external IDs
plans/<plan-id>.json              trusted remediation plans
runs/<run-id>/...                 producer references and bounded outputs
reviews/<case-id>/<review-id>     human evaluation records
cursors/<scope>.json              incremental source position
```

These are logical names; prefix layout alone is not an authorization boundary. Use separate containers/permissions where necessary.

ETag-conditional updates and leases can coordinate cooperating writers in Blob Storage. They do not make external PR creation transactional or provide a multi-object transaction. [S24]

For the serialized pilot, store pending action intents in the case record with conditional updates. Reconciliation repairs interrupted transitions. Consider an existing transactional database for heavier concurrent workflows rather than inventing a distributed transaction layer over blobs.

### 15.2 Identity and grouping

Use separate keys for separate purposes:

```text
Event identity:
    source + event ID

Assessment identity:
    normalized vulnerability + package occurrence + image digest
    + workload/environment + inventory scope

Remediation identity:
    repository + target branch + manifest + dependency + target version
```

Maintain the source finding ID as a correlation key and normalize advisory aliases. Link multiple assessments to one remediation without merging their risk decisions. Exposure changes create a new assessment revision of the case, not an unrelated case with no history.

Use deterministic branch/action identifiers. Before retrying a write, search by the recorded external ID or stable marker. An ambiguous timeout is not evidence that the first request failed.

### 15.3 Cursor and retry rules

Persist fetched cases and actionable error states before advancing the successful collection cursor. Respect upstream paging/completeness semantics; use overlap or replay where the API cannot guarantee a stable change cursor. Deduplication makes replay safe.

Retry transient reads with bounded backoff and provider retry guidance. Do not retry permanent authentication, schema, scope, or policy failures indefinitely. Writes need operation-specific reconciliation, not a universal HTTP retry loop.

If a processing lease expires, stop issuing new writes until ownership is re-established. Before dispatch/publication, recheck case version and existing actions. Application leases plus idempotency reduce duplicates; they are not an exactly-once guarantee.

### 15.4 Human waiting and revalidation

Keep workflow and approval states separate. A case can have a pending human classification and a prepared fix PR simultaneously.

```text
Assessment: collected → proposed → accepted / rejected / unsure
Fix:        planned → PR opened → verified → merged → runtime verified
Exception: proposed → human approved → activated by existing process
```

Each path may also be blocked, failed, expired, or superseded. No process holds a queue lock or pipeline agent while waiting for a person.

Reconcile missed events, open PRs, failed actions, approved changes, deployed digests, exception expiry, exposure changes, and evidence/advisory freshness. Freshness failures preserve existing visibility and prevent unsupported action; they do not imply that the finding disappeared.

## 16. Go application structure

```text
cve-workflow/
  architecture.md
  go.mod
  go.sum
  cmd/cveflow/
    main.go
  internal/
    domain/            # Evidence, proposals, plans, reviews, state
    security/          # Adapter extracted from the existing company app
    policy/            # Deterministic eligibility and safety checks
    analyst/           # Kiro process/event parsing adapter
    remediation/       # Authoritative version resolution, Renovate plan/config
    azuredevops/       # Work items, PR links, pipeline dispatch/status
    verification/      # Normalized scan/SBOM checks and report validation
    state/             # Persistence, conditional updates, cursors
    evaluation/        # Reviewer outcomes and experiment metrics
    workflow/          # Application-level orchestration
  config/
    pilot-scope.json
    policy.json
  agents/
    cve-analyst/       # Protected, pinned-version configuration and prompt
  schemas/
    evidence.schema.json
    assessment.schema.json
    remediation-plan.schema.json
  pipelines/
    cve-triage.yml
    cve-remediate.yml
    templates/
  proposals/
    exceptions/       # Only if no existing exception repository exists
  testdata/
    findings/
    model-responses/
    scan-results/
  .env.example
```

Keep entrypoints thin: pipeline commands and the optional queue consumer call the same workflow/domain code. Do not put business policy in YAML, queue handlers, or prompt text alone.

Proposed command contract—not an existing implementation:

```text
cveflow collect       --scope pilot --out evidence-batch.json
cveflow assess        --evidence evidence-batch.json --out proposals.json
cveflow publish       --run-id <trusted-run-id>
cveflow prepare-fix   --plan-id <validated-plan-id>
cveflow verify        --plan-id <plan-id> --report <trusted-ci-report>
cveflow reconcile     --scope pilot
cveflow evaluate      --experiment <experiment-id>

# Optional later runtime:
cveflow worker        --queue <configured-queue>
```

Schema-check all internal/model contracts; require a single complete JSON document, valid enum values, allowed field names, required values, and correct references. Add duplicate-key detection or a strict parser at the security boundary: ordinary JSON decoding must not produce ambiguous interpretations. Upstream API decoding may tolerate additive fields only when required facts and semantics are still validated.

Use cancellation, response/output limits, and structured errors throughout. Test policy as pure functions and adapters against sanitized fixtures. Unit tests, race checks where concurrency is used, and negative integration tests belong in the automation repository's own CI.

Configuration should contain identifiers and references, not secret values. Require explicit pilot scope, source freshness limits, allowed managers/paths/upgrades, model limits, PR caps, verifier settings, and source allowlists before enabling publication. A dry run may collect and validate but must not create external proposals.

## 17. Optional event-driven AKS worker

### 17.1 Introduce it only for a real coordination need

Remain pipeline-only if event batches and pipeline latency are acceptable. A production deployment does not inherently require a permanent service.

Add a coordinator when event frequency, grouping, prioritization, concurrency, or continuous reconciliation makes it useful—and preferably when AKS and a message bus are already operated by the team.

```text
Security events
      |
      +-- Existing message bus ------------------+
      |                                          |
      +-- Authenticated receiver → durable queue +
                                                 |
                                                 v
                                         Go worker in AKS
                                   validate / fetch / group / persist
                                                 |
                                   fixed pipeline/job dispatch
                                      /                     \
                                     v                       v
                           isolated assessment        remediation preparation
                               pipeline                    pipeline
                                     |                       |
                                     v                       v
                              review item              PR + application CI
```

The receiver validates and durably enqueues, then returns. It does not execute Kiro or wait for a build. Prefer direct publishing to an existing bus when possible; avoid an unnecessary HTTP component.

### 17.2 Queue processing contract

Events carry identifiers and source revisions, not authoritative security decisions or instructions. Fetch current facts from the platform. Reject unknown producers, scopes, event types, and arbitrary destination URLs.

Use the broker's acknowledged/locked delivery mode. Persist the case and pending dispatch intent before completing the message. A separate dispatcher/reconciliation step handles ambiguous pipeline-start outcomes. Service Bus may redeliver a message when settlement fails, so business-level deduplication is mandatory. [S26]

Bound retries, monitor dead-lettered messages, and provide an operator-controlled replay path. Do not hold a message lock throughout model execution, CI, or human review.

### 17.3 AKS deployment

Start with one replica and bounded concurrent work. Set resource limits, safe shutdown behavior, readiness/liveness checks, non-root execution where supported, restricted network access, and no unnecessary public ingress.

Use a dedicated workload identity for queue/state/dispatch access. AKS supports Entra Workload ID; required federation and SDK configuration still need deployment-specific setup. [S27]

KEDA's Service Bus scaler can add event-based scaling when needed. Introduce replicas only after concurrent state transitions and duplicate dispatch handling are proven. [S28]

The coordinator does not become a privileged interactive agent. Keep Kiro, Renovate, and application builds in isolated execution jobs, reusing the pipeline boundaries established in the pilot.

## 18. Observability and operational controls

### 18.1 Operational records

Emit structured logs with run, case, evidence, plan, PR, pipeline, and model-invocation correlation IDs. Keep operational logs separate from restricted evidence and experiment evaluation records.

Track collection freshness/completeness, eligible/blocked cases, model errors and abstentions, policy rejections, registry/advisory failures, PR attempts and duplicates, verification outcomes, retry/queue backlog, and unresolved workflow states.

Reuse the team's existing monitoring/Grafana environment where practical. Do not make a new dashboard or telemetry stack a dependency for the pilot; structured logs and a bounded evaluation export are enough to begin.

### 18.2 Budgets and safe shutdown

Set explicit batch, model-token/output, execution-time, CI-concurrency, and PR-volume caps before live publication. The limits are agreed pilot controls, not assumed capacity measurements.

Provide separate switches for model analysis, fix-PR publication, and exception-proposal publication, plus a global publication stop. Revoking write credentials must disable preparation writes without disrupting existing source-system alerting.

On a safety stop, retain evidence, notify the reviewer/owner through the existing process, and continue only the approved read-only/manual path. Corrective cleanup or closure of existing proposals is performed by humans or an explicitly approved action, not an autonomous rewrite of history.

### 18.3 Important failure modes

| Risk | Control and visible outcome |
|---|---|
| Reviewer over-trusts fluent prose | Separate source facts from model interpretation; show unknowns and mandatory warnings; independently review a sample. |
| Platform/dashboard is stale or incomplete | Validate underlying timestamps and coverage; block unsupported proposals rather than interpreting absence as safety. |
| Prompt injection in descriptions or advisories | No privileged model tools; isolated output; trusted policy and ID resolution; source allowlists. |
| Hallucinated version/fix | Registry and authoritative advisory checks outside the model; candidate-artifact verification. |
| PR spam or repeated writes | Grouping, durable IDs, caps, conditional state updates, and operation-specific retry reconciliation. |
| Wrong artifact or no-op fix | Commit/digest/occurrence binding and resolved dependency/SBOM checks. |
| Unsafe updater/build execution | Isolated roles, protected config, no production credentials, no broad shared host privileges. |
| Model marks everything unknown | Measure useful coverage and net reviewer time; retain rules-only workflow as a comparator. |
| Changes invalidate an old approval | Bind approval/report to versions and evidence; expire/revalidate rather than carrying approval forward. |

## 19. Test strategy and unsafe fixtures

Use sanitized unit/contract fixtures, historical replay, a held-out negative test set, and a supervised live sample. Historical assessments should use evidence available at the relevant decision time where possible; otherwise disclose that the replay uses present-day information and is not a faithful historical comparison.

| Fixture | Expected result |
|---|---|
| Internal-only but applicable Critical | Never label not affected merely due to exposure. |
| KEV finding, including an internal deployment | Expedited human route; exception preparation blocked. |
| Internet-exposed Critical | Expedited human route; exception preparation blocked. |
| Missing/null/unknown exposure or deployment field | Unknown remains unknown; no false safety from Go zero values. |
| Stale register, failed inventory, or partial scan returning zero rows | Block unsupported conclusions; retain visible data-quality failure. |
| Wrong repository, manifest, image platform, or dependency occurrence | No automated bump. |
| Already-fixed source with old runtime image | Rebuild/deployment action, not a no-op dependency PR. |
| Nonexistent or wrong-ecosystem target version | Registry/package validation rejects it. |
| Published version that does not contain the fix | Advisory/fixed-range validation rejects it. |
| Lockfile or transitive copy remains vulnerable | Candidate graph/SBOM/scan fails verification. |
| Old/wrong image accidentally submitted as candidate | Provenance/digest binding rejects the report. |
| Target CVE hidden through suppression or incomplete scanning | No verification pass. |
| New High/Critical introduced by the update | Required remediation verification fails. |
| Build/test/smoke failure or timeout | No verified status; human merge gate remains blocked. |
| Unexpected pipeline/test/scanner/package-source edit | Diff gate rejects the simple-bump plan. |
| Prompt injection requesting token disclosure or repo edits | No capability to perform it; proposal rejected/recorded where applicable. |
| Invalid JSON, unknown fields, duplicate keys, fabricated evidence ID | Assessment rejected or abstained; raw output retained. |
| Retry after successful PR creation but failed acknowledgment | Existing PR is located; no duplicate action. |
| Lease loss, crash after persisted intent, or overlapping schedule | Safe replay/reconciliation; no skipped finding or blind duplicate dispatch. |
| Evidence/target commit changes after verification | Existing verification/approval is invalidated. |
| Bot attempts protected merge, policy bypass, or exception activation | Effective permission test denies the action. |

The verifier must reject 100% of the predefined unsafe verification cases. The larger end-to-end workflow must reject the remaining unsafe action cases. Passing this suite is not proof that every possible unsafe production case is covered.

Before enabling writes, exercise the effective identities, not just mocked policy functions. Validate the pinned Kiro tool restrictions and Renovate configuration against deliberately malicious or unexpected fixtures in a disposable environment.

## 20. Two-week implementation plan

This is a proposed allocation across two calendar workweeks for a part-time engineer, not a promise of ten full engineering days. It assumes existing CI, candidate scanning, and an accessible working integration. Reduce scope rather than weaken controls when these prerequisites are absent.

| Period | Work | Exit evidence |
|---|---|---|
| Days 1–2 | Inspect sanitized existing app; map security API/auth/provenance; pick pilot repos/ecosystem; confirm data approval and candidate scanning; define baseline and policy thresholds. | File/function-backed integration map; one normalized finding; capability gaps; signed-off pilot scope. |
| Days 3–5 | Implement Go collector/contracts/state, hard rules, bounded Kiro adapter, review-card rendering, and offline replay. Begin baseline time measurement. | Read-only end-to-end assessment; raw versus validated results; negative tests; no live authority-changing action. |
| Days 6–8 | Add one constrained Renovate path, existing CI/SBOM/scan verification, PR linking, scoped exception proposal format, and permission tests. | Disposable/supervised proposals with complete verification evidence and enforced human merge gates. |
| Days 9–10 | Run supervised live sample; record reviewer ratings/time; exercise stops/retries; analyze outcomes. | Go/no-go or inconclusive report with counts, denominators, limitations, and recommended next scope. |

### Scope fallback

If candidate scanning, provenance, or safe updater integration is unavailable, deliver **triage-only** and explicitly report remediation as untested/unverified. A useful evidence-and-review workflow is a valid partial experiment; it must not be presented as evidence that automated fixes are safe.

Do not spend the spike provisioning AKS, a message bus, PostgreSQL, a custom UI, or a generic updater when existing pipelines can test the central hypothesis.

## 21. Experiment evaluation and go/no-go

### 21.1 Compare three workflows

Measure the current manual process against evidence assembly plus deterministic rules, and against the same evidence/rules plus Kiro interpretation. This distinguishes integration value from model value.

Use comparable case categories and include both easy and difficult findings. Where practical, have an independent Security reviewer adjudicate a sample without relying on the model's explanation as the answer key.

### 21.2 Metrics

| Metric | Definition / reporting rule |
|---|---|
| Reviewer agreement | Correct recommendations divided by all reviewed recommendations; show correct, wrong, and unsure separately and by category. |
| False exception proposals | Count confirmed unsafe raw recommendations and separately count those blocked before publication. Zero is the pilot target. |
| Useful coverage | Actionable useful recommendations versus eligible cases, abstentions, blocked cases, and out-of-scope findings. |
| Net classification saving | Baseline classification/whitelisting effort minus review, evidence checking, correction, and bookkeeping effort. |
| Fix quality | Prepared attempts, verified candidates, no-op/false-fix attempts, failed builds, rejected/abandoned PRs, and duplicates. |
| Remediation lead time | Separate time to proposal, verification, merge, deployment, and runtime-verified fix. |
| Reviewer usefulness | Explicit useful/noisy/uncertain rating and reason, not merely number of PRs created. |
| Safety-test rejection | Rejected unsafe cases divided by predefined unsafe cases, separated by verifier and other workflow controls. |
| Cost | Available model usage/billing, pipeline/build/scan usage, engineer effort, and reviewer effort; label unavailable measurements. |

The 2–5 minute review time is a target assumption, not an observed result. Count advisory confirmation time and correction work. Do not improve the reported average by hiding abstentions or only measuring easy cases.

For MTTR, use a consistent start such as first eligible observed finding and an end of runtime-verified remediation for that scope. Show unresolved cases and observation-window limits; do not calculate only from completed easy fixes. Two weeks may support a stronger conclusion about preparation time than deployment-level MTTR.

### 21.3 Success criteria

The original experiment's minimum criteria remain: zero real threats recommended for dismissal, no false dismissals for KEV/exposed Criticals, a majority of suggestions matching human judgment, positive measured reviewer-time savings, useful PRs, no hallucinated target releases, and rejection of all predefined unsafe verification cases.

Measure remediation-time improvement against the baseline where the observation window supports it. Otherwise mark that criterion inconclusive rather than converting time-to-PR into MTTR.

Agree any stricter numeric agreement or time-saving threshold before the live run. Report absolute counts and denominators alongside percentages. No observed false dismissal in a small sample does not establish a production error rate of zero or justify autonomous exceptions.

### 21.4 Stop/reassess criteria

Stop live automated proposal publication and reassess when a confirmed real threat is proposed for whitelisting, including an unsafe raw recommendation detected by a guardrail; more than half of reviewed suggestions are wrong; or review/correction work exceeds the effort saved.

Also stop or narrow the affected path for repeated nonexistent targets or false fix claims, actions on stale/out-of-scope evidence, inability to distinguish a real fix from a no-op/broken build, or a failure of permission/isolation controls.

Existing alerting and manual handling continue. Preserve the failure evidence, make a reviewed correction, and rerun the negative suite before re-enabling the affected path.

### 21.5 Decision categories

**Go—supervised expansion:** Safety gates pass, reviewer time improves, recommendations are useful, and the verified remediation path performs acceptably within the measured scope.

**Go—evidence/rules only:** Context assembly saves effort but Kiro adds insufficient value or introduces unacceptable error. Keep the useful integration and disable model interpretation.

**Inconclusive:** Too few representative cases, missing baseline, unobserved deployments, or unavailable verification prevents a reliable conclusion.

**No-go/redesign:** Safety, evidence quality, effective permissions, or net-effort criteria fail. Identify the failing category and required remediation rather than generalizing beyond the measured scope.

## 22. Decisions to confirm before implementation

| Decision | Responsible party | Default until resolved |
|---|---|---|
| Actual API/auth/query behavior from the working app | Engineer + security-platform owner | No assumed endpoints or live connection attempts. |
| Candidate-image scan/SBOM and reproducible comparison support | CI/scanner owner | Remediation remains unverified. |
| Pilot repositories, ecosystem, manifests, and update type | Engineering owners | No repository writes. |
| Freshness/completeness requirements and authoritative inventory scope | Security + platform owner | Unknowns block unsupported proposals. |
| Kiro account, permitted model/data handling, and runtime version | Security/platform administration | No company evidence sent to the model. |
| Azure DevOps Services/Server and approved identity mechanism | Azure DevOps administrator | Do not assume federation or task availability. |
| Branch policies, independent reviewers, and bot effective permissions | Repo owners + Security | No live change publication until tested. |
| Exception repository, approval authority, and activation process | Security | Proposal only; no source-system mutation. |
| Baseline definitions, evaluation thresholds, and stop ownership | Security reviewer + engineering sponsor | No success claim without agreed measurement. |
| Agent network path, storage permissions, retention, and logs | Platform owner + Security | Use only approved environments/data. |
| Event interface and collection cadence | Security-platform owner | Scheduled read with reconciliation when approved. |

These are implementation decisions to resolve through code inspection and existing owners—not reasons to invent missing integration details.

## 23. Definition of done and subsequent phases

### 23.1 Pilot definition of done

The security integration is documented from actual code; evidence and unknowns are represented explicitly; pipeline roles have tested permissions; and a bounded assessment produces an inspectable review item with a human outcome record.

For the remediation scope claimed as delivered, an approved published fixed version results in a constrained PR, independent candidate verification, required CI, and human-only merge. Runtime verification is recorded separately. Exception proposals are scoped, owned, reviewable, and inactive until the established human process applies them.

State survives restarts, retries do not blindly duplicate PRs, unsafe fixtures are rejected, stop controls work, and the final report includes baseline, outcomes, raw model errors, useful coverage, effort, and unresolved limits.

### 23.2 Expansion order

After a successful supervised pilot, broaden supported repositories/update types, improve source-image provenance, then add exposure/exception reassessment and shared-base-image consumer tracking. Introduce the queue worker only when coordination needs justify it.

Batch review, auto-tagging, auto-exceptions, and auto-merge each require a separate policy decision and a larger representative evaluation. They do not become enabled merely because an LLM confidence score is high or a service lacks internet exposure.

### 23.3 Final architecture principle

**Own the evidence contract, deterministic policy, source-to-artifact mapping, and verification. Reuse Kiro, Renovate, the scanner, Azure DevOps review, and existing deployment infrastructure.**

The model remains replaceable. The workflow remains useful when the model is wrong, unavailable, or removed.

## 24. References

Public documentation checked on 9 September 2026. References support external product behavior; internal company capabilities remain subject to the source-code and environment checks above. Tool schemas, tasks, authentication paths, and agent configuration should be rechecked when versions are pinned. Most requirements in this document are proposed design controls, not vendor-provided guarantees.

| ID | Primary source |
|---|---|
| S01 | [FIRST — CVSS v4.0 specification][S01] |
| S02 | [Red Hat — Security backporting practice][S02] |
| S03 | [Azure SDK for Go — azidentity][S03] |
| S04 | [Azure SDK for Go — azblob][S04] |
| S05 | [Azure SDK for Go — azservicebus][S05] |
| S06 | [Azure DevOps REST — Run Pipeline][S06] |
| S07 | [Azure Pipelines — YAML resources and incoming webhooks][S07] |
| S08 | [Azure Pipelines — Pipeline-completion triggers][S08] |
| S09 | [Go — encoding/json][S09] |
| S10 | [CISA — Known Exploited Vulnerabilities Catalog][S10] |
| S11 | [Kiro — Headless mode][S11] |
| S12 | [Go — os/exec][S12] |
| S13 | [Kiro — Custom-agent configuration reference][S13] |
| S14 | [OSV — Package/version query API][S14] |
| S15 | [Renovate — Azure DevOps platform support][S15] |
| S16 | [Renovate — Self-hosted configuration][S16] |
| S17 | [Renovate — Configuration options][S17] |
| S18 | [Renovate — Self-hosting security considerations and examples][S18] |
| S19 | [Azure Pipelines — Build Azure Repos Git repositories][S19] |
| S20 | [Azure Repos — Branch policies][S20] |
| S21 | [Azure Pipelines — Azure DevOps access with Entra workload identity][S21] |
| S22 | [Azure Pipelines — Job access tokens][S22] |
| S23 | [Azure Repos — Branch security and permissions][S23] |
| S24 | [Azure Storage — Blob concurrency management][S24] |
| S25 | [Azure Pipelines — Scheduled triggers][S25] |
| S26 | [Azure Service Bus — Message transfers, locks, and settlement][S26] |
| S27 | [AKS — Entra Workload ID overview][S27] |
| S28 | [KEDA — Azure Service Bus scaler][S28] |
| S29 | [CISA — VEX status justifications][S29] |

[S01]: https://www.first.org/cvss/v4.0/specification-document
[S02]: https://access.redhat.com/security/updates/backporting
[S03]: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity
[S04]: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/storage/azblob
[S05]: https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/messaging/azservicebus
[S06]: https://learn.microsoft.com/en-us/rest/api/azure/devops/pipelines/runs/run-pipeline?view=azure-devops-rest-7.1
[S07]: https://learn.microsoft.com/en-us/azure/devops/pipelines/process/resources?view=azure-devops
[S08]: https://learn.microsoft.com/en-us/azure/devops/pipelines/process/pipeline-triggers?view=azure-devops
[S09]: https://pkg.go.dev/encoding/json
[S10]: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
[S11]: https://kiro.dev/docs/cli/headless/
[S12]: https://pkg.go.dev/os/exec
[S13]: https://kiro.dev/docs/custom-agents/configuration-reference/
[S14]: https://google.github.io/osv.dev/post-v1-query/
[S15]: https://docs.renovatebot.com/modules/platform/azure/
[S16]: https://docs.renovatebot.com/self-hosted-configuration/
[S17]: https://docs.renovatebot.com/configuration-options/
[S18]: https://docs.renovatebot.com/examples/self-hosting/
[S19]: https://learn.microsoft.com/en-us/azure/devops/pipelines/repos/azure-repos-git?view=azure-devops
[S20]: https://learn.microsoft.com/en-us/azure/devops/repos/git/branch-policies?view=azure-devops
[S21]: https://learn.microsoft.com/en-us/azure/devops/pipelines/library/add-devops-entra-service-connection?view=azure-devops
[S22]: https://learn.microsoft.com/en-us/azure/devops/pipelines/process/access-tokens?view=azure-devops
[S23]: https://learn.microsoft.com/en-us/azure/devops/repos/git/branch-permissions?view=azure-devops
[S24]: https://learn.microsoft.com/en-us/azure/storage/blobs/concurrency-manage
[S25]: https://learn.microsoft.com/en-us/azure/devops/pipelines/process/scheduled-triggers?view=azure-devops
[S26]: https://learn.microsoft.com/en-us/azure/service-bus-messaging/message-transfers-locks-settlement
[S27]: https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview
[S28]: https://keda.sh/docs/2.20/scalers/azure-service-bus/
[S29]: https://www.cisa.gov/resources-tools/resources/vulnerability-exploitability-exchange-vex-status-justification-document-june-2022
