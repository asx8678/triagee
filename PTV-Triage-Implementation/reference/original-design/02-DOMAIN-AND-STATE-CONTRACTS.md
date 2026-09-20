# State, counting and evidence contracts

## 1. Do not let a visual redesign change the truth

The screenshots currently expose several distinct facts through overlapping labels: open observations, scanner suppression, local exceptions, requested remediation, disappearance and actual repair. Keep these as separate dimensions. A cleaner page must not be achieved by deleting uncertainty or silently merging states.

This document specifies semantics to reconcile with the actual repository. It is not an instruction to replace the schema without inspection.

## 2. Core identities

An **advisory** has a canonical vulnerability identifier and any known aliases. A **package occurrence** identifies the vulnerable package/version in an immutable image/artifact context. A **placement** identifies a deployment of that artifact into a specific service/environment/cluster/namespace or other supported scope. An **assessment scope** binds the advisory and occurrence to the placement or explicitly defined assessment target.

The same image can have one package occurrence and multiple placements. The same CVE can affect several packages, images, services and teams. Never use a mutable image tag, display service name or team label as the sole durable identity for a decision.

The public-reference dataset is a different data domain from deployment evidence. Demo records are also separate. Retiring a placement does not erase its history, but it must not continue driving the current active-placement headline.

## 3. Separate dimensions

| Dimension | Example values | What it must not imply |
|---|---|---|
| Observation | Observed; not observed in a comparable completed scan; unknown/no coverage. | Not observed does not prove remediation. |
| Observation freshness | Fresh; stale; never observed; incomplete coverage. | A recent import does not mean every placement was freshly scanned. |
| Workflow | Needs decision; investigating; remediation planned; in progress; verification requested. | Work requested or ticket closed does not prove the package was repaired. |
| Exception | None; active scoped exception; expired; revoked; pending approval. | Accepted risk does not remove the active vulnerability. |
| Scanner suppression | Flag present/absent/unknown, source and provenance. | An imported suppression is not a verified human exception. |
| Applicability | Under investigation; affected; evidence-backed not affected, when supported. | Internal network placement is not automatically not affected. |
| Remediation verification | Unverified; evidence pending; verified for specified scope. | A vendor fix or scanner-reported fixed version does not prove deployment. |
| Exposure | Internet; internal; isolated, if genuinely evidenced; unknown. | Exposure classification is not proof of runtime reachability or exploitability. |
| Intelligence | Positive source match; no match in a known complete snapshot; not fetched; stale; failed; partial. | No match or unavailable data is not proof of no exploitation. |

Current badges may summarize several dimensions, but underlying values remain retrievable. For example, a row can simultaneously be Open, Risk accepted until 23 Sep, and Evidence stale. Do not select one badge and discard the other facts.

## 4. Count definitions

Every aggregation receives the same explicit dataset, team and environment predicate. Do not count all deployments in a CVE group after a filter has narrowed only the advisory IDs.

**Active CVEs:** count distinct canonical advisory IDs with at least one open, in-scope affected occurrence on an active placement, based on latest recorded evidence. Include findings that are suppressed or covered by exceptions. Add freshness qualifications when relevant. Do not treat this as a verified live count when the dataset is stale.

**Affected occurrences:** count package/artifact occurrences, not placements. **Affected scopes:** count the distinct assessment/deployment targets in the query. Use these exact unit names near numbers. The word "image" should count immutable images according to the actual inventory identity, not changing tag strings.

**Needs decision:** count distinct CVEs for which at least one in-scope target needs assessment, has an expired exception, is reopened under the policy, or is otherwise explicitly actionable. Maintain a separate work-scope count. Investigation can remain part of this work view, but state that choice consistently.

**Immediate priority:** distinct active CVEs whose applicable in-scope policy result requires immediate action. The label must not make every critical scanner finding automatically indistinguishable from all other critical findings unless that is actually the defined policy.

**Unknown exposure:** count in-scope affected targets with unknown exposure. If the card uses scope units, its drilldown can show unique CVEs but must retain and expose the exact matching target subset.

**Team counts:** deduplicate CVEs within each team. A shared CVE appears once in each affected team and once globally. Team totals therefore are not additive. An Unassigned bucket is explicit, not silently dropped.

**Fixed/verified count:** only count scope-specific, evidence-backed remediation. When legacy data records disappearance but no repair evidence, label it No longer observed and do not include it in verified-fix metrics.

Metric drilldowns must reuse the same query predicate as the metric. A regression test should compare the metric's identifiers with the identifiers returned by the linked table; matching only the numeric count is insufficient.

## 5. Observation transitions and coverage

Record scanner source, scan/run ID, the intended coverage target, observed-at, ingested-at, scan completion and any filtering/suppression rules. A row's absence from a partial import, failed scan or differently scoped inventory snapshot must not create a no-longer-observed event.

To infer not observed, require a comparable completed scan of the same relevant target and evidence that the target was covered. Preserve the reason and source. A known retired deployment is an inventory lifecycle event; it is not a package repair.

A stale observation remains the last known observation with a stale indicator. Do not remove it because the scan stopped arriving. If the product cannot establish current affectedness, show that uncertainty rather than replacing it with either a confident safe state or an invented current detection.

Out-of-order observations should be ordered by evidence time while retaining ingestion time. Duplicate imports should not inflate events or first-observed counts. Do not connect adjacent CVE observations from different placements into a fabricated continuous lifetime.

## 6. Time and timeline measurements

Store timestamps with an unambiguous timezone. Let the UI display the user's selected timezone consistently and expose UTC/exact values on inspection. Define daily bucket boundaries once and apply them to charts, totals and event logs.

First observed is the earliest eligible local observation for the chosen entity and scope. It is not the advisory publication date. A selected time window does not rewrite lifetime first-observed; label an in-window-first metric separately if needed.

Open age is elapsed time since the stated recorded start, not proof of continuous exposure. A re-observed episode can have its own episode age, while lifetime history remains intact. Do not silently restart or double-count an SLA timer; that behavior requires a documented policy.

Time to decision uses an actual recorded decision timestamp. Imported suppression with unknown author/date has unknown time to decision. Coincident import timestamps do not justify claiming an immediate human response.

Time to no-longer-observed uses an observation transition. Verified remediation duration uses verification evidence. These must never be plotted or averaged as the same metric.

For an exception date interpreted as the last covered day, convert the documented timezone's inclusive end-of-day to a stored expiration instant. Expiry evaluation must be deterministic and testable. State the timezone next to the date control/confirmation.

## 7. Action and exception scope

Persist an immutable target set for each committed assessment or exception. Capture the CVE, occurrence, placement, team/environment at decision time, decision type, rationale, responsible identity, created-at, expiration/due date, evidence references and policy version.

A decision for production does not silently cover staging. A decision for one team does not cover another team. A global-CVE exception is exceptional functionality: explicit broad scope, impact preview and appropriate authority, not the default.

Retain existing legacy global decisions as legacy records without pretending they were scoped or authenticated. Migration must preserve original meaning and provenance. Do not automatically approve missing scope or infer an approver from an import source.

In a local/no-sign-in tool, identify a entered name as self-declared. Real approval permissions require an actual identity/authorization design. UI fields alone do not create verified authorization.

Draft targets must not auto-expand on new findings, scope broadening, refresh or late data. Bind drafts to the advisory and intended scope context; reconcile changed identities before saving. Backend validation, not browser filtering, is authoritative.

## 8. Work decisions and external effects

Local decision commit and external ticket creation are separate operations with separate outcomes. A Save decision action must not unexpectedly transmit data. A ticket preview becomes stale if its target set or payload changes; require a new preview/confirmation when material inputs change.

Use stable submission identity, a durable local work record and explicit external result states: not requested, pending, succeeded with ticket ID, failed, partial success, or unknown result. If the remote system does not provide true idempotency, a client-generated key alone cannot guarantee exactly-once creation. Reconcile through durable linkage/search before retrying ambiguous outcomes.

A closed ticket should move work toward verification, not automatically mark the affected occurrence fixed. Similarly, an AI recommendation, a available upgrade target or a risk acceptance does not modify observation facts.

## 9. Priority and confidence

Keep recorded scanner severity unchanged. Compute work priority through a versioned, explainable policy whose inputs are independently visible. Do not invent an organization-wide risk score by averaging scanner severities.

Expose both positive evidence and unknowns. "Known exploited" means the specific intelligence source contains a positive record; "we are being exploited" requires separate local evidence. An absent or unrefreshed cache must not generate a reassuring negative statement.

If EPSS is added later, label it as exploitation likelihood for the published CVE over the next 30 days, with source and date, not as deployment-specific risk or compromise probability. FIRST describes this prediction scope; see Design Spec reference R6. Keep this enrichment optional rather than adding more badges before the core evidence model is sound.

## 10. Update correctness

List, overview and detail reads should reflect a consistent snapshot/version where possible. During refresh, retain the selected item and draft. Show "New data available" rather than reordering the queue beneath the operator.

Commit decisions with a version check or comparable concurrency control. Present conflicts and changed targets explicitly. Audit committed changes rather than overwriting historic assessment text. UI sorting and filtering are never security or authorization boundaries.
