# 01 — Product scope and information architecture

## Product question

For each relevant vulnerability: **what is it, what is affected, why does it need attention, and what happens next?** The product is a decision workspace, not a second reporting dashboard. A simpler interface must not manufacture a cleaner inventory by hiding unresolved risk.

## Remove, merge, retain, defer

| Surface | Target treatment |
|---|---|
| Overview | No independent landing screen. Small inline, clickable counts only. |
| Vulnerabilities + Review + inspector | One Findings workspace and one shared, actionable CVE detail. |
| Timeline | Per-CVE meaningful history in detail. Legacy global read-only links retained during reporting transition; no primary nav item. |
| News | No primary navigation or mount-time fetching. Matching cached intelligence may inform a finding. |
| Whitelisted views | Exceptions register with type, exact scope, evidence, reviewer, validity, and status. |
| Manual CVE research | Secondary lookup; reference-only records never create affected inventory or counts. Explicit network action only. |
| Imports/replay | Keep backend capabilities and current safe entry points; admin/developer scope, not a new reviewer dashboard. |
| Ticketing | Action inside CVE detail with preview, confirmation, existing link, and recovery state. |
| Reports/charts | Grafana via a shared, versioned reporting projection. No new aggregate charts in Triagee. |
| Settings/account/data status | Small utility surfaces. No new settings page made only of explanatory prose. |
| Shared remediation/campaigns | Deferred. Group compatible work later without adding navigation. |

## Findings views

**Needs attention:** a distinct-CVE projection of exact operational targets that require a new human step. Examples: no effective decision/work, a due/expired/invalidated exception, overdue investigation/remediation/verification, a changed material fact that requires reassessment, an uncertain ticket operation needing reconciliation, or reported remediation still needing verification.

A current, not-overdue investigation is work in progress; the same unchanged missing evidence should not generate a fresh review on each scan. A new material fact or due boundary may bring it back to attention.

**In progress:** CVEs with an exact target under investigation, requested remediation, an existing remediation ticket, or awaiting verification. Due or exceptional items may also appear in Needs attention. This overlap is deliberate; view counts are not additive.

**All tracked:** all recorded operational CVEs, including active, excepted, and historical/inactive records. Preserve visibility of legacy reported-fixed records. Exclude public-reference/research-only records. Retain advanced active/history/severity filters where needed for old links; do not expose more top-level tabs for them.

One CVE can have production needing attention, staging excepted, and another deployment in progress. Never collapse that into a misleading global status. The row summarizes matching scopes; the detail shows per-target states and mixed-state counts.

Counts use the same search/scope/view predicate as their drilldown. Label any wider estate total separately. Show distinct CVEs versus deployment targets explicitly. Do not sum team counts to obtain an organization total when a CVE spans teams.

## Exceptions register

This is a flat register, not a KPI dashboard. Columns: CVE, Scope, Type, Rationale, Reviewer, Review/expiry, Status. Use compact summaries with full evidence in the same shared detail.

Types are **Risk accepted** and **Not affected**, with a clearly labeled legacy classification where the original source cannot support either more precise meaning. States include valid, review due, expired, invalidated, revoked/replaced, and pending. Preserve source store and record ID. A read-only union of workspace and case records is acceptable; merging their write semantics is not.

Default to current and review-due records. An archive filter exposes expired/replaced history. Selecting an exception opens its exact provenance and scope, not an unrelated current global CVE conclusion. Expiring/invalidated operational targets also surface in Findings.

## Actions

The shared detail supports investigation, local remediation planning, create/link ticket where backed by a real adapter/domain operation, temporary risk acceptance, a supported not-affected assessment, and reporting remediation for verification. Confirmation binds to the exact selected targets.

Do not create a fake Link ticket action by storing arbitrary user URLs as verified remote work. During M0 determine whether linking is already supported. Implement validated linking behind the same authorization and audit boundary, or keep existing-ticket display plus explicit creation and document linking as unavailable.

A reviewer can finish ordinary work without moving to a separate Review screen. Do not introduce a large assessment wizard for every CVE: reveal fields required by the selected action.

## First release versus later work

M1 may ship the unified workflow with compatible existing actions and a read-only legacy exception register. It is not the completion of M2: unimplemented typed assessments or verification must not masquerade as finished features. The complete core handoff requires the M2 semantics and M3 optional integration boundary, even when live credentials are absent.

Do not add automatic collectors, blanket suppressions, a free-form chatbot, generic risk-score dashboards, a case-management rewrite, or grouped remediation tickets in this build.

## Success measures

Baseline and compare the number of screen changes needed for a routine scoped decision; time from finding selection to evidence and to an explicit action; repeated attention on unchanged evidence; expired/invalidated exceptions rediscovered; ticket duplicates; and unsupported closure attempts. Use these as evaluation measures, not fabricated performance promises. Whitelist volume is not a success metric.
