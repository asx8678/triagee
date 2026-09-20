# CVE assessment and local exceptions

This guide preserves the case-exception domain and former operator procedure.
The old finding/case/exception URLs now redirect to the workspace, so the steps
below are not currently mounted screens. See [README](README.md) for current UI
availability and [review actions](docs/REVIEW_ACTIONS.md) for placement decisions;
those decisions are distinct from the case-bound exceptions described here.

## Former case workflow: start from a CVE

1. Click the CVE in Findings, Activity, Timeline or the review queue.
2. At **Triage / action required**, find the exact package/version, image, team and environment. Click **Open assessment**. This opens the existing case or explicitly captures local evidence for a new one; simply viewing a CVE never creates cases.
3. The assessment form has **Applicability**, **Priority**, **Next action** and **Rationale**. Inspect the evidence and cached exploitation signals, then record investigation, upgrade, rebuild/deploy or mitigation steps as appropriate. Saving these fields alone does **not** suppress anything.
4. To make an exception, choose **Manage local exception / reopen** on the case.

## Choose the right decision

- **Temporarily suppress locally / accept risk**: the vulnerability may apply, but a documented risk is temporarily accepted. Explain the constraint, compensating controls and remediation plan. This is not a claim that the CVE is harmless.
- **Not affected — with evidence**: explain why this exact occurrence is not exploitable in this deployment. Supply evidence/reference: for example vulnerable feature absent, a verified build configuration, or a reviewed reachability analysis. Unknown exposure, lack of a public exploit or absence from the cached KEV feed are **not** sufficient evidence.
- **Reopen / revoke exception**: give the reason for renewed investigation. This is allowed even if the source changed or the placement retired. The old decision remains in history.

All decisions require a reason (up to 2,000 characters). Exceptions additionally require a review/expiry date from tomorrow through 90 days ahead. Not-affected decisions also require nonblank evidence (up to 2,000 characters). Confirm the displayed package, image digest, team, environment and frozen snapshot before saving.

## Scope, expiry and review

There is **no blanket CVE whitelist**. Each decision covers one finding occurrence (package/version/image) in one team/environment case. Other packages, images and teams keep their own action status. Scope, actor and evidence binding are set by the server, not editable form fields.

An exception expires at **00:00 UTC on the selected date**. A changed source, retired placement, refreshed snapshot or subsequent assessment invalidates the exception and returns it to **Action required**. Status is recalculated on page load/reload and after saves; an already-open page is not a live expiry notification. There is no background renewal, notification or automated suppression job.

To renew, review current evidence and explicitly save a new decision with a new date. Refresh stale evidence from the assessment page first. Conflicting tabs and recovered drafts must be explicitly rebound after the new evidence/history is reviewed; the application does not silently transfer a draft to another snapshot.

## What changes—and what does not

CVE action rows, finding details and the review queue display the **local action status**. Decisions and revocations are recorded in an append-only history with the server-owned `local-operator`, time, snapshot and revision. The original records are not edited or deleted.

Raw inventory remains visible. Scanner severity, scanner suppression flags, imported observations, deterministic risk priorities, Timeline and exported/imported report facts are unchanged. **No remote scanner whitelist/suppression API is called**, and no decision verifies remediation. This release provides local triage exception management, not external suppression.

The application is still a loopback-only, unauthenticated local-operator tool. These records are not multi-user approvals. Shared deployment requires authentication/authorization and approval policy before treating decisions as organizational acceptance.

## Installation

The additive migration `priv/repo/migrations/20260916162740_create_local_exceptions.exs` must be applied to the intended application database before running this version (`mix ecto.migrate` in the correct environment after normal backup/review). Verification uses a separate owned disposable database; it does not migrate the operator's working data.
