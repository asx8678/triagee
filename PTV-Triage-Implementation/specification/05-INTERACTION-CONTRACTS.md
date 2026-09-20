# 05 · Interaction, navigation and side-effect contracts

## 5.1 Three operation classes

Read/navigation operations change visible state only. Local commitments save authenticated/self-declared scoped work according to the actual app. External operations transmit data or create resources and need separate explicit controls. Treat these classes distinctly in event handlers, tests, disabled states and audit logging.

A footer label, route change or “success” toast is never sufficient evidence of persistence. Successful local commit must return the durable decision and target set; external success must return an actual linked remote ID.

## 5.2 Read/navigation behavior

| Trigger | Required outcome | Preserve |
|---|---|---|
| Main destination | Open the correct real route/view | Shared scope; noncommitted draft state; logical Back history. |
| Team/environment change | Requery every scoped aggregate/detail consistently | Draft target identity; notify on hidden/out-of-scope targets. |
| Reset scope | Reset visible scope filters | Saved decisions/history; no automatic draft deletion. |
| Overview metric/team count | Open exact contributing entity/target set | Environment/dataset; predicate lineage. |
| CVE link/open arrow | Open shared inspector for that identifier | Table filter/sort/page/scroll/selection. |
| Inspector tab | Change content only | CVE, scope, opener and appropriate per-tab position. |
| Expand inspector | Change width only | Tab, record, context, draft and focus. |
| Review this CVE | Select that CVE in assessment | Scope and origin; no generic first-item fallback. |
| Queue row/previous/next | Switch assessment without commit | Per-record draft with exact targets. |
| Timeline marker | Open exact event on History | Window, filters, chart position and event ID. |
| Search/sort/density/view | Change list/read presentation | Stable current selection according to explicit semantics. |
| Escape/Close | Close only topmost overlay | Parent state and logical focus return. |

Selection is never synonymous with applying an action. View state changes must not invoke mutation endpoints. Use the browser's normal navigation/Back semantics rather than repeatedly replacing all history with one hash. The standalone renderer's simplified URL helper is not production routing guidance.

## 5.3 Draft lifecycle

Draft identity includes operator/session identity appropriate to the app, advisory ID, stable target context and a version. Store action, selected scope IDs, owner, dates, rationale and any evidence references. Do not key drafts solely by a display label that can change or collide.

Draft save is not decision submit. A visible “saved” indicator must state whether it means server-backed draft, permitted local draft or session-only data. Do not put sensitive production evidence in localStorage without an explicit existing product/security decision. Prefer the app's existing server/session draft capability; add a compatible facility only when needed.

Changing an action preserves common fields unless their meaning changes, in which case surface the field change. Changing filters must not silently intersect a draft's targets and permanently lose hidden selections. Reopening the original context must recover the draft, not select new discoveries automatically.

Refresh with newer evidence shows a stable “New data available” indication. Do not reorder the queue or widen a target set underneath an operator. Before commit, compare snapshot/version and ask for reconciliation where targets or authorization changed. A deleted/retired scope is not substituted by a new deployment sharing a mutable image tag.

## 5.4 Commitment behavior

Validate explicit targets, action, responsible attribution, rationale, relevant date/timezone, policy eligibility and permissions on the server. Client validation is immediate assistance only. Require date parsing and expiry logic that is correct for the selected timezone; use a half-open expiration instant at the next day's boundary for inclusive-date semantics rather than hardcoding23:59:59 with lost fractions.

A commit transaction records the decision/work change, immutable target snapshot and audit event coherently. Use an operation identifier and optimistic concurrency or equivalent. Guard duplicate clicks/retries. If the response is lost, resolve commit status without duplicating the decision. A stale form cannot overwrite a newer decision silently.

Save decision leaves the operator with a visible confirmed result. Save & next advances only after confirmed success. If a current item remains actionable for another scope, clearly retain/requeue that remainder. If all work is exhausted, show a truthful empty state—not a safe verdict. A failed save keeps fields, selections and position intact and focuses the relevant error.

Risk acceptance confirmation shows exact targets and expiry; Cancel writes nothing. An accepted exception has a visible expiry/revocation lifecycle. Renewal creates a traceable new decision, not a silent edit erasing the original rationale. An expired exception returns still-affected targets to the correct queue.

## 5.5 External operations

Local remediation work is saved independently of Azure DevOps. Preview resolves configured team destinations and existing links. Capture a payload fingerprint/target version so a material edit invalidates the preview. Confirm is the actual outbound operation; ordinary Save decision is not.

Track not requested, ready, submitting, succeeded, failed, partial and unknown outcomes with per-team detail. Store successful remote links before presenting another retry opportunity. A network timeout after remote creation must not be treated as guaranteed failure. Reconcile uncertain results before retry. A client operation ID alone does not guarantee a remote platform's exactly-once behavior.

AI requests show configured provider/runner and outbound context, require the existing explicit operation, and record advice separately from a human decision. They cannot approve exceptions, mark remediation verified or create tickets by implication. Unconfigured AI does not block human review.

Intelligence refresh is an explicit operation; show source, completion, freshness and completeness. “Not fetched” and “no match in a complete source snapshot” are different states. Never replace either with an unsupported assertion of no exploitation.

## 5.6 Exports, saved views and clipboard

Exports use the visible predicate/selection and explicit units, include scope/time/source metadata where supported, and omit secrets. An export of selected CVEs must not expand to another team's scopes. Keep current production format support or document the needed format implementation; do not rename a CSV download as JSON without changing content.

Saved views preserve supported read filters and sort; they do not bind drafts or include credentials. Validate a view after the team/environment is deleted and show an explanation rather than broadening to All silently. Clipboard actions are explicit local actions and handle denied clipboard access with a truthful message.

## 5.7 Complete control inventory

`contracts/reference-actions.json` is generated from the accepted JavaScript's event switch and input identifiers. It enumerates every reference action and its source location category, so the agent can map each to a real route/handler/test. Mark prototype-only actions as excluded from production; do not simply delete an unimplemented control without reporting parity impact.

Fill the action-to-handler mapping in the repository audit. A production screenshot containing an enabled control is a claim that the action is implemented. Verify it with an interaction test, or disable/remove it honestly in accordance with the delivery scope.
