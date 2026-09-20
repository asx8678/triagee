# 09 · State, failure and edge-case catalog

The accepted reference chiefly shows a populated stable dataset. Implement the following real states using the same compact components and typography. Do not invent large illustration-driven empty pages or repeated full-width warnings. Each condition needs a fixture and a test; none is covered merely by the happy-path screenshot.

| State | Expected presentation | Required behavior |
|---|---|---|
| Initial loading | Stable metric/table/queue skeletons in existing geometry | No temporary0, Safe or fabricated freshness. |
| Background refresh | Existing data with small updating/new-data indicator | Preserve row, scroll, filters and draft; do not reorder underneath typing. |
| Filtered empty | “No matching vulnerabilities” plus exact scope/reset action | Distinguish from no data and from no active exposure. |
| No imported operational dataset | Compact setup/evidence-health message in existing page frame | Do not treat public references as deployed findings. |
| Empty decision queue | “No decisions waiting here” plus active inventory access | May coexist with active accepted/planned work or coverage gaps. |
| Stale data | Scoped as-of/freshness qualifier and source details | Keep last known affected state; do not silently remove it. |
| Partial/failed import | Source/run/completeness information and safe retry path | Missing rows do not become disappearance/fix events. |
| Intelligence not fetched | “Exploitation intelligence unavailable” | No assertion of no exploitation. |
| Complete snapshot with no match | Source/date-qualified no-match text | Not equivalent to proof of no exploitation. |
| Unknown exposure | Labeled amber Unknown, exact affected-target count | Do not infer safe from service name or internal placement. |
| Mixed scoped state | Compact Mixed status with detail access | Preserve open + accepted + stale as separate dimensions. |
| Scanner suppression, no attribution | Scanner-suppressed; approval/date unknown | Does not enter approved exceptions history as a human action. |
| Active exception | Expiry and scope visible | Active vulnerability count is unchanged. |
| Expired/revoked exception | Return affected targets to actionable work, with history | Do not silently renew or delete old rationale. |
| No longer observed | Neutral observed-state label and evidence source | Not shown as verified fixed. |
| Verified remediation | Scope-specific evidence and verification attribution/time | Green only for this proven-positive state. |
| Retired scope | Inactive/retired target and lifecycle context | Not package remediation; do not retarget old decisions automatically. |
| No owner/team | Unassigned bucket and clear assignment path | Not omitted from aggregation. |
| Long values | Internal wrapping/scroll/full-value control | No page overflow or hidden action footer. |
| Form invalid | Field errors and summary/focus within workspace | Preserve all entered values and checked targets. |
| Save pending | Localized progress and duplicate-submit guard | Do not change queue before confirmed commit. |
| Save rejected/offline | Visible actionable error with retry | No success toast, no lost draft, no accidental duplicate operation. |
| Stale version/conflict | Newer evidence/decision explanation and reconcile action | Preserve draft; do not overwrite silently. |
| Target changed while editing | Exact missing/new/retired target differences | New targets never auto-join the saved set. |
| Integration disconnected | Small status and setup access; explicit unavailable remote control | Local decisions remain usable. |
| Remote partial success | Per-team success links and remaining failures | Do not re-create successful tickets. |
| Remote unknown result | “Result unknown — reconcile” with durable request identity | No blind retry presented as harmless. |
| Draft persistence unavailable | Session-only/unsaved warning near footer | Never claim a durable save. |
| Deep-linked record filtered out | Explain out-of-scope state | Offer explicit scope change; never fallback to all targets. |
| Permission/identity limitation | Specific action unavailable with reason | Do not invent approved identity from a name field. |

## 9.1 State composition

Several rows can apply simultaneously. A CVE can be open, scanner-suppressed, covered by one team's temporary exception, stale in another environment and unassigned elsewhere. Summaries must not collapse these facts into one safe/closed badge. Show a concise primary workflow status plus supporting evidence qualifiers and detail access.

Prioritize messages by task: a save-blocking validation error sits at the form; stale data is a persistent evidence qualifier; a disconnected optional integration is a small local section. Do not repeat all caveats above every table.

## 9.2 Date and scope edge fixtures

Test same advisory across two teams, production/staging and multiple images; case/alias identity; missing team; changed image tag but same digest; replaced digest; re-observation; two scans arriving out of order; duplicate import; incomplete scan; unknown action date; inclusive exception expiry; leap day and daylight-saving boundaries; events at exact window endpoints; future heatmap dates.

The supplied synthetic fixture is the visual fixture, not exhaustive edge coverage. Add real-shaped backend fixtures for these conditions in the existing test suite and record their mapping in the acceptance evidence.

## 9.3 Formatting and error copy

Use short factual messages. Examples: “Last observed9Sep · stale,” “Not fetched,” “No longer observed,” “Scanner-suppressed · approval unknown,” “Decision saved for2scopes,” and “Save failed; your draft is unchanged.” Use normal spacing in the rendered text. Avoid blame, vague “Something went wrong” as the only explanation, or success wording for unconfirmed operations.

Raw stack traces and credential-bearing payloads do not belong in operator UI or exports. Provide a correlation/reference ID and sanitized details where the existing app supports them.
