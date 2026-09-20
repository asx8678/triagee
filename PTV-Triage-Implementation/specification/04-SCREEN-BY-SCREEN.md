# 04 · Screen-by-screen implementation specification

## 4.1 Shared application shell

Top navigation order: PTV Triage brand, Overview, Vulnerabilities, Review with queue count, Timeline; local workspace context and Data & settings at right. Do not add a sidebar or move settings into a competing main destination. Brand activation goes to Overview using normal navigation semantics.

The second row holds Team, Environment, dataset scope indicator, Reset scope and evidence-health access. Team/environment are genuinely shared predicates. A local inventory query or timeline window is not the same as shared scope. Keep controls visible on ordinary desktop; reflow at narrow widths as the baseline shows.

Read context belongs in route/query state where supported: page, shared filters, local view/search/sort, advisory, inspector section and timeline window/type. Sensitive decision text, credential values and draft content never belong in the URL. Back/Forward must reproduce logical read state without committing work. Reset scope affects scope filters, not unsaved decisions; warn/reconcile when context changes would hide draft targets.

Build a compact honest bottom status row with workspace/source context. Do not label the actual app “interactive prototype” or show a fixed sample clock. In the isolated screenshot fixture, reproduce the accepted synthetic footer so the baseline is directly comparable.

## 4.2 Overview — operator landing

**Reference:** `overview-1600.png`, `overview-1920.png`, `overview-390.png`.

**Hierarchy:** page heading/actions → attention/confidence callout → four metrics → team ownership and short action list → urgent findings and evidence health. Maintain the exact visual order and relative panel proportions. Operational questions should be answerable before opening another tab.

The attention message describes current policy-required work, not a guessed breach. Its separate confidence block describes freshness/coverage limits. When there is no immediate work but evidence is incomplete, show that combination rather than a green “Safe” state. The main data-health control remains available even if a compact breakpoint hides the longer confidence text.

Metric1: **Active CVEs**, distinct affected CVEs in the current deployment scope. Secondary label gives underlying affected-scope count. Suppression and risk acceptance do not subtract active exposure.

Metric2: **Need a decision**, distinct CVEs with at least one actionable in-scope target. The review-nav badge follows the same shared scope/eligibility rule. Keep a separate work-scope total if displayed; do not rename it “CVEs.”

Metric3: **Immediate priority**, distinct active CVEs with at least one in-scope immediate-priority result under the real versioned policy. Do not bring in a higher priority from an out-of-scope environment. Unknown policy input must remain visible.

Metric4: **Exposure unknown**, affected deployment scopes, not advisory count. Its drilldown retains the exact unknown target subset even if the resulting inventory groups those targets by CVE.

Each metric is a real navigation action with meaningful accessible label. Its contributing ID set is a first-class test contract. While data loads, show placeholders, not transient zeroes. On partial/stale data show accurate qualification near the metric/callout.

Team ownership includes every in-scope team with relevant work and an explicit **Unassigned** bucket. Columns retain team, active, critical, decision work and unknown exposure/ownership action as the reference shows. Count each CVE once per team. Explain once that team rows are not additive because findings can be shared. Clicking an active count opens inventory; decision count opens that team's queue, retaining Environment. Buttons with zero work must not imply an error; show an empty matching result or disable with a clear reason consistently.

Next actions are deliberately short: urgent work, expiring exceptions, unknown ownership and missing/freshness evidence. Every row has a precise destination/predicate, not a generic “Go to Review” for unrelated work. Exceptions include remaining valid coverage/timezone; expired exceptions return affected work to the proper queue.

Urgent findings open the common inspector. Evidence-health summary opens detailed source/run receipts or settings. Do not trigger a scan/refresh just by opening it.

## 4.3 Vulnerabilities — compact investigation table

**Reference:** `inventory-1600.png` and original inventory preview.

Page title, short subtitle, density and export controls. Panel tabs: Active, Risk accepted, Observation history, All; show a contextual P1/Unknown exposure tab when reached from a metric. Avoid another stack of explanatory sections before the table.

Toolbar: search CVE/package/service; severity; priority/oldest sort; Save view and Saved views. Scope remains in the global bar. The visible result summary states exact count/filters/dataset exclusion. Primary filters are not buried in a help accordion.

Columns: selection checkbox; advisory/package; severity; priority; affected ownership/scopes; exposure; work status; age; fix info; compact open control. Use canonical CVE identity as the main link and package/re-observation/suppression metadata as secondary text. Keep versions/short IDs atomic. Long service/image values have deliberate wrapping or full-value disclosure, never character-by-character collapse.

Selection and opening detail are separate targets. Clicking the CVE or arrow opens the inspector; a checkbox changes selection only. Header checkbox shows checked/unchecked/indeterminate correctly. With server pagination, label whether selection means current page or all matching rows; never imply unbounded selection from loaded rows alone.

Selection toolbar shows exact count, Review selected, Export selected and Clear. Review selected freezes an explicit advisory set, preserves global scope and visits one record at a time. It is **not** bulk risk acceptance or bulk remediation. Revalidate scope targets in the review form.

Density toggle preserves filters, scroll and selected records; comfortable is the accepted default. Saved views preserve filter/sort/density as intentionally supported, not draft text or operator identity. Restoring a view never commits a decision. Scope changes reconcile selection and make changes visible rather than applying a hidden broader selection.

Row statuses can be mixed because targets differ. Open, risk accepted and stale evidence may coexist. “Fix available” means reported remediation information, not installed. The table footnote retains that distinction once rather than repeating paragraphs per row.

Pagination/virtualization must expose the true total, maintain stable keys and keyboard access, and never silently cap100 records or50 lanes. Sort ties deterministically by stable advisory ID. Closing detail returns to the same row/scroll/filter/sort context; refetches must not jump the operator to the top.

## 4.4 CVE inspector — shared across all entrypoints

**References:** `inspector-{summary,affected,history,evidence}-1600.png`, `inspector-expanded-1600.png`, `inspector-390.png`.

Use one implementation from Overview, inventory, review and timeline. Right-side dialog/drawer; header contains advisory label, contextual dataset, identifier, severity, priority, package/scope, Expand and Close. Tabs: Summary, Affected assets, History, Evidence. Footer: scope note, Close and Review this CVE.

Header/tabs/footer remain fixed within the drawer while only the body scrolls. Expand/restore changes width without losing tab, body position, focus or record. Escape closes the top dialog only. Return focus to the actual triggering item when it still exists, otherwise a logical stable fallback. Closing the inspector does not reset the underlying page or draft.

**Summary:** compact factual overview, six relevant evidence/status facts, recommended next step with policy attribution, affected teams/environments, data confidence. No autonomous “Safe” verdict. **Affected assets:** scope identity, image digest/package, team/environment, exposure evidence, work/exception/suppression, last recorded observation. **History:** exact scope-filtered recorded events, with timestamps/source and no invented continuous lifetime. **Evidence:** source/run IDs, completeness, observed/ingested times, policy version, intelligence provenance and unavailable fields.

Do not render all scopes when the filtered record has none; explain that the advisory is outside the current scope and offer an explicit clear/broaden action. An inspector opened from a timeline event starts on History and identifies the selected event. History respects event scope rather than leaking a decision from another team into the current filtered view.

Review this CVE closes the inspector and opens that advisory's assessment with the same relevant scope and originating context. It must not drop the user into an unrelated first queue item. Where no assessment is applicable, explain why and show the supported next action; do not call an unsupported mutation.

Support full evidence deep links/expanded views where the existing application needs them, preserving the same visual system. Keep short-format values visible and provide keyboard-accessible copy/full value for long digests. Copy is a local operation; it must not fetch from external sources.

## 4.5 Review — the central working screen

**References:** `review-1600.png`, laptop/mobile/boundary variants and review dialog captures.

Page heading/actions; queue-view tabs; optional queue search; main two-area layout. Queue at left; selected advisory workspace at right. On normal wide desktop, the workspace body itself splits into evidence and decision columns. Below1151px, evidence and decision stack within that workspace. At640px and below, explicitly toggle between queue and assessment.

Queue tabs: Needs decision, In progress, Exceptions. Decision history is a secondary header action, not a separate competing review system. A selected-only batch or direct advisory entry can expose an explicitly labeled special view. Display the actual matching total, stable priority ordering and current selected record. Each row shows ID, priority, package/severity, team/scope count and meaningful overdue state. Never hardcode every item as overdue.

The selected header shows advisory, severity, priority, package, scope count and real freshness. Full evidence opens the shared inspector without losing draft. Previous/next controls navigate queue without committing. Arrow keys or j/k shortcuts are optional enhancements only with proper text-field/modal exclusions; do not override native input behavior.

Evidence order: priority/action strip with Why; short summary; exploitation and fix facts; compact affected-scope table; supporting priority rationale; technical evidence/provenance; optional AI assistance. Preserve the concise core facts. Lengthy descriptions and policy explanations expand below; they do not block seeing the action form.

Scope table includes checkbox, team/environment, service, exposure and relevant observed-at evidence. Default target selection must be transparent and valid for the chosen work view. Show selected count both near the table and in the decision form. Draft target identity is immutable once selected; narrowing a filter may hide targets, but must not silently drop or expand them. Ask for reconciliation or retain the draft context with an explicit count of hidden targets. Confirm the final exact set before broad/risk operations.

Decision selector changes fields/labels in-place, not navigates to another page:

| Action | Required information | Result |
|---|---|---|
| Request remediation | Selected targets, owner, due date, note | Local work plan; observation remains unchanged. |
| Investigate / gather evidence | Selected targets, responsible person, follow-up date, question/note | Investigation work; unresolved exposure remains visible. |
| Accept risk temporarily | Explicit targets, rationale/controls, expiry/timezone, attribution/authority appropriate to app | Time-limited exception; no removal of active CVE. |
| Request verification | Explicit targets, owner, follow-up, claimed evidence/work reference where supported | Verification task; not verified remediation. |

Commit validates on the server, uses a version/snapshot check and records an audit event. Empty required fields show inline errors plus accessible summary/focus. Canceling an exception confirmation leaves every field/checkbox unchanged. Editing targets/action/expiry after a preview invalidates that preview.

Persistent footer: draft-versus-submitted indicator, Save decision, Save & next. Save decision commits without deliberate navigation away; if the record leaves the current queue, retain a clear saved/read context or select next only through an explicit documented behavior. Save & next commits successfully first, then selects the deterministic next eligible record. Failure/conflict leaves the current record and entered form intact. A pending save disables duplicate submission with a visible progress label; it never blocks inspection indefinitely.

No decisions should be submitted by opening a record, changing filters, closing a drawer, switching tabs or restoring drafts. Do not copy the prototype's lack of durable conflict/expiry handling into production.

Azure DevOps appears as a compact integration state in the decision area. Local save always remains available when its own validation succeeds, even when ticket submission is unconfigured. Optional AI assistance stays under its disclosure and never becomes a mandatory step or automatic approval.

## 4.6 Review dialogs and history

**Risk acceptance:** show CVE, number and table of exact targets, rationale, expiry in the specified timezone and real/self-declared attribution. Cancel is safe. Confirm is explicit. Production button text must not claim “demo” outside the test fixture. Creating an exception does not create a ticket by accident.

**Ticket preview:** destinations per responsible team; CVE and selected target content; existing linked tickets; integration readiness; explicit outbound-confirm action. A disconnected button remains unavailable with a reason. Unknown results are not “failed, retry now”; require reconciliation. Partial success is per team/target group so already-created tickets are not recreated.

**Decision history:** unify historical assessments in one readable audit view while preserving legacy distinctions. Display decision time or Unknown, target scope, action, attribution, rationale, expiry/revocation and evidence. Separate current work from historical facts. Do not turn imported suppression into a fabricated human decision.

## 4.7 Timeline — retain the recognisable tracks

**References:** `timeline-tracks-1600.png`, `timeline-log-1600.png`, `timeline-daily-1600.png`.

Page title/subtitle, time-window and export controls. One panel with CVE tracks/Event log/Daily activity tabs, event-type filter, compact statistics, legend, content and footnote. These views are siblings, not a long stack of repetitive sections.

CVE tracks retain the horizontal date axis, fixed left CVE labels, compact alternating lanes and sparse event markers. Keep shapes/colors for first/repeated observation, re-observation, no-longer-observed, requested work, exception and verified remediation. A marker hover/keyboard action gives exact event time, target and source. Activation opens the same inspector on History. No marker shape alone claims continuous presence.

Coverage is derived from actual comparable scan coverage. Do not hatch arbitrary weeks based on a fixed sample. Date window, coverage, event counts, lane data and accessible log must reconcile. Maintain all matching lanes with accessible scrolling/pagination. Expansion into per-scope history must avoid joining incompatible targets into a false single lifetime.

Event log is a compact table with exact timestamps, CVE, type, scope and source/detail access. It is the complete accessible alternative to the chart, not a truncated sample. Long zero-activity intervals can be one expandable gap; distinguish absent scan coverage from a completed scan with no new first observations.

Daily activity counts distinct first-observed CVEs according to the stated local entity/scope/timezone definition, not publication dates. Multiple targets for one CVE must not inflate a distinct-CVE cell. Future days show a dash/unavailable shape, unknown coverage uses hatching, a scanned day with zero new observations can show0. Day activation drills to contributing records and retains the time window. Events with unknown time are disclosed separately, not assigned a guessed date.

Avoid the old ambiguous “Fixed / whitelisted on / Time taken” table. If reporting is retained, split open age, decision delay, time to no-longer-observed and verified remediation duration. They have different source facts and denominators.

## 4.8 Data & settings

**Reference:** `settings-1600.png`.

One compact home for dataset/source identity, latest successful and failed/partial runs, coverage, intelligence-cache status, Azure DevOps readiness, AI configuration, local workspace state and explicit data tools. Ordinary navigation is read-only. Refresh/import/export/reset operations keep their existing confirmations and scope boundaries.

Keep the reference modal geometry for the summary. A larger settings route can host genuine configuration forms using the same primitives when the real app needs it; do not cram secrets and every field into the small summary modal. Sensitive values remain server-side; show configured/not configured rather than the credential itself.

“Reset synthetic data” belongs only to the demo/test fixture. It must not become an unlabeled production reset button. Production destructive data actions require their own explicit, accurately scoped safeguards and are not added merely because the prototype has a reset option.
