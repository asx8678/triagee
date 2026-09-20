# PTV Triage — UI and workflow specification

## 1. Product objective

An operator opening the application should be able to answer four questions without navigating away: How many distinct CVEs are active in the selected deployment scope? Which need a decision or urgent work? Which teams own the affected deployments? How reliable is the evidence behind that assessment?

The next task is to decide and assign work without losing the queue, the selected advisory or its exact scope. Historical investigation should remain available without dominating daily operations.

This is an information architecture and workflow change, not just a reduction in padding. Preserve useful evidence and safety semantics while replacing repeated warnings with accurate, compact state labels and one evidence-health surface.

## 2. Audit of the supplied screens

The filenames identify the supplied screen captures. Similar screenshots are grouped by the function they expose; every supplied capture is accounted for.

| Screens | What the capture shows | Design response |
|---|---|---|
| 13.25.28, 13.25.38 | Vulnerability inventory with collapsed/expanded filters, prominent reference-data warning, global and filtered counts, repeated cache explanations, long table headings. | Add Overview as the landing page. Keep inventory for investigation. Separate reference data from deployment findings. Always expose search/team/environment. Make count units explicit and move source diagnostics into Evidence health. |
| 13.25.47 | Aggregate CVE detail with competing assessment actions, nested tables and compressed package/version/state columns. | One reusable, generous inspector with Summary / Affected assets / History / Evidence. Keep versions and action controls intact; scroll only the table region when necessary. |
| 13.25.54 | CVE detail continuation with extensive public-intelligence/cache text and a generic Open review queue action. | Show intelligence state and timestamp once; put receipts/raw records in Evidence. Replace generic navigation with Review this CVE, carrying the exact advisory and scope. |
| 13.26.02 | Action queue with repeated Select text, long descriptions and a prominent Triage issue button on every row. | Compact left-hand review queue. One selected advisory and one primary decision action. Description becomes a short package/problem summary; exact scope is selected in the assessment. |
| 13.26.10 | Previous assessments page containing active needs-review work and additional status counts. | Consolidate actionable work in one Review destination. Preserve historic assessments under Decision history; do not keep a second ambiguous current-work queue. |
| 13.26.19 | Review step 1 dominated by navigation, progress headings and a large single-content card. | Place the short vulnerability explanation and essential evidence directly in the review workspace. No Next page is required merely to read evidence. |
| 13.26.27, 13.26.35 | Review step 2 shows large repeated cards for production and staging. | Replace with an affected-scope table. The same image deployed to multiple environments remains distinct selectable scope, without repeating the whole advisory. |
| 13.26.42 | Review step 3 repeats severity/policy caveats and gives unavailable AI assistance substantial space. | One concise priority explanation, expandable rationale, optional AI assistance under supporting evidence. Missing AI configuration does not obstruct human review. |
| 13.26.49, 13.26.56 | Step 4 has large parallel whitelist/remediation cards, distant confirmations, disconnected ticket configuration and preview controls. | One action selector with conditional fields, explicit scope, persistent Save decision / Save & next. Ticket creation is a separate previewed external operation. |
| 13.27.04 | Timeline contains a useful CVE-track chart but multiple definitions/counts above it and a capped set of visible lanes. | Preserve CVE tracks. Simplify controls, retain explicit scope and coverage, expose any pagination/virtualization, and use the shared inspector for markers. |
| 13.27.11 | Detection/actions table labels recorded disappearance as Fixed and mixes time-to-whitelist with time-to-fix. | Separate observation state, workflow and verified remediation. Rename measures rather than relying on footnotes to undo misleading headings. |
| 13.27.20, 13.27.26 | Tall day-by-day history repeats prose, dates, statuses and two action buttons for each item; blank days consume substantial height. | A separate compact Event log, with empty intervals represented by coverage, and one detail action. No giant per-day cards as the default. |
| 13.27.33 | Daily heatmap uses a fraction of its container, contains many zeroes and shows a future cell with a zero. | Secondary Daily activity view, responsive grid, distinct unknown / observed-zero / future states, day drilldown, and no unused giant blank area. |

The screenshots contain different count units and filters. This specification does not assume their numbers are wrong. It addresses the fact that understanding them currently requires reading too many qualifications.

## 3. Navigation and shared scope

Use a 52px top navigation bar: PTV Triage identity, Overview, Vulnerabilities, Review with a scoped work badge, Timeline, and Data & settings at the right. Retain the navy/orange identity. Do not add a wide permanent sidebar for only four destinations.

A 44–46px scope row immediately below holds Team and Environment, the dataset boundary, Reset scope and Evidence health. Primary filters are never concealed behind an accordion. Search, severity, time range and view-specific filters remain in the destination's toolbar.

The default operational dataset is deployment inventory, not public-reference CVEs. A separate clearly labeled reference-library view may exist under data tools or an explicit dataset selector. Reference content must never inflate affected-system metrics simply because an advisory exists publicly. Demo datasets need persistent labeling.

Keep the current local/no-sign-in model unless the repository has a separate authentication requirement. The phrase "opening the app" does not imply introducing account management. Compress the current safety strip into a small workspace indicator and a safety/data-health entry, while preserving important confirmations at the moment of external action.

### Navigation state

Scope filters, list sort, pagination, selected CVE, inspector tab, timeline window and relevant scroll position should survive drilldown and return. Use a stable URL contract for shareable read state. Keep draft decisions out of URLs. Browser Back should return to the same filtered view, not a reset homepage. Uncommitted drafts must not disappear when opening evidence or moving between queue items.

Do not silently narrow the decision's targets based on a hidden global filter. Show the current scope, selected count and all targets explicitly before commitment. Broadening scope must not automatically add new targets to a draft exception.

## 4. Overview: the opening screen

### Header and attention statement

Title: **Security overview**. Avoid greeting cards or a generic security-score dial.

Show a compact attention banner with two independent parts: the operational conclusion and its evidence quality. Examples of design states are "Immediate attention required · 3 P1 CVEs" and "Confidence limited · exposure unknown in 10 scopes". These example values are synthetic; real values must come from a documented policy and scoped queries.

The application should not promise "You are safe" simply because an open count is zero. Supported language includes "No urgent findings in the latest completed scans" alongside coverage and freshness. Missing deployment evidence, incomplete imports or an unavailable intelligence cache remain visible even when no urgent row matches.

Priority is not scanner severity and is not proof of compromise. When a policy uses more than severity, expose the evidence and policy version. CISA's SSVC work is an example of action-oriented prioritization using exploitation and impact rather than severity alone [R1]; this design is not a complete SSVC implementation.

### Four primary metrics

1. **Active CVEs:** unique CVE/advisory IDs with at least one open affected occurrence in the selected deployment scope, according to the latest recorded state. Include underlying occurrence/scope count in small secondary text.
2. **Need a decision:** unique CVEs with at least one actionable review scope, including investigation when configured. A partially assessed CVE remains until all applicable scopes are handled.
3. **Immediate priority:** unique active CVEs meeting the published immediate-action policy; show deadlines when actual policy deadlines exist.
4. **Exposure unknown:** count of affected scopes with unknown exposure, not a misleading duplicate count of CVEs.

Each metric is a drilldown into its exact query, not a decorative card. State the unit inside the card. Do not use the same word "findings" for CVEs, image occurrences and deployments.

### Ownership table

Place a team table directly beneath the metrics: Team, active CVEs, critical CVEs, needs decision, exposure-unknown scopes, and a compact open action. Include Unassigned as a real row. Sort by operational urgency, then work outstanding; retain a visible sort description.

A CVE can appear in multiple teams. Explain this once in the table footer and never add per-team unique counts to derive the global distinct count. Critical does not disappear when a risk exception exists.

For production, add overdue work and oldest unreviewed age as optional columns or a team detail, not another row of dashboard cards. Clicking a team count preserves environment and opens precisely that slice.

### Supporting area

Show at most four immediate tasks: urgent work, expiring exceptions, unassigned ownership and stale deployment evidence. Each has a next action. Beneath these primary surfaces, show a short priority-findings table and evidence-health summary. Historical trends are secondary and appear only when scan coverage supports comparison. Do not draw a trend from isolated observations as if it represented continuous active inventory.

## 5. Vulnerabilities: an investigation table

Keep one advisory per primary row; expand or inspect its affected scopes. Suggested desktop columns are selection, Advisory/package, severity, work priority, affected teams/scopes, exposure, work state, recorded age and fix information. Long vulnerability descriptions do not belong in every row.

Search remains visible. Quick views cover Active, Risk accepted, Observation history and All. Add saved views for useful scoped queries. Scanner-suppressed findings remain distinguishable from approved exceptions; they must not silently disappear from operational counts or the review queue merely due to an imported suppression flag.

Only the selected or hovered row needs a prominent contextual action; avoid a full blue Triage issue button on every row. CVE ID opens the same inspector used everywhere. Selection checkboxes are separate from opening detail. Batch actions appear in a single toolbar only after selection, consistent with enterprise table patterns [R2].

Support full-value inspection/copy for IDs, package versions and image digests. Never render a version like `2.14.1` across several lines or collapse a State heading into individual letters. Use nowrap for atomic fields and an explicit overflow strategy for long image paths. Do not place a wide evidence table inside an arbitrarily narrow nested card [R2].

A bulk operation displays selected CVEs and selected underlying scopes. "Select current page" and "Select all matching" are different operations. Read-only export and review-selected are sensible defaults; bulk risk acceptance or remediation verification should not be the first feature shipped.

## 6. CVE inspector: one component, predictable actions

Use a full-height inspector, approximately 640–800px wide on a desktop, with Expand and Close controls. A desktop nonmodal implementation is acceptable only if the underlying workspace reflows or otherwise remains operable without obscured keyboard focus. The prototype uses a native modal drawer for explicit focus containment, not a tiny popup.

The inspector has four rows: fixed header, fixed tabs, one flexible scrolling content region and fixed action footer. The header always contains the CVE identifier, severity, priority, scope and close/expand controls. The footer contains Review this CVE and Close. Essential actions are not hover-only and do not move below the fold.

**Summary** contains the short explanation, meaningful current facts, next action and affected teams. **Affected assets** contains exact package/image/deployment scope. **History** combines observation and decision events with clear event types. **Evidence** contains provenance, scanner/import metadata, intelligence receipts, raw records and policy inputs.

Review this CVE opens that same advisory in Review with the current scope preserved. It must never send the user to an unfiltered action queue and ask them to find the advisory again.

Only data/cell regions may scroll horizontally. The action footer and close button are outside those regions. At narrow widths, the inspector becomes a full-width detail screen. Do not shrink buttons and columns until they are unusable.

Sticky elements must not hide keyboard-focused controls. W3C explicitly identifies sticky headers and footers as possible causes of focus obstruction [R3]. Native modal dialogs or equivalent accessible implementations need focus containment, Escape support and return focus [R4].

## 7. Review: one operational workspace

Remove the mandatory four-step wizard from the default workflow. Reading a description, seeing two deployments, reading priority reasons and then making a decision should not require four full page transitions. A guided checklist can remain optional for onboarding without becoming a second source of workflow truth.

### Desktop structure

Use a 260–310px queue on the left. The remaining workspace contains evidence and scope centrally and a 300–350px decision form on the right at wide widths. Keep the workspace header and final action row fixed; let the evidence and decision regions scroll as necessary. At medium widths stack the decision form in the detail scroller; at narrow widths toggle between the queue and assessment.

The screenshot prototype provides the exact hierarchy: selected ID, severity/priority, last observed, short explanation, intelligence/fix facts, affected-scope selection, then expandable priority rationale, technical evidence and optional AI assistance.

### One queue, several purposeful views

Use Needs decision, In progress and Exceptions. Decision history contains previous reviews and immutable action history. Old assessments must remain searchable, but not presented as a competing current queue.

Default grouping is one CVE with its affected scopes beneath. Operators can switch to a team-specific view through the shared filter. Show both CVE count and remaining scope count when they differ materially. A CVE may legitimately appear in more than one work view when different scopes are in different states; summarize it as Mixed rather than inventing one global approval.

### Decision form

Offer Request remediation, Investigate / gather evidence, Accept risk temporarily and Request verification. The production design can add Evidence-backed not affected through the assessment policy, not as an unqualified dismiss shortcut.

Request remediation needs owner, target scope, due date and note. Investigation needs owner, evidence required and follow-up date. Temporary acceptance needs exact scope, rationale, compensating controls where applicable, recorded-by/approver identity and expiry. Request verification sends work to evidence collection; it is not a Mark fixed button.

For acceptance, show an explicit confirmation listing target teams, environments and asset scopes, expiry with timezone and the recorded identity. In a local/no-sign-in mode, attribution is self-declared unless the product has a verified identity mechanism. Never present a typed name as authenticated approval.

### Persistent actions and drafts

The final action row has a draft/save status, Save decision and Save & next. Saving commits only the explicitly selected targets. Unselected scope remains unchanged. Partial decisions remain visible, and the success message says how many scopes changed.

Draft autosave is not commitment. Show Draft saved locally versus Decision saved distinctly. Failed persistence is visible. Navigation between queue items must retain drafts. Refresh or a server update must never silently expand the target set, overwrite a newer decision or lose the user's text.

Save & next must not silently mark a row fixed, create tickets, run AI or infer risk acceptance. After a partial decision it may advance to the next CVE while leaving the unresolved work in the queue. Preserve the stable ordering of the current review session instead of reordering rows beneath an operator's pointer on every refresh.

### Azure DevOps and AI

Keep the local decision as the primary path even when Azure DevOps is unconfigured. Ticket creation is separately previewed and explicitly confirmed. Show the exact projects/areas, teams, target scopes, payload and existing-ticket matches. If grouping is one ticket per team, preview that grouping; do not silently combine unrelated CVEs or environments.

Track a durable local work item and external submission status. Handle partial success, unavailable destinations and ambiguous responses. An ambiguous network result is not permission to create a duplicate ticket automatically.

AI advice belongs in a supporting evidence section. It is optional, sourced, timestamped and separate from the human decision. Before sending data, show provider, the outbound scope/context and the relevant consent. Disabling AI must not reduce the capability to review manually.

## 8. Timeline: improve rather than replace

Keep the useful horizontal chronology and one CVE track per aggregate advisory. Use sticky CVE labels and date headers, consistent semantic markers and a coverage rail. Allow expanding a CVE into occurrence/deployment lanes when scoped histories differ. Aggregated markers show their underlying count and detail.

A marker means an actual recorded event, not continuous presence. New/continued observations use blue, re-observation uses a distinct purple diamond, no-longer-observed uses an outlined neutral marker, and verified remediation uses a green marker. Risk acceptance and work decisions use their own labeled symbols. Do not use the same green point for a newly discovered vulnerability and a verified fix.

Connecting lines are optional. A dotted connector may show event ordering only if that meaning is clear; never use a solid duration bar to bridge unobserved time and imply sustained exposure. A line should not connect unrelated placement histories just because they share a CVE ID.

Add three sibling views: CVE tracks, Event log and Daily activity. They share window, team/environment and relevant type filters. Do not stack all three vertically into a giant page.

The Event log is a compact table of recorded time, CVE/package, event type, relevant scope, actor/source and one inspector action. Consecutive empty days become an optional gap interval rather than oversized repeated cards. Provide the same underlying events through a semantic table for screen-reader users.

Daily activity is secondary; first-observed counts must be labeled as local observations, not publication dates. Display unknown/no-scan, scanned-with-zero-new-findings, and future days differently. A future day is not zero. After timezone conversion, daily buckets must reconcile with the corresponding events. A small dataset should not occupy half a huge bordered container.

Do not silently display only twelve lanes while presenting the overall total as though everything were plotted. Use pagination or virtualization with visible shown/total information, stable sorting and an accessible alternate log.

Rename misleading duration columns. Open age means elapsed time since the chosen recorded observation; it does not prove uninterrupted exposure. Time to no-longer-observed, time to decision and verified remediation time are separate measures. Unknown imported suppression dates produce Unknown, not a fabricated near-zero time-to-whitelist.

## 9. Visual specification

| Element | Specification |
|---|---|
| Main surface | White on a very light cool-gray background. |
| Navigation | Deep navy; orange is primarily brand/active-navigation accent. |
| Primary action | Strong blue, one per decision surface. |
| Panels | 1px crisp boundary, 3px radius, no soft glow. |
| Controls | 34–36px comfortable desktop height; 32–34px compact. |
| Rows | Roughly 44–50px with two-line content; compact about 40px. |
| Type | 24px page titles, 16–19px section/selected-record titles, 12–14px operational content. Small 10–11px labels only for tertiary metadata. |
| Spacing | Consistent 4/8/12/16/24px scale. |
| Color | Severity, priority, workflow and confidence use distinct labels; color alone never carries the whole meaning. |
| Focus | High-contrast 2px outline with visible separation from the component. |
| Icons | Consistent small line icons with accessible labels and adequate hit area. |
| Motion | Minimal; respect reduced-motion settings. No decorative pulsing or blur. |

Compact must not mean unclickably small. WCAG 2.2 target-size guidance uses a 24×24 CSS-pixel minimum with specified exceptions; target 32px or larger for ordinary controls rather than designing every action at that minimum [R5].

## 10. References

[R1] CISA, Stakeholder-Specific Vulnerability Categorization: `https://www.cisa.gov/resources-tools/resources/stakeholder-specific-vulnerability-categorization-ssvc`.

[R2] IBM Carbon, Data table usage, including toolbar, selection/batch actions and generous table placement: `https://carbondesignsystem.com/components/data-table/usage/`.

[R3] W3C WAI, Understanding Focus Not Obscured (Minimum): `https://www.w3.org/WAI/WCAG22/Understanding/focus-not-obscured-minimum.html`.

[R4] W3C WAI ARIA Authoring Practices, Dialog (Modal) Pattern: `https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/`.

[R5] W3C WAI, Understanding Target Size (Minimum): `https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html`.

[R6] FIRST, EPSS: `https://www.first.org/epss/`. Optional future enrichment only: it estimates exploitation probability over the next 30 days, not the probability that a particular deployment is compromised. Never substitute an absent score with zero.

These sources support selected interaction and evidence principles. Pixel dimensions, information architecture, workflow choices and implementation priorities are design recommendations for this application, not requirements asserted by those sources.
