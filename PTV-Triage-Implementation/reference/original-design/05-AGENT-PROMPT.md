# Implementation-agent handoff

Copy the instructions below into the implementation agent and provide this entire folder alongside the application repository.

---

You are implementing a focused UI/UX redesign of **PTV Triage**, an existing vulnerability triage application. This is not the RouteDesk fleet application and not a request to build a new generic security dashboard.

The product owner wants a compact, sharp, professional interface that makes active CVEs, actionable work, team ownership and risk/evidence uncertainty immediately understandable. Review must be dramatically easier to navigate. CVE detail actions must remain visible without hunting or scrolling. Improve the existing observation timeline rather than throwing away its useful chronology.

## Required reading

Read `00-START-HERE.md`, `01-DESIGN-SPEC.md`, `02-DOMAIN-AND-STATE-CONTRACTS.md`, `03-IMPLEMENTATION-PLAN.md`, `04-ACCEPTANCE-TESTS.md` and `QA-REPORT.md`. Open `ptv-triage-prototype.html` and compare the screenshots in `previews`. Use `design-tokens.json` for the starting visual language.

The prototype demonstrates layout and interactions with synthetic data. Its records, demo clock, priority assignments, sample intelligence, simple rendering and localStorage approach are not production architecture or security facts.

## First task: audit, do not rewrite

Inspect the repository's actual framework, routes, components, data/query layer, assessment/exception model, importer coverage, local-only behavior and integration side effects. Trace one CVE through inventory, detail, review, decision and timeline.

Produce an implementation audit and identify any mismatch between the current model and the requested state semantics. Do not assume the UI is React or replace a server-rendered/LiveView application because the supplied reference is a standalone HTML file. Adapt the design to the existing framework.

Do not infer real affectedness from public-reference records. Do not read synthetic screenshot fixtures as confirmed production findings. Do not modify external systems or create tickets as part of the redesign without the existing explicit operation controls.

## Target information architecture

Use four main destinations: Overview, Vulnerabilities, Review and Timeline. Data & settings holds import controls, provenance/health, configuration and optional integrations. Keep Team and Environment scope visibly shared across destinations.

Overview becomes the opening view. Show four primary metrics with exact units: Active CVEs, Need a decision, Immediate priority and Exposure unknown scopes. Add team ownership, a short next-action list and evidence health. Distinguish actionable risk from uncertainty; do not display a blanket Safe state when coverage is missing.

Inventory remains a compact investigation table with visible search, filters, saved views and exact selection semantics. Eliminate repeated giant row actions and repeated caveat paragraphs. Use one reusable CVE inspector with Summary, Affected assets, History and Evidence, plus persistent Close/Expand/Review actions.

Review becomes one workspace: queue on the left, evidence and explicit affected-scope selection centrally, decision form at the right on wide screens. No mandatory four-page wizard to read the same advisory. Preserve old assessment history, but unify current work under one queue with Needs decision, In progress and Exceptions views.

A review decision affects only selected scopes. The action row is outside the scroll body and remains visible. Draft autosave is not commitment. Save & next does not create tickets, accept risk or mark fixed implicitly. Optional guided help and AI advice cannot become mandatory review steps.

Timeline retains CVE tracks, sticky labels and honest event markers. Event log and Daily activity are sibling views, not huge sections stacked below the chart. Distinguish observation, re-observation, disappearance, work decisions, exceptions and verified remediation. Preserve gaps, unknowns and exact recorded times.

## Non-negotiable semantics

A CVE, occurrence, image and deployment scope are different units. Shared-team CVEs are not summed into the global distinct count. All count drilldowns use the exact same scope predicate as their summary.

Scanner suppression is not human risk acceptance. Accepted risk does not remove an active vulnerability. Remediation requested or a closed ticket is not a verified fix. Recorded disappearance is not proof of remediation. A scanner-reported fixed version is not proof of deployment. Unknown exposure or an unfetched intelligence cache is not a negative finding.

Keep observation, workflow, exception, applicability and verified remediation as separate dimensions. Do not erase legacy facts or invent missing timestamps/approvers while migrating. Decisions bind to immutable or otherwise stable occurrence and placement identities, not mutable tags or display names alone.

A local/no-sign-in app does not gain authenticated approval just because someone types a name. Preserve that distinction. Do not add login or organizational role features merely because the request uses the phrase "logs in" conversationally.

## Interaction and visual requirements

Use crisp 1px boundaries, approximately 3px corners, flat surfaces, navy identity, restrained orange accent, strong blue actions and semantically controlled severity/status colors. Do not introduce soft rounded cards everywhere, glass blur, gradients, giant whitespace or decorative security gauges.

Do not solve density by making text and click targets tiny. Keep main controls around 34–36px high, tables approximately 44–50px with a compact option, and atomic identifiers/versions readable. Supporting copy belongs in compact disclosures; essential evidence and action scope do not.

Main actions must be visible at 1366×768 and 1280×720. Use a grid/flex layout with a fixed header, flexible scrolling body and fixed footer, including `min-height: 0` where necessary. Do not position a footer over content without preserving its reachability and keyboard focus visibility. At smaller widths reflow or switch views instead of compressing three columns.

Preserve read state, selection, draft state and scroll position across drilldowns. Use proper accessible controls, semantic tables, focus management and a complete accessible event log. Do not claim accessibility compliance merely because a component includes ARIA attributes.

## Execution sequence

Follow the numbered phases in `03-IMPLEMENTATION-PLAN.md`. Start with the audit and shared state/count contracts, then the shell/tokens, inventory plus inspector, review workspace, overview, timeline and integration/migration hardening.

For each slice, wire real supported behavior, add relevant tests, render at representative desktop sizes and verify errors/empty/loading/stale/partial states. Prefer one completed end-to-end workflow over many attractive nonfunctional controls. A control representing unsupported behavior must be removed or explicitly unavailable with a useful reason.

Do not silently fake a risk engine, scan freshness, real-time data, ticket linkage or verified remediation. Do not automatically fetch intelligence or send CVE/service context when merely rendering a page. Preserve explicit outbound previews and approvals.

## Completion evidence

For every phase report changed files, migrations, data sources behind new values, tests run, screenshots at 1366×768 and a larger desktop, remaining limitations and rollback instructions. Demonstrate the actual interactions with real-shaped fixtures.

Before declaring completion, verify at minimum: exact metric drilldowns; CVE inspector return-state; a decision scoped only to one of two environments; preserved drafts; always-visible action bars; scanner suppression with unknown attribution; expired exceptions; incomplete imports; no inferred fixed state; timeline/event-log reconciliation; future versus unknown heatmap days; and no unrequested external calls.

Begin with the repository audit and the smallest correct vertical slice. Do not jump directly to rewriting every screen.

---
