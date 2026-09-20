# Incremental implementation plan

## Delivery rule

Do not begin with a full front-end or backend rewrite. First audit the repository, then ship a narrow vertical slice behind a feature flag. Each slice must contain real data wiring, interaction tests, representative screenshots and a rollback path. Preserve the current application's local behavior, data history and explicit outbound-action controls.

The HTML prototype communicates hierarchy, geometry and interaction intent. It is not an instruction to embed a client-side fixture renderer into production.

## Phase 0 — map the existing application

Inventory current routes/components, query functions, data sources, importer coverage semantics, current identity mode, assessment and exception storage, local work state, Azure DevOps submission behavior and timeline event derivation. Identify whether components are LiveView/server-rendered or client-rendered; use the existing framework unless a concrete blocker is documented.

Map all screenshot behaviors to their actual code paths. Determine whether old assessments and the new action queue use different models. Trace a real CVE from list → detail → scoped review → recorded action → timeline. Record existing side effects and all points where scope can be lost.

Deliver `implementation-audit.md` containing a route map, entity/state dictionary, mismatches against the design, existing regression tests and a migration proposal. Do not claim a count or priority rule is understood until its query has been traced.

**Gate:** The agent can explain the exact difference between CVE, package occurrence, placement, review scope, scanner suppression and exception in this repository. Unknowns are documented, not guessed.

## Phase 1 — establish truthful labels and shared selectors

Implement or adapt shared scoped query contracts. Add fixtures covering one CVE across two teams and environments, a suppressed unapproved finding, an exception, a reopened finding, a stale scan, a missing partial-import row and a reference-only advisory.

Rename legacy disappearance-based Fixed labels to No longer observed where they occur. Expose verified remediation separately. Correct intelligence states for unrefreshed/failed caches. Do not rename persisted data without a compatible migration.

Centralize count units, state display labels, source/time formatting and unknown states. Define dashboard drilldown predicates alongside metrics. Freeze expected identifiers for each test fixture.

**Gate:** The same scoped dataset yields reconcilable overview, inventory, review and timeline counts. An exception never reduces the active affected count. No reference-only advisory appears in operational exposure totals.

## Phase 2 — build the visual foundation and shell

Implement tokens, typography, focus styles, compact badges, flat panels, 34–36px controls, predictable table rows and intentional loading/empty/error states. Preserve a comfortable density option. Build the four-destination navigation and shared scope row.

Introduce common UI primitives rather than screen-specific one-off CSS: `AppShell`, `ScopeBar`, `EvidenceHealthIndicator`, `PageHeader`, `MetricLink`, `SeverityBadge`, `PriorityBadge`, `WorkflowState`, `DataTable`, `ActionBar`, `EvidenceDisclosure`, `EmptyState`, and `InlineError`. These are conceptual responsibilities; adapt names and file extensions to the actual stack.

Implement URL/read-state serialization for team/environment, current view, search, sort, selected CVE, inspector tab and timeline window. Keep drafts outside URLs. Preserve browser Back and sensible focus after navigation.

**Gate:** At 1366×768 the shell does not consume half the viewport. Primary filters stay visible. Data tools/configuration are reachable without repeated full-width setup banners. At 200% zoom the layout reflows rather than hiding essential actions.

## Phase 3 — inventory plus reusable CVE inspector

Rebuild the inventory table against real scoped queries. Add visible search, quick views, stable sorting, explicit selection semantics and supported pagination. Defer bulk acceptance; begin with export/review-selected when already supported safely.

Build the shared inspector and reuse it from inventory, overview and timeline. Its structural layout is header / tabs / scroll body / action footer. Keep the CVE ID, scope, Close, Expand and Review this CVE reachable at every supported viewport.

Use stable real identifiers for selections. Keep long text from resizing the action column or breaking versions into separate characters. Make full values accessible by keyboard as well as pointer. Do not hide essential operations only in hover menus.

**Gate:** An operator can filter to one team's production findings, inspect several CVEs and return to the same list and scroll position. Review this CVE carries the selected record and scope. The footer remains visible at 1280×720 and 1366×768 while any detail tab is scrolled.

## Phase 4 — replace the review wizard with one workspace

Render a compact queue and a detail workspace. Move the useful content from the four old steps into summary, exact affected-scope selection, optional supporting evidence and one conditional decision form. Preserve the old routes through redirects/deep-link compatibility while moving legacy records into a coherent history view.

Implement draft state per advisory and scope context. Never implicitly expand a saved target set. Make Save decision different from draft autosave. Add Save & next with predictable queue behavior. Keep required fields and selected-scope counts visible; show validation near the failing fields and in an accessible summary where appropriate.

Implement Request remediation, Investigate and scoped temporary acceptance first, using the existing valid domain actions. Add Request verification if the backend supports it. Do not expose unsupported state changes as working UI. Require explicit scoped confirmation for acceptance and preserve the original decision in history.

Separate local work creation from ticket creation. When Azure DevOps is unavailable, the local decision remains usable. Put AI assistance behind an optional disclosure without making it a required review step.

**Gate:** A real CVE spanning production and staging can be acted on for production only; staging stays in the queue. Reopening detail or navigating to another CVE does not lose the draft. A scanner suppression does not become an approved exception. All primary actions remain visible without scrolling to the end of the page.

## Phase 5 — make Overview the default destination

Build the four primary metrics from the shared selectors. Add the attention/confidence split, team ownership table, short next-action list, priority findings and evidence health. Include Unassigned and stale evidence.

Use actual source freshness and coverage. A successful recent import timestamp alone is insufficient for a globally fresh badge. Add meaningful error/loading states without temporarily displaying false zeroes.

Keep the first viewport focused on counts, urgency and teams. Do not add donut charts, arbitrary percentages or decorative risk gauges. Use trends only when the underlying observation model supports them.

**Gate:** A metric's drilldown returns the exact contributing entities. The opening page distinguishes immediate work from insufficient evidence. Shared CVEs do not produce misleading summed team totals. The first-view tasks are usable by an operator unfamiliar with internal data terminology.

## Phase 6 — refine the existing timeline

Keep the recognizable CVE-track view. Centralize event types and marker meanings. Add explicit coverage, sticky labels, one inspector, and an Event log using the same query/window. Put Daily activity in its own view.

Remove duplicated per-event buttons and huge default empty-day cards. Implement visible pagination or accessible virtualization without silent lane caps. Ensure aggregate CVE history can drill down to scope where needed.

Replace misleading Fixed/time-to-fix reporting with the state and measure distinctions in the domain contract. Preserve actual unknown timestamps and incomplete evidence. Test future cells, daylight-saving boundaries, out-of-order imports and re-observation episodes.

**Gate:** Every visible count reconciles with the corresponding events. Unknown coverage is visually different from recorded zero. No chart line implies continuous observation across an unobserved period. All chart events can be reached through the event log.

## Phase 7 — integrations, migration and production hardening

Polish data settings and optional connectors without turning this UI task into a new platform. For Azure DevOps, implement a real recipient/target preview, approval, duplicate detection/linkage, partial-success rendering and unknown-result reconciliation. Keep outbound requests out of ordinary page rendering.

For AI, require explicit provider/payload visibility and retain source/evidence and human decision separation. Do not auto-accept risk or close work from AI output. Keep operational data and credentials out of browser storage or exported demo artifacts.

Migrate legacy assessments without dropping provenance, attribution uncertainty or scope. Add feature-flag comparison and rollout instrumentation using real operator tasks. Remove old duplicated pages only after parity tests and history migration are verified.

**Gate:** Existing local-only defaults still hold, no unexpected outbound request occurs during navigation, and existing data remains recoverable. All acceptance scenarios pass on representative real-shaped fixtures, including failure states.

## Suggested component ownership

| Area | Responsibility |
|---|---|
| Scope/query layer | Shared scope predicates, count definitions, stable identifiers, snapshot/version. |
| Shell/design system | Navigation, tokens, common controls, accessibility and responsive behavior. |
| Advisory presentation | Inventory, inspector, evidence tabs and preservation of read context. |
| Review workspace | Queue, exact target selection, drafts, validation, decisions and history. |
| Timeline | Event/coverage mapping, tracks, event log and daily buckets. |
| Integrations | Explicit previews, durable linkage, outbound consent and result reconciliation. |

Multiple agents may work in parallel only after these interfaces and domain terms are agreed. Avoid having different agents implement separate severity badges, scope filters, status enums or independent count logic.

## Definition of done for every phase

Supply the changed files, migrations if any, tests run with outputs, screenshots at 1366×768 and a larger desktop, and a short list of known limitations. Show the data source for every newly displayed metric or status. Demonstrate the interaction, not merely a visually matching static panel.

No production claim of accessibility conformance, accurate risk calculation, verified remediation or durable ticket idempotency is justified by the visual prototype. Those require implementation-specific evidence and review.
