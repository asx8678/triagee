# 10 · Incremental implementation sequence and gates

## Delivery strategy

Use a feature flag/route seam appropriate to the existing app. Implement a genuine end-to-end slice before expanding all pages. Prefer small reversible changes over a broad frontend/backend rewrite. Each phase has visual proof and real data wiring; do not call a phase complete after rendering only a static panel.

## Phase A — audit and baseline

Complete repository discovery, route/data/operation mapping and before screenshots. Run existing tests and record pre-existing failures separately. Fill the audit and migration-risk sections. Verify package integrity and open the accepted reference. Establish the isolated synthetic visual fixture adapter design.

**Exit:** actual files for each component/query/mutation are identified; state meanings are understood; no destructive changes; next slice has a supported backend path.

## Phase B — shared domain presentation and query contracts

Centralize scope predicates, count units, status wording, policy result attribution, first/last recorded times and evidence freshness. Add fixtures for shared-team CVE, scoped exception, imported suppression, disappearance, stale/partial scans and reference-only records. Correct misleading display labels without destructive schema renames.

**Exit:** metric/drilldown sets reconcile; suppression/acceptance/absence/verification remain distinct; no public-reference record inflates operational exposure. Current routes still work.

## Phase C — visual primitives and shell

Port exact tokens/CSS, SVGs and core components into the existing styling system. Build navigation, shared scope bar, page frame, status row, buttons, badges, panels, table primitives, disclosures, empty/error states and modal/action-row structures. Add route/query state and focus behaviors.

Capture shell and representative components at 1600×1000,1366×768 and390×844. Check actual font metrics, borders, widths and gutter behavior before adding many screens.

**Exit:** reference composition is matched; standard styles are shared; no remote style/font dependency; core responsive behavior and keyboard focus work. Feature flag can restore old shell safely.

## Phase D — inventory and shared inspector

Wire inventory to real scoped queries, visible filters, stable sorting, pagination and selection. Build the inspector with all four sections, expansion, scope-aware events and persistent actions. Preserve list position, selected-only set and read state. Include invalid/out-of-scope/deleted record handling.

**Exit:** an operator can open several real-shaped records and return to the same list position. Review this CVE selects exactly that advisory and scope. Long digests and table content do not hide Close or Review. Pixel/geometry comparison passes at desktop and laptop.

## Phase E — review vertical slice

Replace the mandatory wizard for the new route with queue/evidence/decision. Wire real scoped decisions, drafts, field validation, audit history, target reconciliation and Save/Save & next. Build risk-acceptance confirmation and compact optional integration section. Add minimal compatible Request verification support or explicitly report the gap; never fake it.

**Exit:** production-only decision leaves staging unresolved, active CVE count unchanged, exact audit targets recorded, draft preserved across inspector/queue navigation. Save failure/conflict keeps form and position. Footer remains reachable at supported widths and zoom. No remote operation occurs during local save.

Do not start polishing secondary charts while this workflow is still a stub.

## Phase F — Overview as entrypoint

Build four metrics, attention/confidence split, team ownership, actionable tasks, urgent findings and evidence health using shared selectors. Drilldowns preserve their exact contributing set. Include Unassigned and partial/stale data. Implement good loading/empty states without false zeroes.

**Exit:** a new operator can see current recorded exposure, decision work, ownership and urgency in the first view. All metric/link sets reconcile with inventory/review. The sample baseline matches and real data labels remain truthful.

## Phase G — timeline refinement

Retain tracks, add consistent markers/coverage, sticky labels and complete lane access. Event log and Daily activity are sibling views with shared source/window/scope rules. Fix ambiguous “time to fix” semantics. Support exact event inspector navigation and scoped history.

**Exit:** event/log/metric/daily sets reconcile; no future or missing-scan day appears as a false zero; no partial import produces an absence; no silent lane cap; old timeline history remains accessible.

## Phase H — integration/settings/migration parity

Consolidate setup/data tools and historical assessments. Keep old routes/deep links through compatibility mappings. Validate legacy global/unknown-scope records without inventing scope, identity or timestamps. Preserve ticket linkage and implement safe preview/partial/unknown states using sanctioned test doubles.

**Exit:** old history and links remain recoverable; local-only mode is preserved; no surprise outbound operation; migration counts/IDs reconcile and rollback plan is tested on a development copy.

## Phase I — full fidelity and production hardening

Run all acceptance scenarios, application tests, deterministic32-case screenshots, boundary/zoom/keyboard checks and representative larger fixtures. Inspect overlays/heatmaps manually. Complete all unresolved state and semantic edge cases. Compare feature-flag old/new results where useful without mixing duplicate mutation systems.

**Exit:** final report contains actual test output, screenshots/diffs, mappings, migration evidence and remaining limitations. All must-pass behaviors are demonstrated. Remove old duplicate UI only after history/deep-link parity; do not delete legacy data for visual cleanliness.

## Parallel work rules

Parallel agents may work on primitives, page composition and tests only after shared scope/state/action/locator contracts are agreed. One owner controls the design tokens, shared inspector and decision semantics. Do not let separate agents build different versions of the same badge, query or action footer.

Each branch/slice should be integrable independently with documented interfaces. Verify combined screenshots after merges; independently correct components can still produce incorrect total geometry.

## Change discipline

Use small commits with clear ownership. Preserve unrelated user modifications. Avoid formatting entire unrelated files. Record migrations, external side effects and environment assumptions explicitly. A blocked backend function does not justify a fake successful UI; isolate the blocker and continue independent visual work without misreporting completion.
