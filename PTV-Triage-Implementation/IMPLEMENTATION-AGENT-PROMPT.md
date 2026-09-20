# Paste this into the implementation agent

You are implementing an approved redesign of the existing **PTV Triage** application. You have the application repository and this implementation package. The package may sit inside or next to the repository; locate `START-HERE.md` and `reference/approved/ptv-triage-prototype.html` before beginning.

**Do not design a different interface. Do not produce another mockup. Modify the real application to match the accepted reference as closely as engineering permits, with real data and working actions.**

## 1. Read and establish the target

Read `AGENTS.md`, `specification/01-DESIGN-LOCK.md`, and all numbered specifications. Open the standalone reference in a browser. Inspect Overview, active inventory, all inspector tabs, the expanded inspector, review scope selection and decision forms, risk-acceptance confirmation, the disconnected ticket preview, all three timeline views, and Data & settings. Examine the 1600×1000, 1366×768, 1280×720 and 390×844 reference renders. Use the computed-style/geometry JSON and exact CSS; do not estimate values from an image when the value is supplied.

The reference has been approved by Adam. Its identity, density, hierarchy, spacing, layout and information architecture are locked. No new sidebar, large rounded-card system, glass effects, gradients, arbitrary risk gauge, oversized whitespace, competing queues or replacement wizard is authorized.

## 2. Audit before changing domain behavior

Inspect the repository's own development instructions, working-tree status, package/lock files, build commands, route definitions, component layout, backend queries, import/coverage model, decisions, exceptions, history, local identity model and integrations. Preserve unrelated changes. Do not assume React, Vue, Phoenix or any library version from the reference's plain HTML.

Trace one advisory from import through list, detail, scoped review, saved decision and timeline. Find the source of every existing total and the conditions that determine active, suppressed, accepted, disappeared and fixed. Identify separate legacy and newer assessment stores. Find where context is lost today.

Write the repository audit using `templates/IMPLEMENTATION-AUDIT.md`, including a mapping of each target component to actual files. Take before screenshots. Establish the current test baseline. Unknowns must remain explicit; do not fabricate a data mapping.

## 3. Preserve the app; port the visual system

Use the current stack and shared primitives. Import/adapt the accepted CSS values into its normal styling system. Extract framework-native components with conceptual responsibilities matching AppShell, ScopeBar, OverviewMetrics, TeamOwnershipTable, InventoryTable, CveInspector, ReviewQueue, ReviewWorkspace, ScopeSelectionTable, DecisionForm, PersistentActionBar, TimelineTracks and EvidenceHealth.

Do not embed the accepted HTML as an iframe or use its fixture renderer, global event switch or browser storage as production architecture. The reference is authoritative for geometry/appearance, not for data persistence, authorization or mutation safety.

Keep desktop shell rows at 52px navigation and 46px scope. Keep the reference bottom status row and flat panel boundaries. At the normal desktop width, use a 278px queue, 14px review gap and 300px decision column; at ≥1750px use 310px and 350px. At ≤1150px stack the decision under evidence within the workspace scroll region; at ≤640px show either queue or assessment. Match the other media rules exactly. Keep primary actions outside scrolling content using the supplied grid/flex pattern and `min-height: 0`.

Use `reference/source/approved-exact.css` and `specification/03-VISUAL-SYSTEM.md` for exact styles. The readable CSS is a convenience copy. Preserve actual font metrics without adding external-font or CDN requests. Do not distribute container font files.

## 4. Implement the intended workflow

Overview is the default route. Its four metrics are Active CVEs, Need a decision, Immediate priority and Exposure unknown scopes. Team ownership, urgent work and evidence health appear directly below. Distinguish immediate attention from insufficient visibility. All filters and drilldowns must reconcile by contributing IDs, not just by matching numbers.

Vulnerabilities is the compact investigation table. Keep search and main filters visible, selection distinct from opening a detail, consistent table actions, exact selected-only review, safe export and saved views. Preserve URL/read state and scroll position. Use actual pagination when needed; never silently truncate.

Use one CVE inspector from every destination. Keep Summary, Affected assets, History and Evidence; a header with Close/Expand; and a persistent Review this CVE action. Opening review must select that CVE and the correct scope, not a generic queue. Long image paths and descriptions must not push actions out of view.

Replace the mandatory four-step review wizard with queue/evidence/decision in one workspace. Put previous decisions in Decision history rather than a second active queue. A decision applies only to explicitly selected scope IDs. Preserve drafts when switching queue items, viewing evidence, changing read filters and navigating Back. Do not silently prune or expand a draft target set. Label drafts versus committed work accurately.

Implement Request remediation, Investigate/gather evidence, Accept risk temporarily and Request verification through real supported domain operations. Add the minimum compatible domain support where required by the agreed scope. Never simulate success. Scope, owner/recorded-by, date and rationale are validated on the server. Risk acceptance has an explicit confirmation including exact targets, expiry/timezone and attribution. It never marks a CVE fixed. Save & next commits first and only then advances deterministically; conflicts/errors preserve the form and position.

Keep the recognisable CVE-track timeline, with Event log and Daily activity as sibling views. Preserve event/coverage uncertainty, exact event scope, all matching lanes and distinct observation/re-observation/absence/decision/exception/verification markers. An empty or future day is not a safe day. No observation gap is proof of remediation. Marker selection opens the same inspector on History.

Move setup diagnostics to Data & settings. Keep local decisions usable without Azure DevOps or AI. Ticket creation is a separately previewed and confirmed outbound operation with durable linkage and partial/unknown result handling. Do not create external work items, refresh intelligence or send AI context as a side effect of ordinary reading.

## 5. Reconcile real semantics; do not copy prototype shortcuts

Read `specification/06-DOMAIN-AND-DATA.md` and `specification/13-REFERENCE-LIMITATIONS.md`. Keep observation, workflow, exception, scanner suppression, applicability, exposure, intelligence and verification as separate facts. Exclude public-reference-only records from operational exposure counts. Unknown evidence is not false, zero or safe. Missing records from incomplete imports do not become disappearance events. Scope-specific priorities must not leak from another team/environment.

Preserve legacy records, missing author/date information, global-versus-scoped meaning and evidence provenance. Keep old deep links working through a compatibility route/redirect. Do not relabel disappearance as verified fixed or manufacture approval timestamps. No destructive cleanup before migration parity and rollback evidence.

## 6. Execute in gated slices

Follow `specification/10-IMPLEMENTATION-SEQUENCE.md`:

Audit → shared data/labels → shell/primitives → inventory/inspector → review vertical slice → Overview → timeline → integrations/migration → final fidelity and failure-state QA.

A phase is complete only when its actual behavior works against the backend and tests/screenshots prove it. Avoid parallel agents inventing separate filters, badges, status enums or data selectors. Freeze shared contracts before assigning parallel components. Keep a phase log and deviation register.

## 7. Verify visual fidelity in a browser

Use the package's exact synthetic fixture in an isolated test database/adapter, not in production. Map it to real application entities without losing its IDs, scope relationships, priority labels or clock. Implement test-only fixture readiness and stable locators using `contracts/locators.json`. Complete `contracts/application-capture.example.json` for your application's real routes. Never assume the example is a working application adapter.

Use `qa/capture_application.py` and `qa/compare_visuals.py`, or your repository's equivalent with the same cases and evidence. Compare screenshots at identical viewport, DPR, locale, timezone, browser/font environment and fixture state. Match desktop geometry to within 2 CSS px, key heights to within 1px, and colors/radii exactly; investigate image-diff failures rather than replacing baselines. The pixel threshold is a triage aid, not permission for local design drift.

Run the functional acceptance catalog, repository tests, keyboard/focus checks, responsive boundaries and error-state tests. Scroll evidence/decision/inspector bodies to the bottom and prove the action buttons stay visible and unobscured. Test 200% zoom and long content. No horizontal page overflow; intentional inner table/chart scrolling is allowed. Do not declare full accessibility conformance from an automated pass alone.

## 8. Completion evidence

Deliver the modified application and a final report using `templates/FINAL-IMPLEMENTATION-REPORT.md`. Include changed files, migrations, real field mappings, old-route compatibility, tests with actual results, screenshots and diff artifacts, scope/decision traces, remaining limitations, and rollback instructions. Distinguish tested from assumed or blocked. Do not claim integration creation, migration safety, real-time freshness or authenticated approvals without evidence.

The end-to-end acceptance demonstration is: open Overview; identify the urgent team workload; drill into the exact contributing findings; inspect a CVE; review only its production scope; commit a decision; leave staging unresolved; return to the prior queue; see the correct scoped history; confirm active exposure has not falsely disappeared; and prove no external ticket or AI request was made.

Begin by locating the repository/package and producing the audit. Continue through the implementation gates without requesting a new aesthetic direction.
