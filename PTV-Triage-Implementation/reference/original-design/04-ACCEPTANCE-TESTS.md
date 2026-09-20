# Production acceptance scenarios

These scenarios are requirements for the real implementation. The browser tests shipped with the prototype cover only the narrower interaction and layout subset described in `QA-REPORT.md`.

## A. Count and scope correctness

**A1 — distinct identities.** One CVE affects one package/image occurrence deployed in production and staging. Show one CVE, one occurrence and two affected scopes; never present all three as interchangeable findings.

**A2 — shared CVE across teams.** The same CVE affects Alpha and Beta. Each team's count includes it once; the global CVE count includes it once. A team total is not obtained by adding scope counts.

**A3 — exact drilldown.** Activate a dashboard metric and compare the returned identifiers/target scopes with the metric's contributing set. Test combinations of team, environment, priority and exception status.

**A4 — partial assessment.** Accept or assign work for production only. Staging stays unchanged and actionable. The active CVE count remains unchanged until relevant observation/remediation evidence supports a change.

**A5 — reference isolation.** Load public-reference or synthetic records without a deployment match. They must not increase operational affected-system counts or create remediation work. The selected dataset is always visible.

**A6 — unassigned and stale.** Unassigned records are visible in an ownership bucket. Stale observations remain visible as last-known evidence, rather than disappearing into a safe state.

## B. Truthful state changes

**B1 — disappearance.** A comparable completed scan no longer finds an occurrence. Show No longer observed, not Fixed, unless independent verification evidence exists.

**B2 — incomplete import.** A partial import omits a prior row. No negative observation or fix is inferred. Coverage indicates the limitation.

**B3 — scanner suppression.** An imported suppression has no author or action timestamp. Show Scanner-suppressed with attribution/date unknown. Do not invent risk acceptance or an immediate response time.

**B4 — exception expiry.** At the documented expiration instant the appropriate scope re-enters review according to policy. The active CVE existed throughout acceptance. Cover UTC and non-UTC day boundaries.

**B5 — ticket state.** Closing a linked ticket requests or awaits verification; it does not automatically change the scanner observation to remediated.

**B6 — cached intelligence.** Never fetched, failed refresh, stale snapshot, partial snapshot, no match and positive match are distinguishable. No fetch is never rendered as not exploited.

## C. Navigation and review behavior

**C1 — retain list context.** Filter/sort, scroll to an item, open detail, inspect another tab and close. Filters, sorting, pagination, row selection and scroll position are retained.

**C2 — direct review.** Review this CVE opens the selected advisory and visible scope. It never opens a generic queue requiring the operator to search again.

**C3 — draft durability.** Type a decision, visit other evidence/queue items, return and reload. Preserve the draft according to the supported persistence model. Storage failure must be visible, not silently described as saved.

**C4 — no implicit scope expansion.** While an exception draft is open, new affected scopes arrive or the global filter broadens. Newly appearing scopes are not automatically selected.

**C5 — save semantics.** Draft autosave, local decision commit and external ticket creation produce different statuses. Save & next has no undisclosed external effect.

**C6 — required fields.** Missing owner, due/expiry date, rationale or scope produces a clear, focusable error. A past expiry is rejected. No selected target disables commitment. Canceling confirmation makes no domain change.

**C7 — concurrency.** A second operator or process updates an assessment during editing. Commit detects a version conflict; it does not overwrite newer data or broaden target scope.

**C8 — queue stability.** Refresh does not reorder the currently selected work underneath the operator. New work can be acknowledged explicitly. A partial decision leaves the remaining scope discoverable.

## D. Action visibility and accessibility

**D1 — responsive matrix.** Test 1920×1080, 1600×900, 1440×900, 1366×768, 1280×720, 1024×768, 768×1024 and narrow mobile layouts. Also test an actual browser at 200% zoom. Main/inspector action bars and close controls stay reachable and are not clipped by tables.

**D2 — scroll stress.** Use a long advisory description, 100 affected scopes, multi-line reasons and long image/digest/package strings. The footer stays visible, the last content item remains reachable and headers/controls do not collapse into single letters.

**D3 — focus visibility.** Tab through all actions and forms. Sticky headers, footers, notices and drawers must not entirely obscure focused controls. Use adequate scroll padding and sensible container sizing.

**D4 — dialogs.** Focus enters the dialog, remains appropriately contained, Escape closes it and focus returns to its invoker or another logical destination. No inert background control receives focus while a modal is open.

**D5 — small-screen review.** Show one meaningful assessment column and an explicit way to return to the queue. Do not squeeze three columns across a phone. Test virtual-keyboard behavior on an actual mobile browser before claiming support.

**D6 — semantic alternatives.** Use proper table headers/captions, labels and accessible names. Provide every timeline event in an accessible list/table. Labels or marker shapes supplement color. Assess contrast and screen-reader behavior, not just DOM presence.

## E. Timeline semantics

**E1 — event reconciliation.** Track markers, event-log rows and counts derive from one event query and scope. Grouped markers expose all underlying events.

**E2 — no fabricated continuity.** Two observations separated by unobserved days do not become a continuous exposure bar. Different placements do not merge into a false single episode.

**E3 — daily cells.** Unknown coverage, observed zero new findings, a positive count and a future day are different states. Future cells never show zero observations as a completed result.

**E4 — time.** Test timezone conversion, midnight boundaries, daylight-saving transitions, duplicate imports, late arrivals and reopened occurrences. First local observation is never silently replaced with publication date.

**E5 — large history.** Test at least the expected production lane/event volumes, including pagination or virtualization. Show total/visible information and retain an accessible alternative. Do not silently cap at 12 tracks or discard additional events.

## F. External actions and untrusted data

**F1 — local by default.** Navigate, search, filter and open details with outbound-network monitoring enabled. No unrequested AI, scanner refresh or ticket creation occurs.

**F2 — ticket preview.** Confirm exact team destinations, scope, payload and prior tickets. Changed payload invalidates a prior preview. Failure for one team does not imply failure or success for all teams.

**F3 — ambiguous result.** Simulate timeout after possible remote creation. Persist Unknown result and reconcile before another creation attempt. Do not describe a generated request key alone as server-enforced idempotency.

**F4 — untrusted text.** Descriptions, package names, imported identifiers, URLs and AI text are treated as untrusted content. Test literal script/HTML payloads, unsafe URL schemes and oversized strings. Display text safely; no script execution or implicit external content fetch.

**F5 — authorization and audit.** Real authority is enforced server-side. A self-declared local name is not displayed as authenticated approval. Migration preserves original legacy/global scope and unknown provenance without inventing facts.

## G. Operator usability check

Give a new operator the following tasks using representative data: identify the most urgent team; find unknown production exposure; review one CVE for staging only; return to the original filtered inventory; locate a re-observation; explain why a disappeared finding is not a verified fix.

Measure task completion, wrong-scope actions, backtracking and errors against the current UI. Treat target reductions in clicks or review time as goals until measured; do not advertise untested percentage improvements.
