# Acceptance catalog

Generated from `acceptance-cases.json`. These are requirements for the implementation agent; none is claimed passed by preparing this bundle. Use exact IDs in tests and milestone reports. Keep current source tests and map retained old acceptance requirements rather than replacing them with this list.

P0 marks safety/data correctness or a critical release boundary; P1 marks workflow/quality behavior. An unavailable prerequisite is BLOCKED, not a pass. Mocked adapters and synthetic fixtures are necessary but not live-service validation. The semantic fixture is not an application seed script; adapt it to actual schema and the repository's canonical evidence hashing in an owned environment.

### A001 · Findings is the landing workspace [P1, M1]

Given: A normal authenticated session with operational data.

When: Open / and /workspace.

Required: Findings / Needs attention is shown. Only Findings and Exceptions are primary workspaces; Grafana is a truthful utility link.

Evidence layers: liveview, browser. Tasks: T04. Initial status: NOT RUN.

### A002 · One actionable CVE detail [P1, M1]

Given: A CVE can be reached from inventory, review, inspector, and an exception.

When: Open it through each supported route.

Required: The same shared detail supports evidence, action, and history without a second Review destination.

Evidence layers: liveview, browser. Tasks: T03. Initial status: NOT RUN.

### A003 · Useful four-column hierarchy [P1, M1]

Given: Real image/package/version and nullable service mapping.

When: Render findings.

Required: CVE/package, affected identity/environment, reason, and specific next action are visible; no invented service or fix.

Evidence layers: component, browser. Tasks: T02. Initial status: NOT RUN.

### A004 · Search and scoped clearing [P1, M1]

Given: Team/environment selected, long list and search text.

When: Submit Enter, clear text, move page.

Required: Search works; clearing keeps deployment scope; pagination and result count use the same predicate.

Evidence layers: query, liveview, browser. Tasks: T04. Initial status: NOT RUN.

### A005 · Mixed-scope CVE is not globally closed [P0, M1]

Given: Same CVE has uncovered production and accepted staging.

When: Filter each environment and open full scoped context.

Required: Production remains attention; staging assessment does not cover siblings; the full row is labeled mixed where appropriate.

Evidence layers: domain, query, liveview. Tasks: T05. Initial status: NOT RUN.

### A006 · Counts match exact contributing records [P0, M1]

Given: Cross-team CVEs and overlapping attention/progress targets.

When: Read counts and follow each drilldown.

Required: Distinct CVE and target units are explicit; exact contributing IDs/scopes match; team/view counts are not summed incorrectly.

Evidence layers: query, domain, liveview. Tasks: T05. Initial status: NOT RUN.

### A007 · Scope-local contextual ordering and pagination [P0, M1]

Given: High exploited/public production, unexposed critical, filtered-out urgent sibling, and more than 50 CVEs.

When: Compare SQL and domain order across pages and scopes.

Required: Specified contextual policy wins over severity-only order; stable ties; no filtered-out urgency, omissions or duplicates in a stable snapshot.

Evidence layers: query, domain. Tasks: T05. Initial status: NOT RUN.

### A008 · Fresh draft is neutral [P0, M1]

Given: No saved draft for a selected CVE.

When: Open detail and start an action.

Required: No action, write targets, or non-applicability conclusion is preselected; zero-target commit is disabled.

Evidence layers: liveview, browser. Tasks: T02. Initial status: NOT RUN.

### A009 · Saved draft retains original binding [P0, M1]

Given: Authenticated user has an explicit two-target draft.

When: Navigate/reload/reconnect and restore it.

Required: Only original target IDs, captured fingerprints, fields and operation ID return; another user cannot adopt it.

Evidence layers: domain, liveview, browser. Tasks: T03. Initial status: NOT RUN.

### A010 · Filter changes do not widen or hide a write [P0, M1]

Given: Draft contains targets outside a newly selected filter.

When: Change filters and attempt preview/commit.

Required: Draft is preserved or explicitly discarded; full selected scope is visible and confirmed; no silent target addition/removal or misleading preview.

Evidence layers: liveview, browser. Tasks: T03. Initial status: NOT RUN.

### A011 · Zero/invalid targets rejected at server [P0, M1]

Given: Forged event/domain call with empty, invalid or duplicate-conflicting selection.

When: Invoke commit without the UI guard.

Required: No decision or remote write; bounded validation error. Normal duplicate IDs may normalize only without expanding intended scope.

Evidence layers: domain, liveview. Tasks: T01, T02. Initial status: NOT RUN.

### A012 · Forged target and evidence bindings fail [P0, M1]

Given: Another CVE/placement ID or browser-proposed evidence hash.

When: Submit a tampered action.

Required: Server validates the authorized captured scope and evidence; rejects mismatched IDs/hashes and global fallback.

Evidence layers: domain, liveview. Tasks: T01, T03. Initial status: NOT RUN.

### A013 · Authentication cannot be replaced by actor text [P0, M1]

Given: Viewer, reviewer, admin, forged actor, revoked role mid-session.

When: Attempt web mutation and ticket recovery.

Required: Actual principal is reauthorized; viewer/revoked user cannot write; forged actor cannot alter audit identity; dev shortcut does not appear in production.

Evidence layers: domain, liveview. Tasks: T01, T02. Initial status: NOT RUN.

### A014 · Complete target evidence survives package filtering [P0, M1]

Given: A selected target has multiple packages and only one matches search.

When: Inspect and commit an allowed action.

Required: Complete relevant package occurrence membership remains evidence-bound; visible filtering does not truncate decision evidence.

Evidence layers: query, domain. Tasks: T01, T05. Initial status: NOT RUN.

### A015 · Changed evidence rejects stale write [P0, M1]

Given: Draft preview followed by changed artifact/package/exposure.

When: Confirm old preview.

Required: Conflict or explicit refreshed review; no old approval applied to new evidence and no silent target expansion.

Evidence layers: domain, concurrency, liveview. Tasks: T01, T03. Initial status: NOT RUN.

### A016 · CVE switching and browser Back preserve work [P1, M1]

Given: Uncommitted changes and an independently deep-linked CVE.

When: Switch item, use Back and a legacy review URL.

Required: Draft guard, original operation, list position and filters survive or discard is explicit; detail loads beyond current page.

Evidence layers: liveview, browser. Tasks: T03, T04. Initial status: NOT RUN.

### A017 · Disconnected result is truthful [P1, M1]

Given: Saved draft or pending operation and LiveSocket disconnect.

When: Reconnect before/during an action.

Required: No false success or duplicate write; persistent state resumes with accurate pending/conflict/result context.

Evidence layers: liveview, browser. Tasks: T03. Initial status: NOT RUN.

### A018 · Legacy routes preserve meaning [P1, M1]

Given: Old overview/inventory/review/inspector/accepted/fixed/timeline links with filters/windows.

When: Follow each mapped alias.

Required: Equivalent new context or documented read-only compatibility; no lost timeline window/history/draft and no reactivated retired unsafe screen.

Evidence layers: router, liveview, browser. Tasks: T04. Initial status: NOT RUN.

### A019 · Empty and unavailable data are different [P1, M1]

Given: No import, filtered-empty result, failed source, unknown exposure/owner.

When: Render each state.

Required: Accurate error/empty guidance and source limits; no all-clear or fabricated complete coverage, ownership or exposure.

Evidence layers: query, liveview, browser. Tasks: T03. Initial status: NOT RUN.

### A020 · Exception prerequisites enforced server-side [P0, M2]

Given: Empty rationale, missing evidence, no validity date, past date or zero scope.

When: Submit accepted-risk/not-affected requests directly.

Required: Required fields and future effective boundary validated; no exception is recorded through bypassed client validation.

Evidence layers: domain, liveview. Tasks: T07. Initial status: NOT RUN.

### A021 · Not affected is not accepted risk [P0, M2]

Given: Two otherwise identical supported draft requests with different assessment types.

When: Commit each in isolated scopes.

Required: Distinct typed outcomes and evidence semantics are stored, read and reported; not_affected never writes accepted_risk as an approximation.

Evidence layers: domain, query. Tasks: T07. Initial status: NOT RUN.

### A022 · Unknown context cannot justify not affected [P0, M2]

Given: Only scanner package match and missing exposure/configuration.

When: Attempt not-affected assessment.

Required: Unsupported conclusion cannot become valid coverage; identify missing justification and retain investigation.

Evidence layers: domain, liveview. Tasks: T07. Initial status: NOT RUN.

### A023 · Exact new UTC expiry boundary [P0, M2]

Given: New exception valid through selected date with exclusive next-midnight metadata.

When: Read immediately before, at and after boundary with frozen clock.

Required: Valid before; expired exactly at boundary; SQL/domain/UI agree; review-due does not imply already expired.

Evidence layers: domain, query, liveview. Tasks: T07, T09. Initial status: NOT RUN.

### A024 · Legacy inclusive semantics remain readable [P0, M2]

Given: Legacy inclusive and new exclusive records at same stored timestamp.

When: Read each around the boundary.

Required: Each follows its preserved metadata; no speculative timestamp normalization; historical labels remain visible.

Evidence layers: domain, query, migration. Tasks: T07. Initial status: NOT RUN.

### A025 · Expired newer decision does not revive older acceptance [P0, M2]

Given: Older global acceptance, newer scoped replacement, pending future decision.

When: Advance time past newer expiry.

Required: Older acceptance stays superseded; future decision covers nothing before effective time; siblings retain their legitimate own chronology.

Evidence layers: domain, query. Tasks: T01, T07. Initial status: NOT RUN.

### A026 · Exact-scope exception never leaks [P0, M2]

Given: Production/staging and multiple package/artifact targets for same CVE.

When: Record an exception for an explicit subset.

Required: Only that subset receives supported coverage; new/sibling placements remain unaffected and visible.

Evidence layers: domain, liveview. Tasks: T07. Initial status: NOT RUN.

### A027 · Review due and invalidation re-enter attention [P1, M2]

Given: Valid exception crossing the seven-day review window, expiry or explicit material invalidation.

When: Refresh using frozen time/new material evidence.

Required: Correct target becomes attention; record remains in register/history with actual reason; no silent renewal.

Evidence layers: domain, query, liveview. Tasks: T09. Initial status: NOT RUN.

### A028 · Material change is scoped and evidence-bound [P0, M2]

Given: Independent sibling plus changed artifact/configuration/relevant intelligence on one target.

When: Recompute assessment validity and queue.

Required: Affected conclusions require reassessment under defined materiality; unrelated scope is not silently broadened or erased; prior evidence preserved.

Evidence layers: domain, query. Tasks: T09. Initial status: NOT RUN.

### A029 · Identical observations do not create duplicate work [P1, M2]

Given: Repeated scans with same material evidence and a current work/assessment record.

When: Ingest or project identical observations repeatedly in owned fixture.

Required: No repeated human task/ticket/AI request; history may collapse observations without deleting source records.

Evidence layers: domain, query, liveview. Tasks: T09. Initial status: NOT RUN.

### A030 · Reported remediation versus verified outcome [P0, M2]

Given: Legacy fixed, new reported change, insufficient then sufficient verification evidence.

When: Read legacy record, report remediation, and attempt verification.

Required: Legacy/new report remains unverified until qualifying evidence exists; successful verification records exact scope, artifact and evidence provenance.

Evidence layers: domain, query, liveview. Tasks: T08. Initial status: NOT RUN.

### A031 · Scanner absence/suppression and ticket closure are not verification [P0, M2]

Given: Finding disappears, scanner suppresses it, or ticket closes without post-change evidence.

When: Refresh reads and reports.

Required: No verified-remediation outcome or green success claim is inferred; source observation and work stay distinct.

Evidence layers: domain, query. Tasks: T08. Initial status: NOT RUN.

### A032 · Current work deduplicates; overdue work overlaps [P1, M2]

Given: Current investigation and overdue remediation in separate targets.

When: Read Needs attention and In progress.

Required: Unchanged current investigation does not endlessly requeue; overdue work can appear in both views; counts state nonadditivity.

Evidence layers: domain, query, liveview. Tasks: T09. Initial status: NOT RUN.

### A033 · Ticket preview is read-only [P0, M1]

Given: Configured fake adapter and selected exact targets.

When: Open/cancel preview, then explicitly confirm once.

Required: No POST before confirmation; preview destination/payload match committed request; no credentials disclosed.

Evidence layers: adapter, liveview. Tasks: T01, T03. Initial status: NOT RUN.

### A034 · Ticket replay and operation conflicts [P0, M1]

Given: Previously successful operation and same ID with modified request.

When: Replay identical request then reuse ID with different binding.

Required: Identical replay returns existing result; modified reuse fails; no second external ticket.

Evidence layers: domain, adapter, concurrency. Tasks: T01, T03. Initial status: NOT RUN.

### A035 · Unknown remote outcome survives local failure [P0, M1]

Given: Timeout after possible remote success, or local persistence failure after remote creation.

When: Reload and attempt recovery.

Required: Durable operation remains; no blind resend/new ID; UI says reconciliation required, not successful or safe to retry.

Evidence layers: domain, adapter, concurrency, liveview. Tasks: T01, T03. Initial status: NOT RUN.

### A036 · Recovery cannot evade ownership or uncertainty [P0, M1]

Given: Original reviewer/admin and unrelated reviewer; empty/ambiguous remote marker results.

When: Reconcile the existing claim.

Required: Only authorized recovery; unresolved remote match remains blocked; no POST, claim deletion or invented success.

Evidence layers: domain, adapter, liveview. Tasks: T01, T03. Initial status: NOT RUN.

### A037 · No external call under source locks [P0, M1]

Given: Instrumented fake ticket adapter and commit transaction.

When: Create a confirmed work item.

Required: Durable claim committed and database locks released before external POST; uncertainty handling retained.

Evidence layers: domain, adapter, concurrency. Tasks: T01, T03. Initial status: NOT RUN.

### A038 · Real responsive shared workflow [P1, M3]

Given: Actual LiveView, long evidence, many targets, required width matrix.

When: Open/act/close/back at 320–1920 widths.

Required: Readable layout without page overflow; visible action/back controls; no squeezed detail or production iframe/mock.

Evidence layers: browser. Tasks: T12. Initial status: NOT RUN.

### A039 · Keyboard, focus, zoom and assistive flow [P1, M3]

Given: Real browser keyboard, actual zoom/text spacing and available screen reader.

When: Navigate tabs/rows/dialogs, Escape, error and return focus; test 200%/400% zoom.

Required: Usable semantics/focus and no hidden critical controls; unavailable manual checks are documented, not called certified.

Evidence layers: browser, manual_accessibility. Tasks: T12. Initial status: NOT RUN.

### A040 · Error paths do not fabricate success [P0, M3]

Given: DB unavailable, conflict, role revoked, double submit, adapter failure.

When: Attempt actions and recover.

Required: Accurate bounded errors and retained draft/operation context; zero unsupported success or duplicate mutation.

Evidence layers: domain, liveview, browser. Tasks: T12. Initial status: NOT RUN.

### A041 · AI is explicit and optional [P0, M3]

Given: No wrapper, configured fake wrapper, viewer/reviewer roles.

When: Navigate, select/filter, explicitly request analysis.

Required: No call on navigation; authorized explicit call only; manual actions work when unconfigured or failed.

Evidence layers: adapter, liveview. Tasks: T10. Initial status: NOT RUN.

### A042 · Untrusted AI evidence and invented references fail [P0, M3]

Given: Advisory contains instruction-like text; response cites unknown/unauthorized evidence or returns HTML.

When: Run analysis and attempt to use output.

Required: Instructions are data; structure and semantic checks reject unusable output; displayed text escaped; no external action.

Evidence layers: adapter, domain. Tasks: T10. Initial status: NOT RUN.

### A043 · AI cannot expand or replace scope [P0, M3]

Given: Response adds/drops targets, changes CVE/finding IDs/hashes or arrives after selection changes.

When: Validate and display result.

Required: Exact request binding enforced; stale/mismatched output not usable as a current draft; no modified mutation selection.

Evidence layers: adapter, domain, liveview. Tasks: T10. Initial status: NOT RUN.

### A044 · AI cannot invent fixes or applicability [P0, M3]

Given: Invented fixed version, mismatched package, unsupported not-affected claim.

When: Validate model output.

Required: Reject or retain as unusable output; no invented upgrade or effective exception; valid draft still requires human confirmation.

Evidence layers: adapter, domain. Tasks: T10. Initial status: NOT RUN.

### A045 · AI cache and late responses respect material context [P1, M3]

Given: Same evidence, changed policy/artifact, cancellation, user edits.

When: Analyze repeatedly and deliver late responses.

Required: Bounded authorized cache reuse only when relevant context matches; stale outputs do not overwrite user work.

Evidence layers: adapter, domain, liveview. Tasks: T10. Initial status: NOT RUN.

### A046 · AI privacy and execution limits [P0, M3]

Given: Oversized/malformed output, timeout, role revoked while running, secret-bearing irrelevant input.

When: Invoke through the real adapter boundary with fakes.

Required: Bounds/authorization/redaction hold; no command execution or unrelated inventory transmission; no automatic retries/approval.

Evidence layers: adapter, domain. Tasks: T10. Initial status: NOT RUN.

### A047 · Reporting/UI use identical target predicates [P0, M3]

Given: Shared deterministic snapshot with mixed teams/states and public reference.

When: Compare domain, SQL, UI and reporting adapter.

Required: Exact IDs/counting units agree; reference-only excluded; attention/progress overlap and nonadditive team totals explicit.

Evidence layers: query, domain, reporting. Tasks: T11. Initial status: NOT RUN.

### A048 · Reporting does not turn acceptance into remediation [P0, M3]

Given: Valid accepted risk, not affected, legacy fixed, source unavailable, verified outcome.

When: Project current and historical reporting records.

Required: Separate states/counters; missing data is not zero risk; current state is not invented historical time series.

Evidence layers: domain, reporting. Tasks: T11. Initial status: NOT RUN.

### A049 · Authorized exact-scope Grafana drilldown [P0, M3]

Given: Configured/missing Grafana URL and links with valid/malformed scope.

When: Open reporting detail links.

Required: Authorized correct CVE/context, no auto write selection, credentials in URLs, open redirect or fake configured destination.

Evidence layers: router, reporting, browser. Tasks: T11. Initial status: NOT RUN.

### A050 · Representative legacy/new migration and rollback [P0, M3]

Given: Owned fixture with cases, global/scoped decisions, mixed boundaries and durable operations.

When: Apply additive changes and rehearse UI rollback.

Required: IDs/evidence/history/chronology/recovery preserved; compatible readers retained; no destructive downgrade or speculative backfill.

Evidence layers: migration, domain. Tasks: T12. Initial status: NOT RUN.

### A051 · Owned resources and read/write boundary [P0, M0]

Given: Repository database guidance and a clean isolated fixture environment.

When: Run characterization/mutation/browser checks.

Required: Only proven-owned resources modified/cleaned; no production data, external service write, unrelated process or tool state altered.

Evidence layers: process_audit. Tasks: T00, T01. Initial status: NOT RUN.

### A052 · Bounded hydration and concurrent snapshot behavior [P1, M3]

Given: Representative high CVE count and one CVE with many targets/packages; concurrent import.

When: Capture plans/reads/memory and perform scoped decision.

Required: Bounded page hydration, consistent page/counts and complete selected evidence; measured limits reported, not claimed as solved by page size.

Evidence layers: query, concurrency, performance. Tasks: T12. Initial status: NOT RUN.

### A053 · Remove UI bloat without deleting domain capability [P1, M3]

Given: Old route/component references, case history/import/replay mechanisms.

When: Audit and remove unreachable presentation code after compatibility tests.

Required: No duplicate primary screens, new dashboard substitutes, lost history or blindly deleted backend/evidence stores.

Evidence layers: static, router, browser. Tasks: T12. Initial status: NOT RUN.

### A054 · Old acceptance and security findings are mapped [P0, M0]

Given: Old PTV package and documented unresolved original security items.

When: Classify old requirements against new design.

Required: Superseded layout assertions identified; safety obligations retained; unavailable original security findings not falsely closed.

Evidence layers: review. Tasks: T00. Initial status: NOT RUN.

### A055 · Delivery evidence is real and scoped [P0, M3]

Given: Implementation report with tests, screenshots and integration claims.

When: Independently verify claims.

Required: Checks distinguish PASS/FAIL/BLOCKED/NOT RUN, mock/live, bundle/app, source/current evidence; no fabricated certification or fake action success.

Evidence layers: review. Tasks: T12. Initial status: NOT RUN.

### A056 · Package-specific fix mapping [P1, M1]

Given: Same CVE has several packages/versions or conflicting reported upgrade targets.

When: Render row, evidence and action preview.

Required: Preserve package→installed→reported-fix provenance; summarize multiple targets without implying a universal upgrade version.

Evidence layers: component, domain, browser. Tasks: T02. Initial status: NOT RUN.

### A057 · Exception register preserves source identity [P0, M2]

Given: Case exception and workspace decision with overlapping IDs/CVE.

When: Open, inspect and attempt an edit.

Required: Composite source identity, frozen evidence and revision semantics preserved; writes go to correct domain; no silent store conversion.

Evidence layers: domain, query, liveview. Tasks: T06, T07, T09. Initial status: NOT RUN.

### A058 · New labels are supported before writing [P0, M2]

Given: New assessment/verification labels and mixed old/new rows.

When: Exercise changesets, commit, SQL, readers, serializations, history and reporting.

Required: No write before compatible interpretation exists; unsupported labels do not vanish or get misclassified as accepted/fixed.

Evidence layers: domain, query, migration. Tasks: T07, T08. Initial status: NOT RUN.
