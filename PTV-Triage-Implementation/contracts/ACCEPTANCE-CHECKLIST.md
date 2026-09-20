# Acceptance checklist — implementation agent

These 90 scenarios are required checks, not production results. Complete the evidence template with actual application test outputs.

## SHELL-01 · Default landing
**Setup/action:** Open the application root
**Pass condition:** Overview is default, with four destinations and shared scope bar.
**Status:** Not run in the target application. **Evidence:** __

## SHELL-02 · Navigation geometry
**Setup/action:** Render the 1600×1000 fixture
**Pass condition:** 52px nav,46px scope,26px status; exact accepted colors and typography.
**Status:** Not run in the target application. **Evidence:** __

## SHELL-03 · Shared filter
**Setup/action:** Change team/environment then navigate all destinations
**Pass condition:** Same predicate is applied; no silent reset/broadening.
**Status:** Not run in the target application. **Evidence:** __

## SHELL-04 · Browser history
**Setup/action:** Search/filter, inspect, review, then Back/Forward
**Pass condition:** Logical read state and selected context restored; no mutation.
**Status:** Not run in the target application. **Evidence:** __

## SHELL-05 · No unintended network
**Setup/action:** Navigate/inspect all pages with integration spies
**Pass condition:** No ticket, AI, refresh or new third-party asset requests.
**Status:** Not run in the target application. **Evidence:** __

## SHELL-06 · Small viewport
**Setup/action:** Use 390×844 and breakpoint boundaries
**Pass condition:** No document overflow; correct queue-or-assessment layout.
**Status:** Not run in the target application. **Evidence:** __

## SHELL-07 · Real zoom
**Setup/action:** Use actual 200% browser zoom
**Pass condition:** Main actions remain reachable; readable reflow.
**Status:** Not run in the target application. **Evidence:** __

## SHELL-08 · Local identity
**Setup/action:** Use existing no-sign-in mode
**Pass condition:** Self-declared names are not represented as authenticated approval.
**Status:** Not run in the target application. **Evidence:** __

## OVERVIEW-01 · Fixture totals
**Setup/action:** Reset ptv-approved-v1 visual fixture
**Pass condition:** 18 active CVEs,12 decision CVEs,3 P1 CVEs,10 unknown-exposure scopes.
**Status:** Not run in the target application. **Evidence:** __

## OVERVIEW-02 · Scope count sets
**Setup/action:** Apply all 18 team/environment combinations
**Pass condition:** Contributing sets match fixture-expectations.json, not only totals.
**Status:** Not run in the target application. **Evidence:** __

## OVERVIEW-03 · Active drilldown
**Setup/action:** Click Active metric
**Pass condition:** Returns exact active CVE set and matching underlying targets.
**Status:** Not run in the target application. **Evidence:** __

## OVERVIEW-04 · Decision drilldown
**Setup/action:** Click decision metric and team counts
**Pass condition:** Exact queue predicate retained with current environment.
**Status:** Not run in the target application. **Evidence:** __

## OVERVIEW-05 · Unknown unit
**Setup/action:** Click unknown-exposure metric
**Pass condition:** Scope count and exact unknown target subset retained.
**Status:** Not run in the target application. **Evidence:** __

## OVERVIEW-06 · Shared ownership
**Setup/action:** CVE exists in two teams
**Pass condition:** Global dedupe; within-team dedupe; team rows not misleadingly summed.
**Status:** Not run in the target application. **Evidence:** __

## OVERVIEW-07 · Unassigned
**Setup/action:** Remove team ownership on test target
**Pass condition:** Unassigned bucket and action are visible; no dropped count.
**Status:** Not run in the target application. **Evidence:** __

## OVERVIEW-08 · Reference-only record
**Setup/action:** Add public-reference advisory without deployment
**Pass condition:** Excluded from operational active counts.
**Status:** Not run in the target application. **Evidence:** __

## OVERVIEW-09 · Stale/partial summary
**Setup/action:** Delay or fail one relevant source
**Pass condition:** As-of/coverage qualifier; no false current/safe total.
**Status:** Not run in the target application. **Evidence:** __

## OVERVIEW-10 · Scoped priority
**Setup/action:** P1 in production, lower priority in staging for same CVE
**Pass condition:** Staging-only view does not inherit out-of-scope P1.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-01 · Visible filters
**Setup/action:** Open inventory
**Pass condition:** Search and primary controls immediately visible, not accordion-hidden.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-02 · Search
**Setup/action:** Search ZLIB, then nonexistent string
**Pass condition:** Case-insensitive exact result; truthful filtered-empty state.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-03 · Stable sort
**Setup/action:** Sort priority/age with ties
**Pass condition:** Stable ID tie breaker; no selection loss.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-04 · Selection separation
**Setup/action:** Click checkbox then CVE link
**Pass condition:** Checkbox selects only; link opens inspector only.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-05 · Select-all scope
**Setup/action:** Use paginated results and header checkbox
**Pass condition:** Explicit current-page/all-matching semantics; correct indeterminate state.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-06 · Batch review
**Setup/action:** Select two CVEs and Review selected
**Pass condition:** Only those advisory IDs in queue; target decisions still explicit.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-07 · Saved view
**Setup/action:** Save and reload filters/sort
**Pass condition:** Correct read state restored, no draft/secret content persisted in view.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-08 · Long values
**Setup/action:** Use long registry path/version/description
**Pass condition:** No outer overflow or character-by-character version breaks.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-09 · Mixed states
**Setup/action:** Same CVE open/accepted/stale across targets
**Pass condition:** Facts coexist or clearly summarized as Mixed, not false resolved.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-10 · Pagination completeness
**Setup/action:** Use larger fixture exceeding initial page size
**Pass condition:** True total/pagination; no silent cap.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-11 · Export scope
**Setup/action:** Export filtered and selected sets
**Pass condition:** Only intended targets; metadata/units correct; no secrets.
**Status:** Not run in the target application. **Evidence:** __

## INVENTORY-12 · Density
**Setup/action:** Toggle compact/comfortable
**Pass condition:** 40px base compact and49px comfortable reference rows; context preserved.
**Status:** Not run in the target application. **Evidence:** __

## INSPECTOR-01 · Shared component
**Setup/action:** Open from overview/inventory/review/timeline
**Pass condition:** Same inspector structure and correct record/scope.
**Status:** Not run in the target application. **Evidence:** __

## INSPECTOR-02 · Default/expanded width
**Setup/action:** Open and expand at a 1600px viewport
**Pass condition:** 780px default;1240px expanded; no lost tab/draft.
**Status:** Not run in the target application. **Evidence:** __

## INSPECTOR-03 · Sections
**Setup/action:** Use Summary/Affected/History/Evidence
**Pass condition:** Actual scoped data and useful unknown states in each.
**Status:** Not run in the target application. **Evidence:** __

## INSPECTOR-04 · Fixed controls
**Setup/action:** Scroll body to bottom at 1280×720
**Pass condition:** Close/Expand/Review reachable and unobscured.
**Status:** Not run in the target application. **Evidence:** __

## INSPECTOR-05 · Return state
**Setup/action:** Close after multiple tab changes
**Pass condition:** Exact originating table position/filter/selection retained.
**Status:** Not run in the target application. **Evidence:** __

## INSPECTOR-06 · Direct review
**Setup/action:** Activate Review this CVE
**Pass condition:** Same advisory/scoped assessment, not generic queue first item.
**Status:** Not run in the target application. **Evidence:** __

## INSPECTOR-07 · Scope filtered out
**Setup/action:** Deep link outside current scope
**Pass condition:** Explicit out-of-scope state, never fallback to all targets.
**Status:** Not run in the target application. **Evidence:** __

## INSPECTOR-08 · History scoping
**Setup/action:** Decision exists only for another team
**Pass condition:** No false attribution to current filtered team; legacy/global labeled.
**Status:** Not run in the target application. **Evidence:** __

## INSPECTOR-09 · Focus lifecycle
**Setup/action:** Keyboard open/tab/Escape/close
**Pass condition:** Top-dialog containment and logical opener restoration.
**Status:** Not run in the target application. **Evidence:** __

## INSPECTOR-10 · Mobile
**Setup/action:** Use 390×844 long evidence
**Pass condition:** Readable drawer and persistent action footer.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-01 · No wizard
**Setup/action:** Open eligible CVE
**Pass condition:** Evidence/targets/decision on single workspace, not four mandatory steps.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-02 · Default scope count
**Setup/action:** Open DEMO-2026-001
**Pass condition:** s01 and s02 selected, both count indicators show 2.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-03 · Production-only commit
**Setup/action:** Uncheck s02; request remediation for s01
**Pass condition:** Only s01 is planned; s02 remains unresolved; active CVE total stays 18.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-04 · Draft preservation
**Setup/action:** Type note,inspect,next,previous
**Pass condition:** Same values/action/date/target IDs recovered; not submitted.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-05 · Filter narrowing
**Setup/action:** Draft contains hidden scope then narrow/broaden filter
**Pass condition:** No silent irreversible target deletion or expansion.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-06 · New target
**Setup/action:** Import new deployment while draft open
**Pass condition:** New target not auto-selected; explicit reconciliation.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-07 · Required fields
**Setup/action:** Submit missing owner/rationale/targets/date
**Pass condition:** Visible accessible errors, no commit, draft intact.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-08 · Action fields
**Setup/action:** Change all four action types
**Pass condition:** Correct conditional labels/validation; no state change yet.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-09 · Save without next
**Setup/action:** Commit valid local decision with Save decision
**Pass condition:** Confirmed scoped result without forced unintended advancement.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-10 · Save and next
**Setup/action:** Commit through Save and next
**Pass condition:** Success before deterministic advance; remaining scopes stay actionable.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-11 · Failed save
**Setup/action:** Make backend reject/time out before confirmation
**Pass condition:** No success toast; fields/position preserved; retry safe.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-12 · Double click
**Setup/action:** Submit same operation twice
**Pass condition:** Single logical decision/audit result; pending state visible.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-13 · Concurrency
**Setup/action:** Another operator changes targets/decision before save
**Pass condition:** Conflict/reconcile flow, no silent overwrite.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-14 · Footer visibility
**Setup/action:** Scroll evidence/decision at all supported sizes
**Pass condition:** Primary actions unobscured; save-without-next available at compact widths.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-15 · Queue toggle
**Setup/action:** Switch mobile queue/assessment
**Pass condition:** Same selected advisory and draft; one pane at a time.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-16 · Decision history
**Setup/action:** Save and open history
**Pass condition:** Immutable scoped audit with time/attribution/rationale.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-17 · Risk cancel
**Setup/action:** Prepare acceptance and Cancel
**Pass condition:** No state/count/audit change; draft intact.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-18 · Risk confirm
**Setup/action:** Accept only s01 through a chosen UTC date
**Pass condition:** Exact immutable target set ; active CVEs stay 18; s02 stays unresolved; correct expiry.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-19 · Expiry
**Setup/action:** Advance test clock beyond inclusive end date
**Pass condition:** Affected target returns to work; history preserved.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-20 · Attribution
**Setup/action:** No-sign-in operator enters name
**Pass condition:** Stored/displayed self-declared, not authenticated.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-21 · Request verification
**Setup/action:** Save verification work
**Pass condition:** Not a verified fix; observation unchanged.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-22 · Inert text
**Setup/action:** Use markup-like note/advisory payload
**Pass condition:** Rendered inert; no script execution.
**Status:** Not run in the target application. **Evidence:** __

## REVIEW-23 · All work complete
**Setup/action:** Finish current queue
**Pass condition:** Truthful no-decisions state, not Safe; active view still reachable.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-01 · Sibling views
**Setup/action:** Open tracks/log/daily
**Pass condition:** Three sibling tabs, not large stacked page.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-02 · Event reconciliation
**Setup/action:** Filter window/type/team/environment
**Pass condition:** Same eventIDs/units across stats,tracks and log.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-03 · All lanes
**Setup/action:** Dataset exceeds old 12/50-lane limit
**Pass condition:** Explicit complete pagination/scroll access, no hidden cap.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-04 · Marker semantics
**Setup/action:** Exercise all event types
**Pass condition:** Distinct labels/shapes; no green new detection or false fixed.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-05 · Marker detail
**Setup/action:** Click recorded event
**Pass condition:** Same advisory inspector on scoped History with exact event.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-06 · Coverage gaps
**Setup/action:** Incomplete/missing/comparable completed scans
**Pass condition:** Different coverage states; absence inferred only when supported.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-07 · No repair inference
**Setup/action:** Disappear or close ticket without verification
**Pass condition:** No longer observed/verification pending, not Fixed.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-08 · Future day
**Setup/action:** Inspect tomorrow on heatmap
**Pass condition:** Dash/unavailable, not zero.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-09 · Distinct daily count
**Setup/action:** Same CVE first appears in multiple scopes on day
**Pass condition:** Distinct-CVE bucket deduped; scope event count separately labeled.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-10 · Unknown dates
**Setup/action:** Import suppression with unknown action date
**Pass condition:** Unknown preserved; no less-than-minute fabricated response.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-11 · Out-of-order import
**Setup/action:** Import late older observation and duplicate scan
**Pass condition:** Evidence time ordering correct; no duplicate first/event inflation.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-12 · Time boundaries
**Setup/action:** Window endpoints and timezone/daylight-saving fixtures
**Pass condition:** Deterministic buckets/expiry; not double-counted.
**Status:** Not run in the target application. **Evidence:** __

## TIMELINE-13 · Accessible alternative
**Setup/action:** Use event log without chart interaction
**Pass condition:** Every relevant event accessible with same scope/window.
**Status:** Not run in the target application. **Evidence:** __

## INTEGRATION-01 · Disconnected
**Setup/action:** No Azure DevOps or AI configuration
**Pass condition:** Local review works; no giant blocking setup section.
**Status:** Not run in the target application. **Evidence:** __

## INTEGRATION-02 · Preview
**Setup/action:** Prepare ticket operation
**Pass condition:** Exact team destinations/payload/existing links before outbound confirm.
**Status:** Not run in the target application. **Evidence:** __

## INTEGRATION-03 · Preview invalidation
**Setup/action:** Edit targets/note after preview
**Pass condition:** Material change requires renewed preview/confirmation.
**Status:** Not run in the target application. **Evidence:** __

## INTEGRATION-04 · Separate local save
**Setup/action:** Save remediation decision normally
**Pass condition:** No external work item created.
**Status:** Not run in the target application. **Evidence:** __

## INTEGRATION-05 · Partial success
**Setup/action:** One test team succeeds, one fails
**Pass condition:** Successful link retained; retry only remaining targets.
**Status:** Not run in the target application. **Evidence:** __

## INTEGRATION-06 · Unknown remote result
**Setup/action:** Simulate timeout after possible creation
**Pass condition:** Reconcile before retry; no guarantee of exactly-once.
**Status:** Not run in the target application. **Evidence:** __

## INTEGRATION-07 · AI advisory only
**Setup/action:** Run sanctioned test AI advice
**Pass condition:** Explicit provider/context, advice not approval/fix.
**Status:** Not run in the target application. **Evidence:** __

## INTEGRATION-08 · Settings read
**Setup/action:** Open data settings/health
**Pass condition:** No automatic refresh or exposed secret.
**Status:** Not run in the target application. **Evidence:** __

## INTEGRATION-09 · Reset
**Setup/action:** Inspect production settings
**Pass condition:** Demo reset not mapped to production deletion.
**Status:** Not run in the target application. **Evidence:** __

## MIGRATION-01 · Legacy route
**Setup/action:** Follow old CVE/review/history deep links
**Pass condition:** Compatible route to equivalent record/scope/history.
**Status:** Not run in the target application. **Evidence:** __

## MIGRATION-02 · Legacy meaning
**Setup/action:** Migrate global/unknown-scope assessments
**Pass condition:** Original meaning/provenance retained; no invented author/date/scope.
**Status:** Not run in the target application. **Evidence:** __

## MIGRATION-03 · Data reconciliation
**Setup/action:** Compare pre/post stable IDs and history
**Pass condition:** No loss or duplicated decision; counts explained.
**Status:** Not run in the target application. **Evidence:** __

## MIGRATION-04 · Rollback
**Setup/action:** Revert feature flag on isolated migrated copy
**Pass condition:** Old reads remain compatible; new writes recoverable; no data loss.
**Status:** Not run in the target application. **Evidence:** __

## MIGRATION-05 · Delivery honesty
**Setup/action:** Inspect final report
**Pass condition:** Reference/application tests distinguished; actual screenshots/results and limitations.
**Status:** Not run in the target application. **Evidence:** __
