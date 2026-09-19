# Approved workspace implementation — audit and acceptance ledger

## Scope and baseline

Source: `PTV-Triage-Implementation/START-HERE.md` and specifications 01–13. Baseline commit: `aba6522`. Preserve `.DS_Store`, `.pi/fabric.json`, `.pi/fabric/mesh/state.json`, the untracked implementation package and `tmp/dev-server.log`.

Stack: Phoenix 1.8 / LiveView 1.2, Ecto/PostgreSQL, same-origin JS and Tailwind plus semantic CSS. No authentication; loopback-only runtime; typed names are self-declared. No external credentials required for local decisions.

This is a gated rollout, not authorization to cut over an incomplete redesign. `/workspace` is the reversible real-app route seam. Existing `/`, `/findings`, `/triage`, `/cases`, `/cves/:id`, `/timeline` remain available. Full default-route cutover is deferred until visual and history parity gates pass. No approved input assets will be changed.

## Actual route and data map

| Responsibility | Existing source | New seam |
|---|---|---|
| Shell | `lib/triage_web/components/layouts.ex`, `layouts/root.html.heex` | optional workspace slot in Layouts.app |
| Inventory | `FindingLive.Index`, `Inventory`, `FindingFilters` | shared server-side Workspace scope projection |
| Advisory | `CveLive.Show`, `Inventory.CveDetail` | common inspector in WorkspaceLive |
| Review | `GuidedReviewLive`, `GuidedReview.Query` | one-screen WorkspaceLive, explicit targets |
| Decisions | `Decisions`, `advisory_decisions` | additive metadata; same append-only logical history |
| Legacy assessments | `Cases`, `review_cases/review_reviews`, `Exceptions` | retained on old routes, not relabeled as new decisions |
| Timeline | `TimelineLive`, `Timeline.History` | preserve old implementation until parity; scoped decision history in inspector |
| Tools | ImportLive/ReplayLive/IntelLive | settings links; no implicit external effects |

Identity: finding ID identifies CVE/package/version within immutable image ID/digest. Placement ID identifies image + namespace + owner + environment. New decision unit is an explicit `(CVE, placement ID)` and includes every affected package occurrence at that placement in its immutable evidence snapshot; occurrence IDs are not conflated with placement IDs. Changing package evidence invalidates the preview, not silently expands it.

Observation: `resolved_at` means no longer observed, never verified remediation. Scanner suppression is `Finding.suppressed`, not an exception. Reference data has `public-reference` / `not-a-deployment` scope and a reference image predicate; excluded from operational totals. Import reconciliation updates only explicit rows; absence from a partial snapshot does not manufacture resolution. Freshness/coverage remain unverified where no comparable run receipts exist.

Scope: legacy GuidedReview filters select CVEs and then hydrate ALL their scopes, and `whitelist/4` saves a whole-advisory acceptance. It cannot safely back production-only decisions unchanged. New reads narrow placements BEFORE grouping/priority aggregation. `Risk` policy v1 remains authoritative; critical is immediate priority, not a new SSVC engine. Cached KEV positive matches remain source claims, not compromise evidence.

Decision stores: advisory decisions have optional placement scope and append supersession links. Case reviews are separate manual assessments bound to frozen snapshots and revision/token checks. New work actions must extend the existing advisory decision history rather than write approximate case outcomes or create an independently mutable duplicate store. Legacy global records keep their global label and provenance.

External boundaries: collection is disabled except guarded test loopback transport. Intelligence refresh, AI assessment and Azure creation are explicit calls. GuidedReview already separates local plans from confirmed ticket creation and persists partial/unknown state. New local save never calls these adapters. Integration UI in this slice is honest unavailable/settings access, not a fake outbound success.

## Acceptance ledger — delivered vertical slice

- [x] Package checksum verification; accepted reference inspection and `legacy-before-1600.png` capture. Initial baseline execution was blocked by incompatible cached BEAM files; verification uses an isolated `MIX_BUILD_PATH` instead of deleting the user's build.
- [x] Shared placement-scoped projection: suppression/acceptance remain active exposure; exact metric target sets, team deduplication, Unassigned (`__unassigned__`), scope-local priority and explicit unknown coverage.
- [x] Additive explicit-placement work commits, frozen observed evidence, optimistic conflict checking, replay-safe operation IDs and inclusive UTC dates. Newer scoped work takes precedence over older global coverage through a shared reader used by both the new projection and legacy review; expiry does not resurrect older acceptance.
- [x] Scoped reference CSS and four-destination shell without remote assets or reference runtime. Existing root UI remains unchanged.
- [x] Overview → scoped inventory → shared four-tab inspector → explicit-target review → decision history. Hidden draft targets block save rather than silently pruning. Save stays on its CVE; Save & next advances only after commit.
- [x] Domain/LiveView tests cover environment isolation, four work actions, retained active exposure, suppression/reference semantics, changed evidence, idempotency, validation, confirmation cancellation, selected-only review, draft return, conflict, read-only navigation and legacy-global precedence.
- [x] Browser subset: 13 review viewports (390–1920 px, including breakpoint boundaries), hit-tested save actions after scrolling; native modal Escape/focus return; four inspector tabs; 780/1240 px inspector widths; centered acceptance confirmation; production-only save and reload persistence. Additional desktop/mobile overview captures show no page overflow.
- [x] Independent final `mix precommit`: 1040 passed, 2 skipped. Final affected suite: 60 passed. Strict Credo: no issues. JS hooks/saved-filter tests: 8 passed. Owned-DB runner refusal/cleanup tests passed. All 173 package hashes and `git diff --check` passed.
- [x] Follow-up review fixed cross-route scoped/global precedence and draft guards for target-only/action-only edits and unacknowledged browser input. Real browser probes confirm cancellation, explicit discard, offline warning, scoped save/reload and persistent actions at 13 widths; evidence is under `evidence/approved-workspace/review-check/`.

## Remaining work / gates not passed

This is the genuine end-to-end slice required before expansion in specification 10, **not completion of phases A–I**. B/C/D/E/F have substantial implementation but their complete acceptance exits are not all certified. G/H/I remain gated.

- Exact 32-case synthetic fixture adapter, 90-case catalog mapping, pixel overlays/diffs and approved visual-deviation sign-off. Current screenshots use a separate two-CVE synthetic fixture, not the package's canonical dataset.
- Timeline Event log/Daily activity/coverage refinement, historical case/exception parity and consolidated settings. Existing timeline and data-tool routes are linked, not replaced by fake implementations.
- Durable drafts across reload/disconnect, saved views/exports in the new seam, full integration preview/partial/unknown UI. Typed identity is self-declared; no remote ticket/AI/intelligence refresh occurs on local save.
- Full keyboard/screen-reader/real browser zoom and additional-browser testing. Verified browser: headless Chrome 153.0.8010.48 on macOS, device scale factor 1. Responsive resizing is not a claim of real zoom testing.
- Large-data performance: rendered lists are paged at 50, but the shared projection currently hydrates matching data server-side. Move aggregation/pagination to bounded queries/streams before production-scale cutover. Commits conservatively lock their source tables NOWAIT; unrelated writes may require explicit retry/reconciliation.
- Migration reconciliation and rollback rehearsal on a representative copy containing legacy history and new work rows. No existing development or production database was migrated/reset.

## Rollout / rollback intent

Use `/workspace` as the reversible opt-in route; `/` stays on the old application. The migration is `priv/repo/migrations/20260919123750_extend_scoped_workspace_decisions.exs`, adding four columns and one uniqueness index to the existing decision store, not a second mutable store.

For UI rollback, withdraw workspace navigation while retaining the extended decision readers and schema. Do **not** drop metadata/columns or revert to code that cannot interpret new work labels after new writes exist. `Decisions.history_for_cve/2` preserves exact IDs and label readability; complete legacy-UI reconciliation is still a release gate, not a claimed pass. Do not enable default-route cutover or migrate production until that gate passes.

See `APPROVED_WORKSPACE_REPORT.md` for evidence paths and reproduction commands.
