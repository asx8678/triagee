# Triage current status

**Code review findings implemented (2026-09-13: `mix ci` exit 0 — `credo --strict`
reports no issues, 634 passed / 2 skipped, `dialyzer` 0 errors).** The findings
list pages by keyset position like the review queue; `credo` and `dialyzer` are
part of the gate and the CI workflow; both oversized modules are split — the case
detail view into section components plus a formatter, and the snapshot import into
its parse/write/reconcile stages plus a shared contract — with per-section tests
and no private state leaked between them. Boundary specs are added and verified by
dialyzer (33, in `Triage.Import`, `Risk`, `Exposure` and both filter modules).
Open, deliberately and in writing: spec coverage beyond that boundary layer, and
two advisory complexity metrics disabled with re-measured counts (36 nesting + 18
complexity) and their worst offenders recorded in `.credo.exs`. See
[CODE_REVIEW_FIXES_EXECUTION.md](CODE_REVIEW_FIXES_EXECUTION.md).

**A+B implemented (independent Astra verification PASS, 2026-09-12). UI redesign,
overview intelligence and bounded findings paging implemented and verified
(2026-09-13: `mix precommit` 612 passed / 2 skipped, exit 0).**
**Checkpoint committed locally** (`Checkpoint the triage application source and its
verified local runtime`): 197 source-only paths, staged from the generated inventory
with a bounded staged-content scan. The previously untracked `app/` is now tracked.
No push and no deployment occurred; the app remains unauthenticated and
loopback-only. `.pi/` harness state, `architecture(3).md`, `tmp/` scratch output and
evidence binaries/logs/probes stay out of git. See
[CHECKPOINT_REVIEW.md](CHECKPOINT_REVIEW.md).

## Fresh A+B evidence

- Enforced local-only runtime: exact `TRIAGE_BIND=127.0.0.1|::1`; invalid/public
  binds rejected. Strict `PORT=0..65535`, defaults test 4002 / dev+prod 4000.
- 89 affected integration tests passed; final runtime matrix has 9 tests.
- **One full guarded `mix precommit`: 484 passed, 2 skipped**, exit 0.
- **Separate exact opt-in concurrency: 2 passed**, exit 0.
- Actual test and isolated production Endpoint listeners proved IPv4/IPv6
  loopback on ephemeral ports; owned listeners stopped and all three owned DBs
  dropped (catalog confirms zero DBs/connections). User ports 4000/4001 unchanged.
- Fresh exact Astra high/nonrecursive review: **9 runtime tests, 10 shell guard
  scenarios, 31 actual-helper simulations**, production listener/HTTP probes, and
  142 candidate-file hashes passed. No blocking defect;
  [independent report](evidence/a_b/ASTRA_REVIEW.md) records limits.
- Precommit's two unrelated whitespace changes were inspected and matched to
  exact initial hashes with equal metadata-free ASTs. Lockfile/vendor assets unchanged.

Details, failures/repairs, commands, ownership, hashes and limits:
[A_B_EXECUTION.md](A_B_EXECUTION.md). Reviewed prospective inventory/exclusions:
[CHECKPOINT_REVIEW.md](CHECKPOINT_REVIEW.md). Runtime and guarded verification:
[LOCAL_RUNTIME.md](app/LOCAL_RUNTIME.md),
[OWNED_DB_VERIFICATION.md](app/OWNED_DB_VERIFICATION.md).

## Later verified work (2026-09-13)

- The findings inventory is paged and sortable: `Inventory.list_groups/1` accepts
  `:sort`, `:limit` and `:offset` through strict total orders, `count_groups/1`
  reports the unpaged total, and the list page exposes page controls plus an order
  control wired to a validated `sort`/`page` filter contract.
- The overview is compact and honest: a capped critical table and newest rail state
  the real total and what is withheld, so a truncated table cannot read as the whole
  picture.
- The advisory detail wires cached KEV/NVD intelligence and operator-declared exposure into
  the review-priority policy: severity and fix availability are derived per placement from
  that image's own occurrences, and a cached KEV entry escalates priority. The three wiring
  defects fixed (unreachable KEV lookup, KEV never reaching the policy, group-wide severity
  mixed with unrelated placement exposure) are recorded in
  [INTEL_WIRING_EXECUTION.md](INTEL_WIRING_EXECUTION.md).
- **`mix precommit`: 612 passed, 2 skipped**, exit 0 (574 before this work). Live
  read-only browser checks at 1440x900 confirmed paging, ordering, clamped and
  invalid pages, and the overview captions.
- Per-slice evidence, the defects found and fixed, file hashes and explicit limits:
  [FINDINGS_PAGING_EXECUTION.md](FINDINGS_PAGING_EXECUTION.md),
  [UI_REDESIGN_REPORT.md](UI_REDESIGN_REPORT.md),
  [UI_IMPROVEMENTS_REPORT.md](UI_IMPROVEMENTS_REPORT.md).

## KEV intelligence coverage (2026-09-15)

- The cached known-exploited signal is now the whole CISA KEV feed rather than a
  50-row prefix, and the actionable fields (`requiredAction`, `dueDate`,
  `knownRansomwareCampaignUse`) are cached and shown per advisory. The advisory page
  reports rows stored and the last refresh receipt, and renders the intel banner as a
  warning whenever the KEV cache is empty, so "no cached entry" can no longer read as
  "not known exploited".
- Verified on this tree: focused intel/CVE suites **30 passed, 0 failures**; full
  suite **705/712 passed, 2 skipped, 7 failed** — the same seven pre-existing Timeline
  window tests (696/703 before this slice, +9 new tests); `mix compile
  --warnings-as-errors`, `mix format --check-formatted`, `mix credo --strict` and
  `mix dialyzer` all exit 0. The staged stylesheet checkpoint is untouched: all 224
  manifest paths still match their staged blobs. This slice is **unstaged**.
- Defects, the transport-contract mismatch found while testing, and what remains
  unverified (live feed size, stale-cache escalation, exposure producer, queue
  filters): [KEV_INTEL_EXECUTION.md](KEV_INTEL_EXECUTION.md).

## Timeline window tests were Sunday-only (2026-09-15)

- The seven failing Timeline window tests were not a regression: they hard-coded the
  window as a round `7 * weeks` days, while the read model ends the window at today
  (Monday-aligned start), so the span is `49 + day_of_week(today)` — 56 only on a
  Sunday. The slice's own probe ran on Sunday 13 September and counted 56 bands,
  which is why the record looked clean. A weekday table is in
  [TIMELINE_EXECUTION.md](TIMELINE_EXECUTION.md).
- Fixed by deriving every window expectation from the contract
  (`Triage.Fixtures.window_span/1`), pinning the semantics with
  `length(days) == Date.diff(to, from) + 1` and
  `day_of_week(to) == 7 or length(days) < 7 * weeks`, asserting the label's real
  span, and asserting that the grid's future cells read "not yet observed". **No
  production code changed.**
- Verified: `mix test test/triage/timeline_test.exs
  test/triage_web/live/timeline_live_test.exs` → **50 passed**; **full suite 712
  passed, 2 skipped, 0 failed** (705/712 before). The earlier "696 passed" line in
  the timeline record counts the same tree in which those seven failed (696 + 7 =
  703, the pre-KEV total).

## Decisions taken on the owner's behalf (2026-09-15)

The owner delegated the remaining calls ("take decisions for me and continue").
These are decisions, not open questions; the ones I could not take are named with
the fact that is missing.

- **No commit, no push, nothing newly staged.** The index already holds the reviewed
  Tailwind checkpoint (20 files, +697/−2622 — `default.css` −2590 replaced by the
  Tailwind build) and still verifies 224/224 against
  `evidence/checkpoint/MANIFEST.sha256`. Committing *now* would land a
  `CURRENT_STATUS.md` that this session's unstaged work has already superseded and
  would mix the checkpoint with the KEV slice, the timeline fix and the cross-links
  into one unreviewed unit. The reviewed unit worth committing is one commit over the
  whole current tree; the worktree is at a green, fully recorded state for it.
- **No exposure write path.** `Triage.Exposure.record/4` is still reached only by
  `Triage.Seeds`. Who may *declare* exposure, and under which entitlement, is an
  authorization decision (work package E) — not something to invent behind a new
  button. Missing exposure evidence keeps being stated as unknown.
- **No new queue filters.** `CaseFilters` validates exactly the saved scope
  (`owner`, `environment`) and the keyset `before` cursor, and `Triage.Cases`
  exposes `list_cases/1`, `get_case/1`, `open_case/2`, `case_filter_options/0` —
  nothing that filters by assessment state or by advisory. A new filter would mean a
  new domain query, which this UI-only round excluded, so the queue keeps two honest
  filters instead of a filter that would silently return the wrong set.
- **Advisory cross-links: every site that renders a CVE id can now reach it.** The real
  gap was that only two places did (the findings list and the home page) — nothing
  reached an advisory from a case, the queue, the activity feed, a finding detail or the
  timeline. Added, each under the scope of the view it is opened from and never wider:
  `#case-cve-action` (case → advisory, under the case's **saved** scope and never the
  URL scope — the case page's own rule, so a mismatched query cannot widen the
  aggregate); `#case-cve-<id>` (queue row → advisory, under the queue's filter, absent
  when the queue is unfiltered); `#cve-inventory-link` and `#cve-package-link-<id>`
  (advisory → scoped inventory and per affected package, built through the findings
  page's own `q` search contract, so a link cannot show a different set than that search
  does); `#finding-cve-action` (finding detail → advisory under its display scope, and
  deliberately **without** the list's `q`/`sort`/cursor params, which the advisory route
  cannot apply — a link must not claim a filter it ignores); `#event-cve-<id>` (activity
  row → advisory under the activity filter); `#tl-lane-cve-<cve>` (timeline lanes →
  advisory), with the timeline's other two advisory links — the bands row button and the
  drawer's — unified onto one implementation,
  `TriageWeb.TimelineFilters.advisory_path/2`, where only `owner` and `environment`
  travel because the timeline's `weeks`/`cve` params are not advisory filters. A blank
  captured advisory id or package name renders as text, never as a link to an empty
  route or an accidentally unscoped search.
- **Three CVE ids stay deliberately unlinked**, recorded so they do not read as
  oversights: the chart's SVG gutter label (the chart's whole subtree is `ignored` in
  the accessibility tree, and the lanes and bands tables carry that navigation), the case
  page title and the drawer title (each has an explicit advisory action beside it), and
  the finding eyebrow (the header action is the affordance).
- **Deferred polish stays deferred, with reasons.** #13 (per-occurrence case count)
  needs a case count per finding and `Triage.Cases` exposes none; #16 (receipt expiry
  countdown) has no receipt expiry field — the only `expires_at` in the domain is
  exposure evidence (`lib/triage/exposure.ex:26`), so the countdown would have nothing
  truthful to count; #12 (search autofocus/shortcut) is deliberately skipped, because
  autofocus moves focus for keyboard and screen-reader users and a `/` shortcut is a
  keybinding-contract decision; #15 (hover polish) is cosmetic.

Verified on the tree carrying all of the above: `mix ci` → exit 0, **714 passed,
2 skipped, 0 failed**, `credo --strict` 1809 mods/funs with no issues, `dialyzer`
0 errors. New tests: `TriageWeb.CaseLiveTest` "the case's captured advisory opens the
advisory detail under the saved scope" and `TriageWeb.CveLiveTest` "the advisory links
into the scoped inventory and per affected package"; further assertions extend the
finding, activity and timeline suites, each deriving its expected URL through the same
contract the page uses so the two cannot drift. Guard check: every link is built from
the frozen captured value rendered beside it, and a blank captured id (or package name)
renders as text instead of a link — the present-id path is what the seeded fixtures
exercise.

## Inherited evidence, not fresh claims

Historical FAIL/PASS records are preserved:
[UI workflows](app/UI_WORKFLOWS_PLAN.md) (latest bounded 23 tests/4 probes),
[PR6](app/PR6_PLAN.md) (initial FAIL then limited offline PASS),
[PR7](app/PR7_PLAN.md) / [history](app/PR7_HISTORY.md) (bounded repairs),
[PR5](app/PR5_PLAN.md), [PR4](app/PR4_PLAN.md), and
[roadmap](IMPLEMENTATION_ROADMAP.md). Their old browser/probe counts and `/tmp`
artifacts are inherited, not reproduced or recovered by this execution.

**Original historical-baseline proof remains unresolved.** These fresh A+B results
are a new bounded baseline, not recovery of that missing evidence. The application
still has no auth: no shared deployment, real export/import, live source, SSO, or
observation ingestion is authorized. **C–F remain gated** in
[NEXT_STEPS_PLAN.md](NEXT_STEPS_PLAN.md). Checkpoint staged-diff approval and commit
are still pending: the regenerated source-only inventory awaits owner approval, and
`architecture(3).md` needs an explicit decision. Do not indiscriminately add the
untracked app or harness state.

## Tailwind asset pipeline (2026-09-15)

The frozen daisyUI stylesheet is replaced by a real build: `assets/css/tailwind.css`
(v4.1.18, `source(none)` plus one `@source "../../lib"`) is compiled by
`mix tailwind triage`, which `mix assets.setup` runs before copying the pinned vendor
dists; the root layout loads the generated sheet before the tracked, hand-written
`app.css`, which stays authoritative. `priv/static/assets/default.css` (2,590 lines,
no build behind it) is deleted. Verified in this tree: `mix format --check-formatted`,
`mix compile --warnings-as-errors`, `mix deps.unlock --check-unused`, `mix credo
--strict` (0 issues) and `mix assets.setup` all exit 0, the generated bytes are
reproducible (`05734178f35cd213252180a8921fc4d3fd8fb5b9940e1293e50941d67b8a635c`), and
[scripts/tailwind_assets_probe.exs](scripts/tailwind_assets_probe.exs) passes 22 checks
without a database, including a fresh-destination build and a synthetic `.heex` scan
witness. `mix dialyzer` passes in the test environment CI uses (0 errors), and the full suite
runs here against a local PostgreSQL 16 cluster: 696/703 passed, 2 skipped, 7 failed,
all seven pre-existing Timeline window tests that fail identically at HEAD. No production
digest path exists because there is no deployment target. Details: [TAILWIND_EXECUTION.md](TAILWIND_EXECUTION.md).

## KEV visibility and the Timeline window (2026-09-15)

The cached KEV signal now reaches the views where triage decisions are made: the
findings list, the overview critical table, the review queue, the case header and the
timeline lanes render a "Known exploited (KEV cache)" marker only when the cache holds
a row, with one source note per page; the advisory page adds the recorded required
action, due date and ransomware flag. Ingest keeps the whole feed (the 50-row prefix is
gone), persists those three fields and enforces the 8 MB bound at one transport boundary
for real and injected transports alike. A review of that delta found the
timeline lane component never received the index (fixed), that none of the five marker
surfaces was tested (six tests added) and that `lib/triage/intel.ex` broke
`mix format --check-formatted` (fixed). Verified on the current tree: `mix test`
**721 passed, 2 skipped, 0 failures** — the seven Timeline window tests now pass under
the `window_span/1` contract that derives the today-clamped span instead of hard-coding
56 days — and `mix format --check-formatted`, `mix compile --warnings-as-errors`,
`mix credo --strict` (0 issues) and `mix dialyzer` (`MIX_ENV=test`, 0 errors) all exit 0.
The staged Tailwind checkpoint is untouched: 224/224 manifest paths still match their
staged blobs. Details: [KEV_INTEL_EXECUTION.md](KEV_INTEL_EXECUTION.md).
