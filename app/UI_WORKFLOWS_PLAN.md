# UI workflow completion — current independent verdict and historical ledger

## Current Astra browser verdict — PASS within bounded local coverage

- Actual shipped LiveSocket, `DOM.setFileInputFiles` and ordinary pointer clicks;
  1440/375/320 roots, seven visible working nav links, six real homepage cards,
  exact titles/active state, keyboard outline and focused skip-to-main. Scoped
  owned finding/case routes keep navigation. Screenshots captured and read.
- Replay complete faithful counts/digest, full DB unchanged until explicit Save;
  one receipt on Save/repeat; invalid/oversize/new input/cancel clear bindings.
  History 25+2 ordered receipts, safe expanded summary, Next/First, invalid/empty/
  expired recovery. Expiry uses owned expired fixtures, not a 30-day wait.
- Real historical preview preserves full DB; review + checkbox + Apply creates
  exactly one image/placement/finding/event. Missing ack, wrong nonce, new/pending
  upload, invalid input, cancel and duplicate cannot reuse a binding. An owned
  Import metadata change makes an old browser preview stale; fresh apply changes
  inventory only, preserving nonempty case/snapshot/event and replay history.
- Corrected native button `value=""` rejection in Replay Save/Clear and Import
  Review; scoped CSS fixes confirmation wrapping and long source-fact/table
  overflow; main gets `tabindex="-1"`. No protected backend/dependency edits.
- Fresh tests: initial new regressions **0/2**; corrected workflow **14 passed**;
  final shared-layout/workflow **23 passed**; independent direct probes **4 passed**.
  Browser ledger: **105 passes, 4 retained historical failed assertions**; two
  real layout failures fixed, two assertion/protocol probe mistakes diagnosed.
  Initial browser Save timeout, rejected expiry-fixture UPDATE and one stale CDP
  node retry also remain documented, not presented as product passes.
- No browser console errors, external page requests or HTTP error responses
  observed. 27 screenshots and scripts in `/tmp/ui-browser-evidence/`.
- Full dev/shared schema+row dumps identical (only pg_dump nonces normalized);
  **1,152 protected hashes match**. Owned DB/endpoint/Chrome/profile/daemon removed;
  user app remains stopped. No ports 4000/4001 or existing sessions touched.
- Earlier 473 passed/2 skipped and 3 real backend probes below are inherited,
  not rerun. Exact artifacts, limitations, source hashes and next prompt:
  `/tmp/ui-astra-final.md`.

## Historical integration ledger (preserved)


## Scope and execution

Approved three source slices supplied `/tmp/ui-shell.md`, `/tmp/ui-replay.md` and
`/tmp/ui-import.md`; all writers were stopped per user instruction. Integration
was serialized by this assistant. No nested agents, harness changes or commits.
Only new UI/helper/tests/CSS, shell/router/home and minimal root-title branding
were changed; existing finding/case/What's New views retain their authorized
one-line `Layouts.app active_page` additions. Protected Import/Inventory/Cases/
Collection/Replay/Runs, migrations, dependencies/configuration and existing tests
match the integration-start manifest. The helper calls unchanged Import APIs.

## Four-request acceptance matrix

| Request | Implementation / checks | Result |
| --- | --- | --- |
| Branded homepage | `page_html/home.html.heex`, existing wordmark, six real workflow cards, local/no-auth/disabled-live-source notices; root title Home · Triage | Controller tests + direct Plug response verified; visual review pending |
| All-page navigation | `Layouts.app`, router, seven named wrapping links, canonical active keys, keyboard focus/skip link; mobile CSS without hidden-menu dependency | Seven root titles/labels/hrefs/active states mechanically verified; detail/error and affected old LiveViews green; actual desktop/375px pending |
| Replay + history | `ReplayLive`, `ReplayHistoryLive`, genuine `/assets/examples/replay.json`; one JSON upload, 1,000,000-byte limit and descriptor read cap +1, pure Replay.run, explicit Runs.record_result save only; safe counts/completeness/diagnostics/digest | Real LiveView upload/ordinary submit, no-write replay, explicit/duplicate save, wrong-shape/new/cancel/oversize/quota/error clearing and secret omission pass; 25 ascending receipts/Next/First, invalid and expired-page clearing, read-only history pass |
| Historical import | `ImportFlow.prepare/read_upload/apply`, `ImportLive`; lexical depth 32 + byte guard; preview → review → exact server nonce + ack → explicit apply | Preview no-write, no-SQL malformed bindings, real upload/submit, missing ack/forged/new/cancel/duplicate clearing pass; stale full report AND affected-row fingerprints rechecked under Import lock; unchanged write! in one transaction; separate backend lock and rollback probes pass |

## Corrections made during integration

- Real upload-only form submits include `replay=` / `snapshot=`. Exact empty-field
  shapes and empty forms are accepted; arbitrary nested/path/JSON fields are not.
  Removed the import hidden field whose `snapshot[intent]` collided with the file
  input's `snapshot` name. No special mock-only test submit protocol was introduced.
- Replaced test `LazyHTML.filter` (root-node filter) with descendant `query`.
- Rejected consumed replay JSON no longer attempts to cancel the already stopped
  upload process from the pre-consumption socket. Invalid JSON now fails closed.
- Added import upload-progress binding invalidation and exact review/apply shapes.
- A full action report alone cannot detect two different old metadata values that
  both require `:update`. Added deterministic hashes of actual affected image,
  placement, finding and event rows to the report binding. Same-ID/same-count
  changed metadata is now stale, not silently overwritten. Queries use fixed
  server identifiers and parameterized digests; private fingerprints never render.
- Root branding is Home/default or page title + Triage. New replay pages no longer
  nest main landmarks. New workflow buttons and the actual file-input element
  receive scoped styling and bounded width.

## Runtime evidence (all Mix explicitly test + owned partition)

Partition: `_ui_integrate_0911a`, DB `triage_test_ui_integrate_0911a`. Literal ABSENT
was confirmed before creation; test config and SQL current_database were checked
before effects. No dev/shared writes, migrations, tests or seeds. Existing test
fixtures seed only the disposable sandbox. Mix task help was read before use.

1. Initial scoped integration: **12/32 passed, 20 failures**; inspected failures.
2. Focused protocol diagnostic: **0/2** before fix, actual wire shapes recorded;
   temporary event logging removed. No source input logging remains.
3. Scoped corrections: **27/28 passed**, exposed consumed-upload recancel crash.
4. After crash fix and adversarial additions: **20 passed** (replay/import/helper).
5. Shared navigation/controllers + affected old/new LiveViews: **109 passed**.
6. **ONE `mix precommit`: 473 passed, 2 skipped**, exit 0. Existing Import
   concurrency tests require exact owned-empty-DB opt-in, so they remain skipped;
   their pre-existing nil-opt-in compiler warning is recorded, not repaired.
7. Separate-backend probe **3 passed**: Import holder→Flow waiter→stale rejection;
   Flow holder→Import waiter→unchanged/existing rather than duplicate; trigger
   failure at final event insert→all inventory rows rolled back. Distinct backend
   PIDs and actual advisory waiters verified. Probe-owned trigger/function removed.
8. Direct Plug/API mechanical check: seven page titles/labels/hrefs/active states;
   three route modules; six public helper/component APIs; eight static assets;
   example fixture equality + faithful counts; all nine app tables remain empty.

Logs/scripts: `/tmp/ui-integration-evidence/` (`scoped-initial.log`, `protocol.log`,
`scoped-fixed.log`, `affected.log`, `navigation-affected.log`, `precommit.log`,
`backend_probe.exs`, `backend-probe.log`, `mechanical.exs`, `mechanical.log`).
Exact handoff and command list: `/tmp/ui-integration.md`.

## Protection, cleanup and honest exclusions

- Current-startup full schema + row pg_dumps of `triage_dev` and shared
  `triage_test` match before/after, stripping **only** restrict/unrestrict nonces.
  This captures the user's already-applied PR7 migration; no old-baseline claim.
- Protected manifest excludes only authorized UI/new helper/test paths; all
  protected files including deps, mix files and migrations match after precommit.
- Owned DB ended with nine zero application-table counts, was dropped, and is
  verified ABSENT. No listener/server/browser started; no user process signalled.
  Port 4000 belongs to another project and was untouched; port 4001 remains stopped.
- No live sources, Oban, auth, migration, scheduler, history rewrites or snapshot
  conversion. Nonces bind local server state, not durable authorization. Approved
  historical import can stale existing review evidence but never edits history.
- Independent reviewer must still verify actual desktop/mobile rendering,
  keyboard flow, upload picker interactions and overflow. Plug/LiveView tests are
  not browser evidence. No new production build or browser signoff is claimed.
- Dedicated injected UI DB-unavailable/temp-read-failure tests were not added;
  static fallback branches exist, bounded-reader and transaction failure probes
  cover their underlying safety properties. Expiry transition uses expired
  fixtures rather than waiting 30 days. Advisory locks coordinate Import writers,
  not arbitrary external SQL writers that ignore the lock.
