# CVE Triage — practical implementation roadmap

## Current implementation decision: Phoenix through scoped PR7 and local UI completion

## Current independent UI verification — PASS within bounded local coverage

Owned headless Chrome completed desktop 1440 and mobile 375/320 navigation,
homepage destinations, keyboard/skip focus, scoped details, real replay uploads
and explicit Save, 27-receipt pagination, import preview/review/acknowledged Apply,
replacement/pending uploads and stale rejection through unchanged Import APIs.
Fixed native button empty-value protocol handling, narrow confirmation/source
fact overflow and skip target focus, only in authorized UI/CSS/layout plus tests.
**23 final affected tests + 4 independent direct probes passed**. Browser history:
**105 pass entries, 4 retained failures** (two corrected layout failures, two
probe artifacts); initial ordinary Save failure and 0/2 regression reproduction
are retained separately. No new full 473-test or backend-lock run claimed.
Full dev/shared dumps and 1,152 protected file hashes match. Only the owned
random-loopback test runtime ran; DB/Chrome/profile/daemon/endpoint cleaned up,
user ports and sessions untouched, app left stopped. See `/tmp/ui-astra-final.md`
and 27 screenshots/scripts under `/tmp/ui-browser-evidence/`. Previous evidence
and its exclusions below remain historical, not silently upgraded.

## Historical UI integration — runtime gates passed, browser pending at handoff

The approved shell/replay/import source slices are integrated without changing
Import, Inventory, Cases, Collection, Replay/Runs, migrations, dependencies or
harness configuration. Homepage branding, seven-link wrapping navigation and
active states cover all routes; the root title suffix is now Triage. Existing
LiveViews retain only their authorized one-line active-page shell additions.

Real bounded JSON uploads drive `/replay` (pure, safe summary; explicit Save only),
`/replay/history` (25 ascending unexpired receipts, truthful pagination, read-only),
and `/imports` (read-only preview → review → exact nonce + acknowledgement →
explicit atomic apply). Forged/new/error/cancel transitions clear old bindings.
ImportFlow binds the full report plus actual affected inventory, rejecting changed
same-ID metadata even when action counts match; it rechecks under the existing
Import advisory lock and calls unchanged `Import.write!` in that transaction.
Confirmed imports can stale prior review evidence, never rewrite human history.
No replay-to-current-snapshot fabrication, live sources, Oban, scheduler or auth.
This remains an unauthenticated loopback-only local operator UI, not access control.

Fresh evidence: affected tests 20 passed; shared navigation/controllers and old/new
LiveViews 109 passed; **one** full precommit 473 passed, **2 existing opt-in Import
concurrency skips** (existing nil-opt-in warning retained). Separate PostgreSQL
backends proved both Import↔Flow lock directions and stale/no-duplicate behavior;
a late event-write failure proved whole-inventory rollback (**3 probes passed**).
Mechanical checks cover exact public APIs/routes, seven titles/labels/links/active
states, static example/assets, and faithful safe replay counts. Initial integration
failures were inspected and fixed: upload submit wire shapes, LazyHTML descendant
queries, consumed-upload recancellation, and equal-action stale metadata detection.

Fresh ABSENT guarded test partition `triage_test_ui_integrate_0911a` was checked
against configured/current DB, then dropped and verified ABSENT. Current dev/shared
full schema/row captures (including user-startup PR7 migration) match before/after;
only pg_dump restrict nonces were stripped. Protected source/dependency manifests
match. No listener or browser was started, no user app was touched; Triage stays
stopped. Independent reviewer owns actual desktop/mobile/browser verification.
See `app/UI_WORKFLOWS_PLAN.md`, `app/README.md`, `/tmp/ui-integration.md`, and
`/tmp/ui-integration-evidence/`. Older PR7/PR6 evidence below remains historical,
not a claim that the new UI has passed visual review.

## Current bounded independent PR7 recheck — PASS

All three repaired acceptance defects independently pass on the final tree:
genuine stage-specific Query metrics preserve open/suppressed Normalize parity;
unknown inventory evidence cannot complete; lexical 5000 aggregate array-value,
64 object-field-occurrence and depth-32 bounds precede Jason decoding.
Fresh unchanged adversarial checks: **4/4**. Fresh targeted tests: **105/105**
(11 Replay, 6 CLI, 8 history, 80 Collection), exit 0. Fresh actual CLI exits:
complete/suppressed/incomplete/invalid **0/0/2/1**, with asserted JSON. Four additional
actual-task probes with refused DB port 1 produced identical JSON and verified
Repo/Endpoint absent and triage not started at output, including nonzero exits.

Protected PR6 and CLI/ledger/migration hashes and read-only full dev/shared-test
row/schema dumps matched before/after. The absent-before disposable partition
`triage_test_pr7close_0911c` was dropped and verified absent; final owned counts
were 0/0/0. Current Phoenix PID **64795** was unchanged and untouched.
Prior separate-backend concurrency and rollback/remigrate evidence was inspected
and is **inherited**, not rerun. No new production build or full precommit result
is claimed. This PASS closes exactly the three fixes, not a new full-scope audit.
Prior BLOCKED and repair-pending records below are retained as history, superseded
only for this bounded acceptance. Details, hashes, cleanup and limits:
`/tmp/pr7-astra-closeout.md`; fresh evidence: `/tmp/pr7-closeout-evidence/`.

## Previous repair verdict — independent recheck pending (historical)

The three independently reproduced replay blockers are repaired in PR7-only code:
Query-shaped detail counts preserve open/suppressed findings; closed stage-specific
image/metrics schemas reject unknown evidence as incomplete; lexical array-element
(5000) and object-field (64) budgets run before Jason decoding. Genuine fixtures
and same-process unchanged Normalize parity are covered. The retained adversarial
suite passed 4/4 unchanged after its baseline 1/4 (three failures). Affected tests
passed 105 (11 Replay, 6 CLI, 8 history, 80 Collection); final-fixture Replay and
fresh CLI complete/suppressed/incomplete/invalid checks are recorded in
`/tmp/pr7-replay-repair.md`. No new full precommit, production build, or unchanged
ledger concurrency rerun. Independent acceptance remains pending; previous
verification and PR6 history below are retained, not new signoff.

Pure synthetic versioned JSON is normalized locally and projected to a redacted,
non-actionable summary with canonical SHA-256. The file CLI exits 0/2/1 without
app/Repo startup, including isolated production without runtime DB credentials.
Explicit Runs APIs recompute results, hash keys, deduplicate transactionally,
reject updates, retain receipts for 30 days, cap physical rows at 1000, and hide
expired rows pending explicit purge. Separate-connection dedup/conflict/quota/purge
probes passed on a disposable partition. No scheduler, source snapshots, lifecycle,
live collection, inventory/review mutation, or new UI. See `app/PR7_PLAN.md`,
`app/PR7_CLI.md`, and `app/PR7_HISTORY.md`. Earlier PR6 records below remain historical.

## Earlier implementation decisions: PR1–PR6

The user selected **Elixir + Phoenix LiveView + Ecto + PostgreSQL**, implemented as a conventional single application in `app/`. This supersedes the earlier TypeScript/SQLite and Go runtime recommendations below and in `architecture(3).md`; their integration findings and safety requirements remain relevant. `tmp/cve-collector/` is a read-only behavioral reference, not a runtime dependency.

**PR 1 — foundation and offline inventory: implemented and verified.** Application lives in `app/` (Phoenix 1.8.13, LiveView 1.2, Ecto/PostgreSQL, pinned via `app/.mise.toml`: erlang 27.3.4.16, elixir 1.20.4-otp-27). See `app/README.md` for setup/run/test commands. My Work/news workflows, production collection, SSO, AI, exception writes and remediation remain later milestones; scoped local cases/evidence/review (PR 2) is delivered and fully verified (final Astra closeout PASS, 2026-09-10). The read-only `/cases` Review Queue (PR 3) is now also implemented and verified (final independent Astra signoff PASS, 2026-09-10; durable record in `app/PR3_PLAN.md`).

### PR 1 verification record

- `mix test`: 26/26 passed (context idempotence, team/environment scoping, suppressed/resolved/reopened semantics, LiveView list/filter/detail journeys, safe third-party text).
- `mix format --check-formatted` and `mix compile --warnings-as-errors`: clean (0 warnings).
- Browser smoke (headless Chromium 152 via CDP): inventory renders grouped advisories with counts/flags; team filter restores from URL; unknown team shows a visible notice and empty list; finding detail renders source facts, deployment scope, lifecycle history; hostile `<script>` fixture renders as visible text only (`&lt;script&gt;` in HTML, no markup execution); reload round-trips state.
- Dev DB `triage_dev` and test DB `triage_test` are isolated local PostgreSQL 18 databases; seeds are idempotent (re-running adds no rows or events).

### Pre-PR 2 scope correction (implemented and verified)

PR 2 reviews must bind to the team/environment scope selected in the list, so the detail view was corrected before case persistence lands:

- `Inventory.fetch_finding/2` accepts `:owner`/`:environment`: displayed placements and related occurrences are scoped, and a finding with no active placement in the selected scope returns `{:error, :out_of_scope}` instead of silently showing every team's context. Unscoped calls keep the previous behaviour.
- The detail LiveView validates ids before touching the database (malformed, zero, negative and out-of-int4-range ids redirect safely), redirects not-found/out-of-scope findings back to the list while preserving team, environment, search and suppressed filters, and displays the selected scope. Both LiveViews now wrap content in `<Layouts.app flash={@flash}>`, so redirect flashes actually render — they were silently dropped in PR 1.
- Verified red → green: the three new regressions failed before the fix (`Ecto.Query.CastError` on malformed ids, unscoped `beta` placements shown, no out-of-scope rejection); after the fix `mix precommit` passed with 29/29 tests (compile `--warnings-as-errors`, format, full suite, flash rendering asserted after redirects). A loopback headless-Chromium CDP smoke at that stage confirmed: alpha-scoped list; alpha-only placements and related occurrences on the detail page; preserved back link and visible selected-scope line; out-of-scope and malformed ids redirecting to the scoped list with a visible flash; hostile `<script>` text still rendered as text.

### Pre-PR 2 input-boundary correction (implemented, test-verified)

Follow-up to the scope correction, driven by three parallel read-only reviews; browser verification is deferred to the independent Astra pass:

- Both LiveViews share an explicit scalar filter-validation contract (`app/lib/triage_web/finding_filters.ex`): recognized fields are `owner`/`environment`/`q`/`suppressed`; only plain trimmed text of at most 120 characters without NUL/control characters is valid; blank stays the intentional All choice; genuinely unrelated query/form metadata is ignored. The id bound was corrected after probing `information_schema` in the local `triage_test`: `findings.id` is `bigint` (not the previously claimed int4), so ids are accepted up to the positive signed 64-bit maximum, with a boundary regression inserting and rendering an id of 9,223,203,685,477,580,7; one past the maximum redirects before any query.
- Malformed inputs render a visible invalid state with no data queried — never a crash, silent coercion, truncation into another owner's name, or unscoped results: bracket query shapes (`owner[]=alpha`, `environment[x]=prod`, `q[]=busybox`, `q[x]=value`), NUL-bearing scopes, map-valued filter fields, a non-map `filters` wrapper and overlong values show `#invalid-filters` (list) or `#invalid-scope` (detail) with no findings/detail rows. Valid blank selectors remain the All choice; unknown but valid scopes stay visibly empty; valid nested `filters` wrappers and realistic flat filter-form events still patch the URL with all four parameters.
- Verified red → green: the new regressions first failed exactly as reviewed (FunctionClauseError crashes on `String.trim/1` of list/map scope values in both views, `Postgrex.Error 22021 (character_not_in_repertoire)` when a NUL scope reached PostgreSQL through the list query, no guard in `Inventory`); after the fix the suite is green.
- `Inventory` now rejects malformed scope values before the database (`ArgumentError` on non-binary values and NUL/control text; the `to_string` coercion and 120-character truncation were removed so a scope can never alias a real name) and `fetch_finding/2` returns `:error` for malformed, zero, negative and out-of-range ids instead of relying on cast errors. Blank scopes still mean "All". No schema change was made to fit the guards.
- Environment regressions use a test-only additive fixture (alpha/staging-cluster-1 active and beta/staging-cluster-1 retired on image_a; seeded beta/prod image_b data untouched): environment-only detail placements and related occurrences scoped independently of owner, combined owner+environment intersection, mismatched valid scopes visibly empty, retired-only placements failing the active gate (`{:error, :out_of_scope}`), direct `fetch_finding/2` behavior and unchanged unscoped history and placements.
- Suppression policy unchanged; a suppressed related occurrence on the detail view is now labelled `suppressed — not mitigation evidence` instead of rendering as an ordinary active finding, covered by a regression.
- `mix precommit` passes: compile `--warnings-as-errors`, format, full suite 69/69 (29 previous + 40 new regressions across the shared contract, LiveView input boundaries, scope flows and context guards). The NUL/PostgreSQL interaction was probed once against the sandboxed local `triage_test` (Postgrex raises 22021), documenting why NUL is rejected before query building.
- Not performed in this pass: browser/CDP verification (Astra runs it independently), live-database or credential access, any change to suppression policy, schema, cluster identity, PR 2 reviews/auth features, git commits or dependencies. Local toolchain: `mise`-pinned Elixir 1.20.4/OTP 27, Homebrew PostgreSQL 18.

### Pre-PR 2 integration of the GLM corrective patches (integrated; independently re-verified — one open failure remains)

Serialized integration of the two completed GLM corrections (backend input-boundary, browser client), covering all six previously verified Astra failures: the true bigint maximum rejected by a typo'd constant; stale detail data surviving a valid→invalid same-view `render_patch`; double `filters` wrapper unscoping; non-map event bodies crashing the channel; leading/trailing control characters silently trimmed; and the missing shipped LiveSocket client.

Corrected facts, as verified in the combined tree:

- **Bigint bound**: `Triage.Inventory` is the single runtime source of truth — `@max_finding_id Integer.pow(2, 63) - 1`, i.e. 9,223,372,036,854,775,807 (the id recorded in the section above as 9,223,203,685,477,580,7 was a transposed-digit typo; no such literal remains in app code or tests). The detail LiveView only parses ids into positive integers and delegates the upper bound; boundary tests insert and render the true 2^63−1 id and reject 2^63 before any query, computing the bound independently of the runtime constant.
- **Stale detail data**: the detail LiveView clears the `:data` assign on invalid same-view transitions, preserving only the last explicitly valid scope for the back link; a valid→invalid→valid journey is covered by regression.
- **Filter contract**: `TriageWeb.FindingFilters` is total for non-map params and event bodies (visible invalid state, no channel crash), rejects nested/double `filters` wrappers and ambiguous wrapper+flat combinations without unscoping, and validates raw UTF-8 and NUL/control bytes *before* trimming so trimmable edge controls can never become a scope or the All choice.
- **Shipped browser client**: the root layout loads three ordered same-origin vendor scripts (`phoenix.js`, `phoenix_html.js`, `phoenix_live_view.js`) regenerated from the mix.lock-pinned Hex dists by `mix assets.setup` (`app/lib/mix/tasks/assets_setup.ex`, wired into `mix setup`/`mix test`/`mix precommit`; vendor directory git-ignored), followed by the real LiveSocket bootstrap in `priv/static/assets/js/app.js` (no placeholder remains, no injected/CDN browser libraries, no dependency changes).

Integration failures found and fixed while serializing the two patches (all were real breakage, no unrelated refactor):

1. The delivered root layout's HEEx comment closed with `%>` instead of `--%>`, which broke compilation of `TriageWeb.Layouts` outright (`phoenix_live_view` 1.2.11 tag-engine parse error). Fixed in `app/lib/triage_web/components/layouts/root.html.heex`.
2. The new assets test asserted script order via `String.index/2`, which does not exist on the pinned Elixir 1.20.4 (verified `UndefinedFunctionError`) — the test could not pass. Replaced with DOM assertions per project guidelines: `LazyHTML.from_fragment/1` + `filter("script[src]")` + `attribute/2` verify the exact ordered same-origin script sources.
3. The assets test ran `async: true` while regenerating the shared vendor files on disk, racing concurrent tests that fetch those files; the case is now synchronous (`async: false`).

Verification record for this pass (commands via `mise exec` inside `app/`): focused `mix test test/triage_web/assets_test.exs` → 7/7; focused correction suite (`inventory_scope_test`, `finding_filters_test`, `finding_live_input_test`, `finding_live_scope_test`) → 55/55; `mix precommit` passed once — compile `--warnings-as-errors`, `deps.unlock --unused`, format (`--check-formatted` clean), `assets.setup`, full suite **91/91, 0 failures**. Asset generation proven from pinned local dists: `mix assets.setup` copies `deps/{phoenix,phoenix_html,phoenix_live_view}/priv/static/*.js` byte-identically into `priv/static/assets/vendor/`, the `mix test` alias regenerates before every run, and `mix help assets.setup` discovers the task after a normal compile. Mechanical consistency checked: routes (`live "/findings"`, `live "/findings/:id"`) match the LiveView modules, `static_paths` serves `/assets`, and the evaluated bound equals 9223372036854775807. No dependency, schema, migration or lockfile changes; no browser/server started.

**Astra re-verification completed: FAIL — final signoff remains OPEN.** The independent pass (agent `8b7bbbf7e95b4363b4e863343da56cbb`) confirmed all six GLM corrections pass end-to-end, but surfaced one further malformed-UTF-8 live-patch protocol boundary owned by the vendored LiveView framework. PR 2 is not started; this tree is **not** ready for PR 2.

Passing evidence (fresh isolated headless Chromium, only same-origin shipped scripts, sandboxed `triage_test` server, no client-library injection): read-only `mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix assets.setup`, `phx.routes` all clean; serialized integration precommit 91/91, plus independently re-run seven focused files 86/86 (`inventory_test`, `inventory_scope_test`, `finding_filters_test`, `finding_live_test`, `finding_live_input_test`, `finding_live_scope_test`, `assets_test`); 282 browser assertions over the real WebSocket and all DOM filter controls/patches/rows — restored four-field scope, detail/back/reload, unknown/missing/overflow/out-of-scope redirects, test-only environment discrimination/AND scope/inactive gate, related/unscoped/history semantics, escaped script fixture, and nested/scalar/bool/list bad channel events with valid recovery. SQL independently confirmed the true bigint maximum 9223372036854775807 fetched/rendered and 2^63 rejected with zero query telemetry; 297 context C0/DEL combinations rejected; fresh invalid-UTF-8 HTTP URLs return 400 with no finding data. Vendor dir regenerated from absent, byte-identical to pinned deps; a fresh `/tmp` app with no application beams/vendors ran `assets.setup` (compiled 22 files). All sandbox rows rolled back; own processes/listeners/temp files removed; 56 app-file hashes plus this roadmap's hash unchanged; no external or live systems.

**Remaining open failure (framework-owned):** a malformed-UTF-8 query parameter injected through the `live_patch` channel event bypasses every app-level guard. `phoenix_live_view` channel.ex `handle_info` for `live_patch` calls `Route.live_link_info!` **before** `Utils.call_handle_params!`, and route.ex `live_link_info_without_checks` decodes the query via `Plug.Conn.Query.decode`, which raises `Plug.Conn.InvalidQueryError` (invalid UTF-8 byte 255) before any app callback — so `TriageWeb.FindingFilters` cannot intercept it. Minimal reproducer (existing finding id placeholder): from a valid scoped detail `/findings/<existing-id>?environment=prod-cluster-1&owner=alpha&q=busybox&suppressed=1`, call the shipped client's `window.liveSocket.pushHistoryPatch(new Event("click"), location.origin + "/findings/<existing-id>?owner=%FF", "push", null)` — the channel raises, no `#invalid-scope` state is shown, and the previous valid-scope data stays visible during the connection interruption/rejoin; a direct `live_patch` push on the existing channel with the same malformed URI fails/times out identically. `pushHistoryPatch` is `@internal` (live_socket.ts), history commits only after a successful reply (view.ts), and the cancellable `phx:before-navigate` event does **not** fire for direct internal calls or forged channel pushes, so a browser-only guard would not close this reproducer. No vendored framework patch, custom protocol wrapper, validation change, dependency upgrade or monkeypatch has been authorized or implemented; none is claimed. This is a malformed-input/error-handling boundary, **not** an authorization leak; there is no evidence any broader rows were fetched.

**Next step:** a scoped decision on a framework-level mitigation or upstream fix (guarding/normalizing live_patch URL decoding in `phoenix_live_view`), not another rerun of the unchanged passing app tests.

### Pre-PR 2 socket serializer guard for malformed-query live_patch URLs (implemented; final Astra signoff PASS)

Closes the framework-owned open failure recorded above with an approved application-owned serializer guard — no vendored framework patch, monkeypatch, protocol change or dependency change.

- **Module**: `app/lib/triage_web/socket_serializer.ex` — `TriageWeb.SocketSerializer`, `@behaviour Phoenix.Socket.Serializer`, wrapping `Phoenix.Socket.V2.JSONSerializer`. `encode!/1` and `fastlane!/1` delegate unchanged. `decode!/2` delegates, then for any map payload carrying a binary `"url"` (covers both `live_patch` and `phx_join`, whose `url` flows through the same route decoding) attempts `Plug.Conn.Query.decode/1` on the parsed URI query and, on **any** raise (broad rescue — any query Plug itself would crash on, not just invalid UTF-8; predicate chosen because `URI.decode_www_form/1` silently accepts `%FF` while `Plug.Conn.Query.decode/1` raises `Plug.Conn.InvalidQueryError` before any app `handle_params`), replaces **only** the query with `filters=malformed`, preserving scheme/host/port/path/fragment. Everything else — non-map payloads (`{:binary, data}`), non-binary `url`, no `url`, nil query — passes through byte-identical, and the module never raises for input V2 itself accepted.
- **Contract reuse, no new UI**: the rewritten `filters=malformed` query is one `Plug.Conn.Query.decode/1` accepts and `TriageWeb.FindingFilters.parse/1` marks invalid (reserved wrapper key), so the list renders its existing `#invalid-filters` state with zero rows and the detail its `#invalid-scope` state with data cleared — exactly the visible-invalid contract already covered by regressions.
- **Wiring**: `TriageWeb.Endpoint` now sets `serializer: [{Phoenix.Socket.V1.JSONSerializer, "~> 1.0.0"}, {TriageWeb.SocketSerializer, "~> 2.0.0"}]` for **both** `websocket` and `longpoll`. The V1 entry was kept (design-preferred): LiveView's shipped JS hardcodes vsn `"2.0.0"` (`phoenix` JS `DEFAULT_VSN = "2.0.0"`, never overridden in `live_socket.ts`), so no supported client of this socket negotiates V1, but dropping it required verified evidence that LiveView channels hard-require v2 `join_ref`, which was not established. Known residual, stated honestly at the time: a hostile scripted client forcing vsn 1.0.0 would bypass the wrapper (fresh HTTP with the same URL still returns 400); no shipped browser client can. **Update (approved residual fix)**: the V1 entry has since been removed — both `websocket` and `longpoll` now list only `[{TriageWeb.SocketSerializer, "~> 2.0.0"}]`; see the Astra verification and V1-removal bullets below.
- **Astra verification (agent `c40dc010c69142679412b9e33611b4d0`)**: the V2 guard is browser-verified working — the shipped V2 client negotiating vsn "2.0.0" gets the visible invalid state for the `?owner=%FF` live_patch and phx_join URLs with no stale data and no connection loss (109 browser assertions, 99 focused tests). Astra then mounted the LiveView detail channel over a V1-negotiated WebSocket (vsn=1.0.0) and re-sent the `%FF` live_patch: the channel crashed with the ORIGINAL `Plug.Conn.InvalidQueryError` (route.ex:95 -> channel.ex:162) because the V1 path bypasses the guard — the documented residual was real and reachable; V1 LiveView mounting does NOT hard-require V2.
- **V1 removal (the approved fix)**: the `{Phoenix.Socket.V1.JSONSerializer, "~> 1.0.0"}` entry was removed from both transport serializer lists, leaving only the guard. Negotiation-refusal evidence: `Phoenix.Socket.__connect__/negotiate_serializer` (`app/deps/phoenix/lib/phoenix/socket.ex` ~lines 498-527 and 608-636) — if the client's requested vsn matches no serializer requirement, it logs a warning ("does not match server's version requirements") and returns `:error`: the transport refuses the connection cleanly, no channel is created, no crash, no data. LiveView's shipped JS hardcodes vsn "2.0.0", so no supported client is affected.
- **Tests**: `app/test/triage_web/socket_serializer_test.exs` (13, real V2 JSON frames with `opcode: :text` and a real binary push frame with `opcode: :binary`): live_patch/phx_join malformed-query rewrites with scheme/host/port/path/fragment preserved; exact pass-through of valid urls, messages without `url`, non-binary `url` and binary frames; `encode!/1`/`fastlane!/1` delegation round-trips; `TriageWeb.Endpoint.__sockets__/0` wiring assertions for both transports (now asserting the serializer list is exactly `[{TriageWeb.SocketSerializer, "~> 2.0.0"}]` — V1 no longer present); and the chain proof that `Plug.Conn.Query.decode("filters=malformed")` feeds `FindingFilters.parse/1` into the invalid state. No `Process.sleep`, plain assertions.
- **Verification record** (`mise exec` inside `app/`): focused new file 13/13; the seven relevant existing files re-run 86/86; `mix precommit` once — compile `--warnings-as-errors`, `deps.unlock --unused`, format clean, `assets.setup`, full suite **104/104, 0 failures** (91 previous + 13 new). No dependency/lockfile/schema changes; no vendored `deps/` edits; no browser/server started. **Post-V1-removal rerun** (serialized, `mise exec` inside `app/`): focused `socket_serializer_test.exs` 13/13; the seven focused files 86/86 (`inventory_test`, `inventory_scope_test`, `finding_filters_test`, `live/finding_live_test`, `finding_live_input_test`, `finding_live_scope_test`, `assets_test`); full `mix precommit` once — **104/104, 0 failures**.
- **Known behavior (not a defect)**: with the guard, the channel replies `ok`, so the shipped client commits its own pending link and the hostile crafted string may remain in the browser URL bar while the server renders the visible invalid state with no data; a fresh reload of that URL still returns HTTP 400. Real user flows never produce such URLs. Astra additionally observed that a bare `channel.push('live_patch')` reply is only rendered when the client consumes the reply — normal Phoenix channel behavior, not a defect. **Final independent Astra re-verification — PASS** (agent `0df01d54dd46408fbd5ce6832a9a9195`): the V1-removal correction satisfies the narrow acceptance checks below; earlier FAIL findings remain historical evidence, not erased.
- **Independent test command** (inside `app/`, `pi.bash(timeout=180, settle=True)`): `mise exec -- mix test test/triage/inventory_test.exs test/triage/inventory_scope_test.exs test/triage_web/finding_filters_test.exs test/triage_web/live/finding_live_test.exs test/triage_web/live/finding_live_input_test.exs test/triage_web/live/finding_live_scope_test.exs test/triage_web/assets_test.exs test/triage_web/socket_serializer_test.exs` — **99 passed, 0 failures**, seed `419495` (11 + 13 + 21 + 13 + 12 + 9 + 7 + 13); tool `ok=true`, success response omits `exitCode`. Exact serializer-list equality is asserted for both websocket and longpoll. No precommit, formatter, dependency or lockfile task was run; the test alias copied its normal same-origin assets, byte-identical afterward.
- **Independent browser evidence**: **60 passing browser assertions**, fresh headless Chrome with temporary profile `/tmp/astra-final-bo5kPA/chrome-profile`, CDP port `19473`, private harness port `19847`, and own server `http://localhost:54558` bound only to `127.0.0.1`. Server command inside `app/`: `MIX_ENV=test mise exec -- mix run --no-start /tmp/astra-final-bo5kPA/server.exs`; the temporary script asserted `triage_test`, used a shared SQL Sandbox transaction with a bounded `1_200_000` ms lease, and inserted five uniquely owned fixtures. Browser commands used `CDP_REPL_PORT=19847 CDP_REPL_LOG=/tmp/astra-final-bo5kPA/cdp.log CDP_RECORD=0 BROWSER_HARNESS_JS_HOME=/tmp/astra-final-bo5kPA/harness browser-harness-js '<CDP probe>'`; only the four shipped same-origin JS files loaded. A native WebSocket to `/live/websocket?vsn=1.0.0` (with the own-page CSRF parameter), with a V1 `phx_join` attempted for `/findings/10113?owner=%FF`, never opened: handshake **403**, browser close **1006**, one error, zero incoming messages and zero sent channel frames. The server logged `The client's requested transport version "1.0.0" does not match server's version requirements of [{TriageWeb.SocketSerializer, "~> 2.0.0"}]`; refusal precedes channel creation, so no LiveView channel or finding data was exposed. The shipped V2 connection stayed connected and the server identified `TriageWeb.SocketSerializer`.
- **V2 recovery and DOM regression**: from `/findings/10113?environment=astra-prod&owner=astra-final-a&q=astra-busybox&suppressed=1`, `window.liveSocket.pushHistoryPatch(new MouseEvent('click'), '/findings/10113?owner=%FF', 'push', null)` rendered visible `#invalid-scope`, removed placements/related-occurrence/source-detail sections and the prior CVE/fixture text, preserved the scoped back link, and kept `isConnected()` true. A valid history patch restored the finding. The same LiveView object, WebSocket object and channel join reference survived both patches, with no error/close callbacks, reconnect or `phx_join` frames. Shipped Team, Environment, Search and Include suppressed controls patched the URL and changed row counts **4 → 3 → 2 → 1 → 2**; list → detail → back → reload restored all four controls, the full query string and both expected rows. Fresh cache-disabled, cookie-omitting HTTP requests for `/findings?owner=%FF` and `/findings/10113?owner=%FF` each returned **400**, body exactly `Bad Request`, without finding data.
- **Harness qualifications and integrity**: initial use of `127.0.0.1` as the browser hostname hit the configured `localhost` origin check; the harness URL was corrected without changing app configuration. A DOM-valued readiness predicate was made boolean, and an initial queued-client join wait (whose timer cannot start before transport open) was replaced with the bounded native-WebSocket refusal probe. An overbroad network assertion flagged the shipped CSS `data:image/svg+xml` noise image (`assets/default.css:2319`); the corrected network-origin check passed with zero external network requests. These were harness corrections, not app acceptance failures; the 60 passing assertions exclude that false-positive assertion. SHA-256 manifests confirmed all `app/deps/`, application source/tests/config/assets, `mix.exs` and `mix.lock` unchanged. No real credentials, external systems, project `.pi` contents or `tmp/cve-collector` were accessed. Sandbox rollback was checked with zero owned images remaining; own server, Chrome and harness stopped, and ports `54558`, `19473`, `19847` were confirmed unbound. No query-decoder, channel-termination or sandbox-ownership exceptions were logged. Temporary verification files/profile are removed during final cleanup.
- **Next step**: the pre-PR 2 correction has final signoff **PASS**. **PR 2 is not started**; its work and acceptance remain separate. Earlier FAIL records above are retained unchanged as history.

### PR 2 — scoped local cases, evidence and human review: implemented, integrated and fully verified — final Astra closeout PASS (2026-09-10)

PR 2 was implemented per the binding contract `app/PR2_PLAN.md` by three parallel GLM writers (A: domain/context/schemas/migration/domain tests; B: router + `CaseLive.Show`, finding-detail entry/banners, README, LiveView tests; C: independent `cases_integrity_test.exs`), followed by the serialized GLM integration pass that fixed only actual integration failures. Contract invariants were preserved: every fix addressed a cause; no rejection trigger, invariant or failing test was weakened or bypassed.

**What was integrated and fixed** (details and the full command/failure record live in `app/PR2_PLAN.md` → "Integration record"): the missing `insert_snapshot!/4` helper was implemented and `captured_at` precision fixed; invalid `has_many` associations were removed from `ReviewCase`; the migration's `execute(up:, down:)` keyword form was converted to the reversible `execute/2` arity required by ecto_sql 3.14; handoff-mangled escape syntax was repaired in both new test files; `refresh_evidence` now advances `current_snapshot_id` together with the revision bump (it previously never moved the pointer, causing a version-unique violation on the next refresh); the final `review_saved` audit append now rolls the review and revision back and returns a controlled error instead of raising; concurrency-task sandbox gating, savepoint-scoped append-only-refusal assertions and B's event-count expectations (the contract specifies exactly ONE opening event) were corrected; duplicate LiveView DOM ids were removed and the captured scanner description is now rendered (hostile text stays literal).

**Verification totals** (via `mise exec` inside `app/`): focused PR2 suite `mix test test/triage/cases_test.exs test/triage/cases_integrity_test.exs test/triage_web/live/case_live_test.exs` → **48/48 passed**; final `mix precommit` → compile `--warnings-as-errors`, `deps.unlock --unused`, `format` (`--check-formatted` clean), `assets.setup`, full suite **152 passed, 0 failures** (104 PR1 baseline + 48 new PR2 tests). Migration probe on an owned disposable database (`MIX_ENV=test MIX_TEST_PARTITION=_pr2probe`): create → migrate → `ecto.rollback -n 1` → migrate → drop, all clean; the old inventory schema was never altered.

**Mechanical confirmations**: routes `live "/findings"`, `live "/findings/:id"` and the new `live "/cases/:id"` (browser scope) are registered; `TriageWeb.SocketSerializer` and `TriageWeb.Endpoint` are untouched and still V2-only on both websocket and longpoll; migration `20260101000000_create_inventory.exs` and `lib/triage/inventory.ex` are untouched; the new `Triage.Cases` context performs no writes to any source (inventory) table — only `review_cases`, `review_evidence_snapshots`, `review_reviews`, `review_case_events`.

**Incident, remediated**: one early migration probe omitted `MIX_ENV=test`, so `MIX_TEST_PARTITION` did not apply and `mix ecto.drop` removed the dev database `triage_dev` (synthetic seeded data only). It was immediately recreated, migrated and re-seeded (`summary_counts()` → `%{open: 6, suppressed: 1}`, the deterministic PR1 state); the dev app remains stopped, as requested.

**Astra verification of the integrated PR2 tree: FAIL — four verified defects** (agent `ac98987ed17a426d93674d0ffc1e96d5`, real browser + real server; all reproduced, all missed by the 152/152 app suites). A serialized corrective writer then fixed exactly these four at their causes, with durable regressions and no weakened invariants:

1. **Cross-case current-snapshot pointer accepted at the database level** — the single-column FK on `review_cases.current_snapshot_id` only checked snapshot existence, so repointing a case at another case's snapshot committed and `get_case/1` returned `snapshot: nil`. Fix in `app/priv/repo/migrations/20260910093411_create_review_cases.exs:70-90` (still-unreleased migration, edited in place): `current_snapshot_id` is a plain bigint plus a COMPOSITE foreign key `(current_snapshot_id, id) -> review_evidence_snapshots (id, case_id)`; down drops it. Regression in `cases_integrity_test.exs` (cross-case UPDATE raises the FK violation inside a rolled-back transaction; same-case pointer moves stay legal).
2. **Mismatched query scope escaped via back navigation** — `/cases/:id?owner=beta&environment=...` on an alpha case preserved beta on the back link. Fix in `app/lib/triage_web/live/case_live/show.ex:359-391` + `#scope-mismatch` (line 712): the back link is always built from the case's saved owner/environment; `q`/`suppressed` preserved only on an exact URL-scope match; any mismatch renders a visible `#scope-mismatch` notice and the back link carries the case scope alone. Regressions in `case_live_test.exs` decode the back-link query: all four filters on match, only the case scope on owner/environment mismatch.
3. **Malformed review attrs raised instead of controlled errors** — `change_review([])`/`submit_review(..., [])` raised `Ecto.CastError`; keyword lists and atom/mixed-key maps escaped validation. Fix in `app/lib/triage/cases.ex:145-162, 626-634`: only string-keyed maps are cast; any other shape is `{:error, :invalid_request}` from `submit_review` and, for `change_review`, the documented changeset shape marked invalid with a form-level error (decision documented in code). Regressions in `cases_test.exs` for every malformed shape, plus two existing assertions updated coherently with the corrected contract.
4. **NUL-containing idempotency token crashed the LiveView** — a forged hidden `meta[idempotency_token]='bad\0token'` reached the insert and raised Postgrex 22021, killing the GenServer. Fix in `app/lib/triage/cases.ex:612-619` and `app/lib/triage_web/live/case_live/show.ex:430-437`: strict `Ecto.UUID.cast/1` validation at BOTH boundaries before any write (the server only issues `Ecto.UUID.generate/0`); the LiveView renders the visible `#invalid-request` with the draft kept, and the context returns `{:error, :invalid_request}` before any database access. Regressions: direct context calls (`bad\0token`, empty, nil, integer, overlong, truncated, invalid UTF-8) and a browser-equivalent LiveView `render_submit` per invalid token — visible error, no crash, no rows.

**Corrective-pass verification record** (via `mise exec` inside `app/`; full detail in `app/PR2_PLAN.md` → "Corrective record"): `triage_test` recreated with `MIX_ENV=test mix ecto.reset` (fresh migrate of the edited migration); focused PR2 suite `mix test test/triage/cases_test.exs test/triage/cases_integrity_test.exs test/triage_web/live/case_live_test.exs` → first run 52/53 (one new-test assertion used the wrong `errors_on/1` shape; the assertion was fixed, not the code) → **53/53**; migration reversibility re-probed on the disposable database `triage_test_defect1probe` (create → migrate → `ecto.rollback -n 1` exit 0 with the composite constraint cleanly dropped → migrate exit 0 → drop); `mix compile --warnings-as-errors` clean; final `mix precommit` → **157 passed, 0 failures** (104 PR1 baseline + 53 PR2 tests), `mix format --check-formatted` clean. **Database actions**: `triage_test` reset as above; `triage_dev` had the old migration version applied (0 review rows), so its constraint was swapped in place with SQL to the identical composite FK (`DROP review_cases_current_snapshot_id_fkey`, `ADD review_cases_current_snapshot_fkey FOREIGN KEY (current_snapshot_id, id) REFERENCES review_evidence_snapshots (id, case_id) ON DELETE RESTRICT`) — no data rows touched, inventory rows verified intact, dev schema now matches a fresh migrate. The dev app remains STOPPED (nothing bound to port 4000).

**Closeout (2026-09-10) — final independent Astra verification PASS** (agent `f0c88272df214c9f95a49d04162464c8`; full detail and the failure/fix history live in `app/PR2_PLAN.md` → "Final verification and closeout (2026-09-10)"). Sequence and combined evidence:

- **GLM runtime verification PASS** (agent `aa94682caa934f50ab350c8f9569ea0b`): 53 focused / 157 full precommit + 25 direct DB probes (composite FKs, six immutability triggers, rollback, real two-connection concurrency, idempotency, stale, retired-scope, noninterference); own DB dropped, no app changes.
- **Two new navigation defects, fixed** (GLM agent `8379b0982cdc4ab3afd9010798dd8ce4`): static review found that an invalid query kept a wrong back link and that invalid/not-found case ids left stale identity/snapshot/form/bindings/streams, so a queued save/reload/confirmed refresh could write or reveal a previous case. Three FAILING regressions added first; only `CaseLive.Show` + `case_live_test.exs` changed (invalid query resets backlink to `/findings`; `invalidate_case` clears old identity/snapshot/form/bindings/streams; valid draft-conflict behavior preserved). 19 CaseLive tests / 160 full precommit PASS.
- **Serialized Astra browser pass** (agent `b66da4ff32d3443a8334672344b82a5d`): **31 browser checks PASS**, but found struct attrs `Case.change_review(%URI{})` raising `Protocol.UndefinedError`; Astra stopped before recapture/restart and recorded the FAIL honestly — retained above as failure history. It also mechanically validated the 72-file manifest: only the guard line + added regression changed (reversing them reproduces the old hashes); UI/assets/guarded V2 unchanged.
- **Struct-attrs correction** (GLM agent `facf5ab138c44b94b55c3f1250693b5e`): one-line guard `is_map(attrs) and not is_struct(attrs)` in `lib/triage/cases.ex` + one regression in `cases_test.exs` (6 struct shapes, both APIs), failure witnessed first, then 23 targeted / **161 FULL PRECOMMIT PASS** (104 baseline + 57 PR2, four new tests this closeout), format check clean. ExUnit tests attributed to GLM; Astra audited raw logs/manifests and ran independent probes, did NOT rerun the full suite. No UI/schema changes; own DB dropped, dev/test unchanged.
- **Final Astra closeout FINAL PASS**: **14 NEW browser checks** passed, all using the 4 actual shipped same-origin scripts, and **30 independent public-API calls** (valid/invalid/empty shapes), made as direct Elixir context probes, also passed. Recapture end-to-end: own-source fact changed → stale read-only evidence/draft blocked → first click no writes → confirm appends exactly 1 snapshot + 1 event + 1 revision, old snapshot/review unchanged, inspectable and needs-revalidation-labelled; unchanged recapture zero churn; explicit new review valid. **Real restart proof**: old BEAM (80858) gone + port unbound, then new server (81613), same owned DB `triage_test_astra_SWlCVS` (port 43291), no reseed; all 8 tables byte-identical; 2 cases / 3 snapshots / 2 reviews / 5 events; DB proof SHA256 `fda60aa1f61662c40a9c8ff6b746de35ac966c30b77891af544724736bdf196a`. Zero external requests/unexpected JS errors/`phx_error`; 9 expected connection refusals during downtime. **Cleanup proof**: all owned DB/Chrome/profile/daemon/PIDs removed, ports 4000/4002/43291-43293 free, preexisting daemon untouched, dev/shared test rows + schema unchanged; all 72 source/docs files unchanged by Astra (no final-signoff editing by Astra itself).

**Qualifications**: temporary `/tmp` and `/var/folders` evidence paths are OS-cleanable raw artifacts; this roadmap and `app/PR2_PLAN.md` are the durable compact verification record. No commits/GitHub PRs created. Technical verification complete; auth/shared deployment still blocked by design. The earlier `ac98987ed17a426d93674d0ffc1e96d5` FAIL and the `b66da4ff...` browser-pass/struct-FAIL records above are retained unchanged as history (including the accidental dev-DB recreation incident, remediated).

**PR 3 — read-only `/cases` Review Queue: IMPLEMENTED AND VERIFIED (final independent Astra signoff PASS, 2026-09-10).** Delivered per the prepared contract: team/environment filters, bounded keyset pagination (25), awaiting-review / needs-revalidation / current-review labels, "Current review" requiring `review.snapshot_id == case.current_snapshot_id` AND an unchanged current source; no automatic cases, assignments, auth, AI, jobs or exception writes. Final evidence: **31/31 fresh Chrome browser assertions** — rows -> empty -> malformed event -> rows -> empty on one LiveView, empty computed-visible outside the stream, canonical filters/saved-scope links/detail/back/hard-reload/Browser Back/nil-snapshot safety, second-tab review -> Reload, own source change -> frozen identity + stale, two-click recapture keeping the old review needs-revalidation — plus five readonly purity phases with all 8 table counts/full-row hashes identical, 0 unexpected JS/channel/request failures, 0 external page/WebSocket requests and four actual shipped scripts byte-compared (Astra `0c4be006927148158fd8a6c659ed3503`, `/tmp/pr3astrasign_20260910_160903/`, temporary). Retained: **276 API assertions** with 4 (one row) / 4 (25 rows) / 2 (options) SELECT budget (Astra `4b41989bf87048aeb4fdb1fcd61123bd`) and final GLM `mix precommit` **236 passed** (161 PR 2 baseline + 75 PR 3; agent `79f594d9e5cc4d6eafc622908689b67a`, raw logs Astra-audited, not rerun), plus 28 earlier passing browser assertions retained from the first Astra pass (not additive unique counts). Final source manifest `01c089b64ec3f265e62be8577c5e67014aa870cfb66680d0d13df523c06845f3`; only the index LiveView and its test differ from the 276-passing tree and reverse exactly. Cleanup verified: owned DB/server PID 17807/Chrome 17808/daemon 18001/profiles removed, ports 4000/4002/43183/19283/19883 free, preexisting daemon 27631:9876 untouched, dev/shared rows and normalized schemas unchanged, app left stopped. Durable failure/fix history, hash continuity and the acceptance-ledger closeout live in `app/PR3_PLAN.md` → "Final implementation and verification record". No auth/shared deployment, news, AI, collection, exception writes, migration or dependency changes; no commits/external PRs. The local What's New view remains deferred, after the queue, per the Later slices paragraph.
**PR 4 — local read-only What's New (`/whats-new`): IMPLEMENTED; independent API/browser/telemetry and wave-local protection checks PASS. Original historical-baseline proof remains BLOCKED.** Delivered per `app/PR4_PLAN.md`: `Triage.Activity.list_events/1` and `event_filter_options/0`, `TriageWeb.ActivityFilters`, and `TriageWeb.WhatsNewLive` on a `/whats-new` route with primary navigation and a home entry link; read-only inventory-wide `finding_events` (newest recorded first, fixed 25-row keyset pages, `id DESC`), truthful lifecycle labels, same-placement owner/environment scoping with inactive-inclusive options, scope-preserving detail links gated on an active matching placement, and visible local/synthetic coverage warnings. No writes, schema/index/migration/dependency changes, or protected PR1–3 path changes.

Verification and fixes: the 17 Activity failures were caused by `app/mix.exs` chaining `run priv/repo/seeds.exs` into `ecto.setup`, so `MIX_ENV=test mix ecto.reset` seeded `triage_test`; the Ecto SQL sandbox rolls back test writes but not pre-existing seeded rows. Fixed by removing seeding from `ecto.setup`, adding an `ecto.seed` alias, setting `ecto.reset = [ecto.drop, ecto.setup, ecto.seed]`, making the `test` alias create and migrate without seeding, adding `reset_inventory!/0` (`TRUNCATE TABLE images, findings, finding_events, image_placements CASCADE`) in `app/test/support/data_case.ex` and calling it in the `setup` of `app/test/triage/activity_test.exs` and `app/test/triage_web/live/whats_new_live_test.exs`, plus the new guard `app/test/triage/test_environment_test.exs`. Checks: `mix test activity_test.exs test_environment_test.exs whats_new_live_test.exs --seed 0` = **40 passed**; `mix precommit` = **292 passed** (not the older 236 baseline) on the still-seeded shared `triage_test`; `mix format --check-formatted` exit 0; `activity_test.exs` = **27 passed** on the clean partition DB `triage_test_pr4fix1`. Independent `openai-codex/gpt-6-astra` verification confirmed the `mix.exs` aliases, `reset_inventory!/0`, both setup call sites, `Triage.Activity`/`ActivityFilters` existence, the `/whats-new` route and primary navigation, and independently re-ran the targeted command (40 passed); Astra did not run the full suite and the 292 figure was produced by the coordinator. Durable detail and the acceptance-ledger closeout live in `app/PR4_PLAN.md`. **Independent PR4 browser/telemetry/full-row evidence (2026-09-10, from the remaining-review report):** a real headless Chrome journey passed **29/29** final assertions (home/nav -> What's New -> owner/environment filters -> 25/25/5 disjoint rows over 55 events -> suppressed/resolved inclusion -> hard reload -> Newest -> scoped detail -> Back -> inactive-only honest empty -> crossed-placement empty; hostile note rendered as text). Telemetry measured **2 SELECTs at one row, 2 at 25 rows, 2 for options and 0 for eight malformed requests**, with all eight table hashes unchanged. Readonly before/after full-row and normalized-schema hashes for `triage_dev` and shared `triage_test` were identical for that wave, and the 177-file protected source manifest was byte-identical. **Still blocked:** a historical pre-PR4 protected-path baseline proof — the original baseline was never captured, so invariance before that review began remains unproven. This supersedes the earlier statement that the local What's New view remains deferred; the historical PR 3 record above is preserved verbatim.

### PR 1 acceptance ledger

- [x] Scaffold a conventional Phoenix LiveView application in `app/` with Ecto/PostgreSQL, a verified supported/pinned Elixir/OTP toolchain and dependency lockfile. Retain ordinary Phoenix conventions; no umbrella, separate SPA or custom workflow engine.
- [x] Provide isolated local development and test databases, migrations and deterministic synthetic seeds. Bind the unauthenticated demo to loopback and visibly label it as synthetic/read-only. No production URLs, credentials, legacy database access or external source/model calls. PostgreSQL is the selected store; do not silently substitute SQLite.
- [x] Implement an `Inventory` context and LiveView finding list/detail using database-backed fixtures for multiple teams and explicit environment/cluster scope. Include a shared CVE/image across team placements, distinct affected packages, suppressed findings, reappearance history and unknown context. Preserve digest-based identity; do not conflate a CVE with a scoped finding or treat suppression/absence as verified remediation.
- [x] Support team filtering with URL-restorable navigation and a detail view that preserves the selected scope. Handle empty results, invalid filters/IDs and unknown fields safely. Render third-party text safely. Team filtering is not authentication or authorization; shared deployment remains blocked pending SSO/roles.
- [x] Add focused ExUnit/Ecto and LiveView tests for fixture idempotence, team/environment boundaries, list/detail navigation, suppressed/unknown labels and safe text rendering. Mechanically check routes, Repo/application registration and database/endpoint configuration.
- [x] Run formatting, compilation, targeted tests and a real-browser list/filter/detail/reload smoke journey against disposable local data. Inspect nonzero results and fix only their causes. Record exact results and any environmental blockers; compilation alone is not acceptance.
- [x] Document reproducible setup/start/test commands in `app/README.md`, ignore generated dependencies/builds/local database artifacts, reconcile outdated roadmap choices and mark this item complete only when supported by verification. Leave `tmp/cve-collector/` and unrelated harness/user changes untouched. Do not create a git commit or external PR unless asked.

### Later slices

PR 2 adds immutable evidence, durable human review and append-only audit history with atomic writes and stale-version conflicts. PR 3 is now the read-only `/cases` Review Queue (team/environment filters, bounded pagination, review/evidence status badges) per the prepared draft plan `app/PR3_PLAN.md` — it supersedes this paragraph's older My Work/news PR 3 numbering, which remains accurate only as historical context below. The daily My Work/What's New workflow with correctly labelled lifecycle timers comes after the queue, not as part of PR 3. PR 4 delivered the read-only local What's New lifecycle feed (`/whats-new`) per `app/PR4_PLAN.md`; its 29/29 independent browser journey, query telemetry and wave-local protected hashes are recorded there. Those protected sources still match the verified manifest in the final PR5 recheck; the missing original historical baseline remains blocked.

**PR 5 — approved historical snapshot import: implemented, test-verified (2026-09-10).** `Triage.Import` provides strict versioned snapshot parsing with per-problem JSON paths, explicit document/record/string budgets, a read-only reconciliation (`create`/`update`/`unchanged`/`existing`) with a fixed SELECT budget, and an all-or-nothing transactional apply that creates/updates images, placements, findings and lifecycle events only — never review cases, evidence snapshots, reviews or case events — and never infers resolution from an omitted field. `mix triage.import --file <path>` is dry-run by default and requires `--apply` to write. A scoped remaining-review fix pass (2026-09-10) added boundary re-validation of normalized snapshots, a transaction-scoped `pg_advisory_xact_lock` before every re-read (with a real separate-connection concurrency regression), rejection of provable `last_seen`/`first_seen` regressions with indexed paths (without treating `generated_at` as authoritative ordering), shared resolution warnings between dry run and apply, UI-matching owner/environment scope limits, consistent blank-optional normalization, and byte/record/work budgets with linear collection construction. Details, acceptance ledger, red/green evidence and command counts are in `app/PR5_PLAN.md`. Independent final affected-path recheck (2026-09-10): **PASS for the bounded synthetic/local contract**, with concrete residual normalized-map/whitespace/stale-preview defects fixed and nine regression tests added. The previously unconditional real-commit/TRUNCATE concurrency tests now skip ordinary runs and require exact owned-empty-DB opt-in; sentinel probes proved default, mismatched and populated-DB invocations preserve all eight row hashes. ONE fresh full `mix precommit` **337 passed**, six direct multi-connection/invalid-input/warning/atomicity/preservation probes passed, and seven actual CLI runs covered dry/apply/repeat plus controlled failures. Dev/shared rows and schemas remained identical, and the sole owned DB was dropped with zero connections. Prior browser evidence is retained, not newly rerun. Current details and final source-hash artifact locations: `app/PR5_PLAN.md` and `/tmp/triage-import-final-recheck.md`. **Still BLOCKED:** missing original historical baseline and unavailable real approved export; no legacy credentials/data accessed, no commits.

**PR 6 — offline collection adapter: implemented, test-verified (2026-09-10).**
`Triage.Collection` is a read-only, disabled-by-default adapter over the security
GraphQL source, per `app/PR6_PLAN.md`. It offers a two-stage owner->images->
image(id, engine) crawl, digest identity with aggregated owners/placements and an
explicit environment, claimed-vs-raw (open + suppressed, pre-dedupe)
reconciliation (positive-claimed/empty is a failure, other drift an explicit
incomplete warning), terminal 3xx/401/403/GraphQL handling with retries and
redirects disabled, streamed response-byte bounds, and a normalized report that
never synthesizes lifecycle history. It performs no inventory writes and
references no `Triage.Repo`; scheduling is deferred to PR7. `Req` was added as a
dependency and the existing `Bandit` serves the fake source in tests. Verified
on the owned partition `triage_test_pr6_c9a4`: focused collection tests **37
passed**, direct probes passed, and ONE `mix precommit` **372 passed, 2 skipped**
(the 2 skips are the honest import-concurrency opt-in). Protected `triage_dev`
and shared `triage_test` full-row and schema hashes were unchanged. **Blocked/
unmet:** the requested 3-way `neuralwatt/deepseek-v4.1-flash` leaf-writer fan-out
could not run (Fabric depth limit 4 with re-armed prewalk); the coordinator
implemented the frozen contract directly with no model substitution. Independent
Astra verification is pending. **Still BLOCKED:** historical original-baseline
proof and an approved real export.

Subsequent isolated changes address source authentication/collection, shared SSO/roles, and human-authorized time-bound exceptions with verified upstream scope and synchronization. Oban and Req are introduced with the jobs/integrations that require them.

---

## Historical planning context

The source-backed proposal below is retained for integration provenance and safety constraints. Its earlier language, database, directory and first-PR descriptions are superseded by the current implementation decision above; it is not evidence that the successor is implemented. See [the original architecture plan](./architecture%283%29.md) for the historical pipeline-first design.

Reviewed `/Users/adam2/projects/cve-collector` and all of `architecture(3).md`. Four independent `zro/glm-5.3` reviewers covered architecture/delivery, web workflows, data/integration, and security/operations; their findings were reconciled against source code. This was static inspection only: no application/test execution, credential-file access, live database inspection, production API calls, or model calls using CVE database contents. Source citations below establish implemented behavior, not current deployment health or passing tests.

## 1. Recommendation in one paragraph

**Build a usable CVE evidence-and-review web application before building an autonomous remediation system.** Use the existing TypeScript collector and web UI as the behavioral baseline, preserve their hard-won integration safeguards, and add durable cases, evidence snapshots, human decisions, notes, and history. Keep the old app operational while building an isolated successor in `triage`. Start locally with SQLite and the existing HTML/CSS/JavaScript approach. Add authenticated team access, optional AI proposal ingestion, and finally narrowly constrained remediation in separate, demonstrably safe steps. Do not make Go, React, PostgreSQL, AKS, Azure Boards, or a model service prerequisites for the first useful screen.

If Go is an organizational requirement, keep the same milestones but use the Go alternative in section 5. Do not rewrite the GraphQL collector and replace the entire frontend in the same milestone.

## 2. What changes in the original plan

| Original plan | Adjustment proposed for this user's requirement |
|---|---|
| Sections 1 and 12 prefer existing review tools and no custom frontend. | A web management interface is now a first-class deliverable. Reuse the existing UI behavior instead of introducing Azure Boards synchronization first. |
| Section 2.2 says the old application has not been inspected. | Source has now been inspected. Authentication in the real environment, freshness guarantees, and remediation capabilities are still unverified. |
| Go supersedes TypeScript. | Recommend TypeScript for the first release because the working integration, UI, and test corpus already exist. Confirm this change with the user; retain a Go migration option. |
| Short-lived pipeline jobs are the only initial runtime. | An interactive web UI needs an available HTTP service. Start with one local process; shared use needs one approved private host. Pipelines remain suitable for later isolated analysis/build/updater jobs. |
| Existing storage or Blob records for a serialized pipeline experiment. | SQLite is the simplest local application store. Blob is not a good primary query/review store for this UI. PostgreSQL is an explicit later operational decision, not already selected in the original plan. |
| Proposed changed-finding/cursor interfaces. | The inspected adapter is snapshot-based: owners, image inventories, then image details. No source pagination or trustworthy change cursor is implemented. Do not invent one. |
| A part-time two-week experiment includes collection, AI, Renovate, verification, and evaluation. | Aim first for a useful triage-only milestone. Do not promise the full automation scope plus a web UI in that window. Measure actual effort and resolve external prerequisites before estimating remediation. |

**Keep the original plan's safety controls:** unknown is not safe; internal-only does not prove non-applicability; AI proposes rather than approves; exception approval differs from activation; a merged PR is not a remediated deployment; incomplete scans cannot prove a fix.

## 3. Existing app: preserve, extend, or defer

Paths below are under `/Users/adam2/projects/cve-collector` unless otherwise stated.

| Capability | Evidence in existing code | Successor treatment |
|---|---|---|
| Overview, CVEs, Libraries, Images, Whitelist tabs | `public/index.html:30-60`, `src/server.ts:491-515` | Preserve the familiar navigation and drill-downs. Add a Cases/review queue rather than discard the existing views. |
| Owner, severity, search, reported-fix coverage, regression and sorting controls | `public/index.html:78-108`, `src/cve-query.ts`, `public/app.js` | Preserve semantics, stable pagination and URL-restorable filters. Owner filtering is not authorization. |
| Per-CVE/image/library details and local lifecycle history | `src/server.ts:536-549`, `src/db.ts:46-88` | Preserve first/last seen, resolved and reopened history. Do not relabel these as verified runtime fixes. |
| CSV/JSON inventory exports and focused triage exports | `src/server.ts:505-515`, `src/triage-http.ts:87-116`, `src/stream.ts` | Preserve safe streaming. Clearly distinguish current table, selected CVEs, and all-owner-scope export semantics. |
| Collection with progress and cancellation | `src/server.ts:517-534`, `src/collect.ts` | Preserve UI behavior; replace process-local-only job status with durable jobs/restart reconciliation when collection is added to the successor. |
| Exposure CSV import; public descriptions and intelligence | `src/triage-http.ts:39-85`, `src/exposure.ts`, `src/enrichment.ts`, `src/descriptions.ts` | Keep unknown/stale/error states visible. Manually supplied exposure does not establish complete workload inventory. |
| Kiro bundle export, not automated analysis | `src/kiro-bundle.ts`, `src/triage-instructions.ts`, `src/triage-http.ts:87-101` | Keep the manual export path. Add validated proposal import later to close the loop before considering headless execution. |
| Whitelist audit and cleanup handoff | `src/whitelist.ts`, `src/whitelist-cleanup.ts`, `src/server.ts:482-491` | Read-only by default. The existing cleanup POST refreshes collection; it does not remove whitelist entries. Make this explicit in labels. |
| Browser safety and accessibility | `public/app.js:31-36`, `public/index.html`, `src/csv.ts`, `src/server.ts:449-459` | Preserve text-safe rendering, keyboard navigation, focus behavior and CSV formula escaping. Extend request protections, not replace them with a frontend framework. |

**The biggest missing product capability:** the current Kiro workflow ends at an exported file. The inspected DB schema and HTTP routes do not provide persisted assessment proposals and human review outcomes. That gap is more valuable to fix first than automating dependency upgrades.

### Integration facts that must become contract tests

| Confirmed by code | Implementation consequence |
|---|---|
| Images use immutable digest keys; API IDs rotate (`src/db.ts:4-11`). | Never migrate to API-ID-based history. Keep API IDs only as source correlation. |
| Current finding key is digest + CVE + package name + version (`src/db.ts:46-67`); dedupe uses the same package tuple within an image (`src/collect.ts:286-308`). | Preserve a legacy identity map. The existing key cannot represent every possible distinct package occurrence; do not claim lost distinctions can be reconstructed. |
| `packagePath` is mapped to `purl` in `src/collect.ts:388-389`. | Do not assume it is a filesystem path. Adding purl to a primary key is not, by itself, an occurrence-identity migration. Confirm actual semantics before changing keys. |
| Owner-scoped image queries do not populate findings; image-detail queries require an engine (`src/queries.ts:29-89`). | Preserve the two-phase crawl and configured, validated engine. No CVE-first vendor endpoint is established. |
| Suppressed findings live in a separate array and contribute to claimed counts (`src/collect.ts:262-307`). | Store and display suppression separately, never as proof of safety. Compare counts using both arrays. |
| Zero returned findings with nonzero claimed counts is a failure; other count drift is a warning (`src/collect.ts:268-284`). | Preserve those distinctions for parity. Flag drift as a quality limitation for new decision/verification policy; warnings do not become proof of complete evidence. |
| `lastClusterScan` advances frequently; a wall-clock interval guards recrawls (`src/collect.ts:101-113`). | Use bounded snapshot replay and run identities. Do not treat this timestamp as a reliable source cursor. |
| Only successful, unfiltered, unlimited **full-scope** runs resolve findings (`src/collect.ts:312-324`). | Partial, severity-filtered, failed, and owner-only runs cannot globally resolve findings. Successful unfiltered owner-only runs may retire placements for the requested owners only. |
| Redirects, 401 and 403 are authentication failures (`src/graphql.ts:128-139`). | No redirect-following that silently turns a login page into collection data; stop doomed requests. |
| Writable `Store` construction runs schema setup/migrations (`src/db.ts:218-245`). | Never point the successor's writable store at the live legacy DB. Open an approved snapshot read-only for import. |
| `relatedArtifact` is queried (`src/queries.ts:81`) but is not a complete persisted source/build/workload graph in the inspected store. | Repository-to-manifest-to-build-to-digest provenance remains a blocker for automated fixes, not a relationship the model can supply. |

Important existing regression fixtures live in `test/fake-api.ts`, `test/collect.test.ts`, `test/db.test.ts`, `test/server.test.ts`, `test/triage-http.test.ts`, `test/cve-selection.test.ts`, and `test/whitelist-cleanup.test.ts`. These are source references; this planning pass did not execute them.

## 4. What the web interface should do

### Early navigation

- **Overview:** current findings, new/regressed findings, cases awaiting review, collection quality and age. Keep scanner counts and workflow counts separate.
- **CVE inventory:** retain existing owner/search/severity/fix/regression filters, pagination and image/library drill-downs.
- **Cases:** a work queue with applicability, priority, assigned reviewer, next action, workflow status and stale-evidence indicator. Saved views such as My open cases, New/regressed, and Expedited are useful follow-ups.
- **Case detail:** source facts and timestamps; affected package/artifact/deployment contexts; unknowns and contradictions; any AI proposal in a visually separate panel; reviewer decision/rationale; append-only timeline.
- **Exceptions:** existing whitelist audit first. Later show scoped proposals, expiry and external approval/activation references. Never rename a candidate to “safe to whitelist.”
- **Runs/settings:** collection/import/enrichment jobs, progress, failures, last success and effective scope. Configure secret references server-side, never show or accept source tokens in ordinary browser forms.

### Management actions and their boundaries

| Browser action | What it changes |
|---|---|
| Assign a case, add a note, record a next action | Local workflow records, with an audit event. |
| Record applicability/review outcome | A version-bound human review in this app. It does **not** change the scanner's authoritative disposition. |
| Import AI output | An untrusted proposal, after strict validation. Never a human approval record. |
| Request an exception | A scoped proposal for authorized review. No platform suppression write. |
| Link a fix PR or source-system decision | A correlation record, not proof of verification or deployment. |
| Mark “source no longer reports finding” | Collector observation only, under completeness rules. Distinct from runtime-verified remediation. |

Use ordinary UI language: “Reported fix available,” “Evidence incomplete,” “Awaiting review,” “Proposal only,” and “Merged, deployment not verified.” Do not hide uncertainty behind green badges.

### Five browser acceptance journeys

1. Filter by owner and CVE, navigate pages and details, and return to the same filter state. The selected owner/floor scope is consistent across detail and export; selected CVEs across pages never silently become all CVEs.
2. Open a case, inspect evidence, add rationale and a human review, refresh, restart the app, and see the same review/history. A different deployment context does not inherit the decision.
3. Two tabs review the same revision. The second stale submission receives a conflict and offers a refresh; it does not overwrite the first review. Refreshed evidence marks the old review as needing revalidation without erasing history.
4. Import a proposal containing a nonexistent evidence ID, fabricated approval, invalid enum, duplicate JSON key or stale snapshot. Reject/stage as blocked with a useful error and no authoritative state change. A valid proposal still requires human review.
5. Start collection, observe progress, cancel or restart during work, and retain the last good evidence. The job becomes cancelled/interrupted/reconciled, not successful; retry does not duplicate findings or globally resolve them.

## 5. Architecture: deliberately small

### Recommended default: TypeScript modular monolith

- Node supported by the existing app's `package.json` (currently Node >=24), TypeScript and an independently pinned successor lockfile.
- SQLite on one host for the local/single-instance pilot. Keep backups, schema migrations, explicit transactions and bounded writes.
- Reuse the current HTML/CSS/JavaScript behavior; split code by feature as it changes. Do not introduce React/Vite solely to obtain tables, forms and a drawer. React is an option if later UI complexity and team preference justify it.
- Thin HTTP and CLI entrypoints call the same application services; source adapters and persistence sit behind narrow interfaces.
- One durable job queue/table with a single collector worker initially. Polling is sufficient for progress; add SSE only if it materially improves the UX.

```text
Browser
  -> local HTTP server (later TLS + authenticated proxy)
      -> case/review/query application services
          -> local workflow + evidence store (SQLite)
      -> enqueue job; return 202 + job ID
          -> bounded worker -> read-only security adapter

Later: isolated analyst / updater / CI jobs
  -> authenticated, version-bound result ingestion
  -> proposals or verification evidence, never invented human decisions
```

Suggested boundaries, **not a request to move every existing file at once**:

```text
src/
  domain/        evidence, case identity, reviews, policy, validators
  application/   collect/import/review/assess use cases
  adapters/      legacy-snapshot, security GraphQL, intelligence, later Kiro
  persistence/   SQLite queries, migrations, transactions, job claims
  web/           thin handlers, auth/authorization, serializers
  cli/           thin local/batch commands
public/          feature-oriented views and assets
migrations/
test/            unit, API, contract and browser tests
testdata/        synthetic/sanitized fixtures only
```

Do not import application source from the sibling repository at runtime. Establish a reviewed, code-only baseline in `triage`; leave `cve-collector` untouched. Copy only explicitly reviewed source/assets/tests and dependency metadata as needed, never the whole directory: it contains credentials, live DBs, reports, `node_modules`, and local agent configuration.

**Runtime is not just folders.** Separate modules do not isolate credentials. The web process must not hand source credentials to browsers or later model/updater code. Use separate process/job identities and staged evidence when those trust boundaries are introduced.

**Pipeline compatibility:** do not mount a SQLite file over a network share or expect ephemeral Azure agents to share the web host's local file. A pipeline can emit an immutable, scoped artifact for authenticated ingestion. If remote writers, HA or multiple app replicas become real requirements, select an existing PostgreSQL service and test a deliberate migration; do not pretend the storage switch is free.

### If Go is a firm constraint

Use a Go HTTP service with `html/template` and optionally locally served HTMX, plus SQLite for the first local slice. Keep the existing collector as a temporary producer of approved snapshots; implement Go adapter parity against exported, sanitized contract fixtures before allowing live collection. Replace one adapter at a time. Keep the same domain/review invariants and milestones below. A Go binary does not replace the separate runtimes needed by Kiro, Renovate and builds.

## 6. Data model: a CVE is not a review case

A CVE can affect several packages, images, owners and deployments. The UI may group by CVE; an approval must stay bound to the actual affected scope.

Proposed logical records (add only those needed by the current milestone):

| Record | Purpose |
|---|---|
| Source finding / package occurrence / artifact | Source-specific facts, aliases, digest/platform and known package identity; preserve legacy keys and unresolved identity gaps. |
| Deployment context | Workload/environment/inventory scope where actually known; explicit unknowns otherwise. Owner or namespace alone is not invented workload evidence. |
| Case | Finding/occurrence plus artifact and deployment scope, assignment and revision. An unknown-context case cannot authorize a global disposition. |
| Evidence snapshot | Immutable, versioned inputs, source observations/retrieval times, coverage, warnings, collector version and content hash. |
| Assessment proposal | Snapshot reference, proposed applicability/priority/action, model/prompt version where applicable, raw result and separate validation result. |
| Human review | Authenticated actor (or explicit local-operator label in the offline demo), time, reviewed case/proposal/snapshot revision, outcome, rationale and optional external decision reference. |
| Note / audit event | Append-only who/what/when, changed versions and correlation IDs. Corrections append; they do not erase old decisions. |
| Job / collection run | Type/scope, requestor, queued/running/completed/failed/cancelled/interrupted state, attempt/claim, progress and completeness metadata. |
| Later remediation / verification / exception | Separate scoped paths linked to cases. Do not overload `case.status` to mean everything. |

Separate these dimensions:

- Applicability: `affected`, `not_affected_with_evidence`, `unknown`.
- Priority: `expedited_review`, `normal_review`, `insufficient_context`.
- Next action: investigation, dependency update, base-image update, rebuild/deploy, mitigation review, or exception proposal.
- Review outcome: pending, accepted, rejected, unsure; this rates/records the reviewed proposal or manual assessment, not external exception activation.
- Fix progress: planned, PR opened, verified, merged, runtime verified; also blocked/failed/expired/superseded.

Generate IDs with canonical structured serialization, not delimiter concatenation of unchecked strings. Keep stable case identity separate from changing evidence revisions. A content hash detects changes; it does not establish that its producer is trusted. Revalidate freshness independently of hash equality.

New human writes should require a case/evidence revision (`If-Match` or an equivalent expected-version field). Write the review, version transition and audit event atomically. Preserve rejected and superseded proposals for evaluation, subject to agreed access and retention rules.

### Proposed API surface (not currently registered endpoints)

- `GET /api/cases` and `GET /api/cases/:id`: paginated, authorized case queries.
- `GET /api/cases/:id/evidence` and `/history`: immutable evidence and timeline.
- `POST /api/cases/:id/reviews`: validated human outcome plus expected revision.
- `POST /api/cases/:id/notes`: audited local annotation.
- `PATCH /api/cases/:id/assignment`: optional follow-up, not needed for a single-user first demo.
- `POST /api/proposals/import`: bounded strict JSON, known IDs, snapshot binding, proposals only.
- `POST /api/jobs/collect`, `GET /api/jobs/:id`, `POST /api/jobs/:id/cancel`: later durable job lifecycle.

Retain legacy list/detail/export routes during the transition where practical. Endpoints enforce methods, body bounds, authorization, validation and CSRF protection; a frontend button is not a security boundary.

## 7. Small, controllable milestones

Each milestone has a user-visible demonstration and a stop gate. Split it into reviewable PRs; do not combine a collector rewrite, schema migration and frontend rewrite in one diff.

| Milestone | Deliverable | Acceptance / stop gate |
|---|---|---|
| **M0: baseline and decisions** | Confirm TypeScript vs required Go; local vs shared first; define one pilot owner/scope; establish safe code-only baseline and synthetic contract fixtures. | Baseline runs offline in its own directory/store when implemented; no sibling credentials/config/data copied. Document current behavior and known gaps. |
| **M1: usable local web review** | Familiar inventory + case detail, immutable evidence snapshot, manual review/rationale and timeline. No AI and no live API required. | Browser round-trip survives refresh and restart; same-CVE contexts stay distinct; stale write rejected; a review cannot change scanner status or whitelist. This is the first release worth showing. |
| **M2: safe historical import** | Approved legacy snapshot import with dry-run validation, identity mapping and reconciliation report. | Preserve image/finding/placement/lifecycle/run history and source metadata. Reimport is idempotent. Errors roll back; mismatch blocks cutover. Old app remains usable. |
| **M3: reliable refresh** | Reuse/extract the source adapter, add durable jobs/progress/cancel and freshness/completeness UI. | Offline fake-API tests prove wrong-engine, auth, sparse/duplicate data, scope and resolution safeguards; interrupted work is visible and safely replayed. Live validation only with approved read-only credentials and scope. |
| **M4: shared team pilot** | Approved SSO, roles, CSRF, trusted proxy boundary, audit attribution, persistent hosting and restore procedure. | Anonymous/unauthorized requests denied server-side; owner filter cannot bypass access rules; backups restore successfully; secrets remain outside web/client artifacts. No network exposure before this gate. |
| **M5: complete the AI handoff loop** | Export a snapshot-bound bundle; import validated Kiro output as a proposal; accept/reject/unsure and measure reviewer effort. | Unknown refs, injection attempts, malformed output and forged approval fields fail safely. Raw unsafe proposals counted even when blocked. Entire review workflow works with AI disabled. |
| **M6: optional automated assessment** | Pinned isolated Kiro adapter with no source/publisher credentials or privileged tools, bounded input/output/time/cost and kill switch. | Data-sharing approval and effective isolation tests pass. Timeout produces a visible abstention, not approval. Proceed only if automation improves the measured manual handoff. |
| **M7: one verified remediation path** | One approved repo/ecosystem/direct dependency: trusted fix resolution, constrained Renovate PR, protected CI/SBOM/scan verification, human merge and runtime reconciliation. | Real source/build/digest provenance and candidate scanning are prerequisites. Missing/partial/suppressed/wrong-artifact evidence is unverified, never success. No auto-merge or exception activation. |

**Do not gate M1 on M7.** A successful release can stop at M1-M4 and remain valuable. If the time budget is two part-time weeks, scope it to a demonstrated triage-only slice and measured follow-up, not the whole table.

### The first three PRs

1. **PR 1 — safe baseline and offline harness.** Establish the selected code-only successor baseline, independent dependency metadata, fixture-only config and disposable test DB. Preserve current list/detail/export behavior and capture collector contract fixtures. No new live connection or directory-wide copy. Run the existing applicable unit/API tests against fixtures when implementing; do not run live schema introspection or public smoke scripts as part of an offline check.
2. **PR 2 — one case with evidence and review persistence.** Add the minimal additive schema/domain service for a snapshot, case revision, manual review and audit event. Test migration, restart persistence, transaction rollback, repeat requests and stale-version conflict. Do not add model calls, assignments, PR creation or a general workflow engine.
3. **PR 3 — one complete browser review journey.** Add the Cases view/detail and review endpoint/form. Test owner-scoped navigation, keyboard access, safe third-party text, review persistence and conflicting tabs. Demonstrate the fixture-driven workflow end to end before adding live collection.

These PRs are scoped changes, not promises that each takes exactly a day. Re-estimate after PR 1. Move to M2 only after the offline demo is genuinely usable.

## 8. Migration and rollback without losing history

1. Leave `/Users/adam2/projects/cve-collector` unchanged and serving its existing role until parity is accepted. The successor gets a distinct store/config and disabled-by-default external connectors.
2. Use synthetic fixtures first. Before handling real inventory, obtain approval for its destination, access, retention and backup procedure.
3. Produce a consistent snapshot using an approved SQLite online-backup procedure, the existing backup facility under reviewed operating conditions, or a coordinated stopped-writer snapshot. **Do not copy only `cve.db` while WAL writes may be active.** `src/db.ts` implements a `VACUUM INTO` backup; do not invoke the old CLI blindly, because its writable Store path may run schema migrations.
4. Open only the resulting copy read-only. Validate schema version, integrity and required tables. Read into a new destination transaction; never migrate the old live DB in place.
5. Inventory and reconcile images, findings (including suppressed/resolved), placements (including retired), finding events, scan runs, deployment context, enrichment, descriptions and whitelist snapshot metadata. Preserve unavailable values as unknown; retain an import manifest with source snapshot hash/schema and counts.
6. Preserve `first_seen`, `last_seen`, `resolved_at`, `reopen_count` and historical run IDs through an explicit source-ID map. Replaying an import must not emit new appeared/reopened events or duplicate notes/reviews.
7. Do not manufacture source hashes, timestamps, reviewer identities, workload provenance or package occurrences that the old store never recorded. Keep legacy identity and any future richer occurrence key side by side until a tested mapping exists.
8. Compare per-owner/per-severity counts and selected CVE/image histories, not just one global total. Partial/floor-filtered legacy snapshots retain their coverage label. Absence from an import never globally resolves a finding.
9. Shadow the same approved snapshot/collection and compare outputs before switching the collection schedule. Avoid double-polling production unnecessarily; only one collector schedule owns an operational scope at cutover.
10. Rehearse restoring the new store. On rollback, disable successor collection/publication and reopen the untouched old UI for inventory; retain/export successor reviews for recovery because the old app cannot display those new records. Do not discard new human history during rollback.

## 9. Security and operating gates

### Before the first local demo

- Bind loopback only. Preserve same-origin checks; validate allowed Host/Origin values rather than trusting an arbitrary Host header. No wildcard CORS.
- Synthetic fixtures by default; connectors off. Bounded bodies, safe text rendering, safe CSV export, no arbitrary URL fetches or shell commands from requests.
- Explicit local-operator attribution is acceptable for an offline demo, but must not be presented as authenticated corporate approval.
- Audit local review changes, keep evidence/proposals separate, and reject stale revisions. The local process is a trust boundary, not a multi-tenant sandbox.

### Before sharing with a team

- Reuse approved Entra/OIDC authentication or the existing trusted oauth2-proxy pattern. Do not substitute one shared token for named reviewer identities.
- Server-enforced roles such as viewer, reviewer and operator. Decide whether owner scope is an authorization boundary; implement and test it if so. A dropdown does not grant or deny access.
- TLS, session-bound CSRF protection, secure cookie settings, explicit origin policy, and proxy-header trust only from the protected proxy path. Block direct access that can spoof identity headers.
- Dedicated read-only source identity and server-side secret references. Do not copy the old `.env` or developer PAT. Bound collection/import/export load and restrict inventory exports.
- Persistent disk, migration/backup/restore test, job interruption reconciliation, structured non-secret logs, source freshness indicators, retention and an operator stop control.
- One SQLite host/instance initially. Reassess storage for HA/remote writers rather than adding replicas against a shared SQLite file.

### Before AI or external writes

- Confirm approval for sending internal inventory to a model. Exporting a bundle is also data sharing; manual execution is not proof of isolation.
- Manual Kiro sessions must also use approved tool/credential restrictions. Automated analysis uses an isolated workspace with bounded evidence and no production/repository/state-write credentials.
- Strict proposal validation, raw-versus-validated records, explicit unknowns, evidence freshness and deterministic policy before and after model execution.
- New least-privilege publishing identity, separate from existing read-only credentials; no automatic widening of the whitelist PAT. Effective permission tests in a disposable repo precede live use.
- Scoped, version-bound exception proposals only. No bot can activate suppression, tag a final security disposition, merge or deploy.
- Trusted plan/diff gates, deterministic external action IDs, persisted intent and timeout reconciliation; never blindly retry a PR creation with an ambiguous outcome.
- Separate switches for AI, fix publication and exception-proposal publication. Revoking write credentials must not break read-only collection or existing alerting.

## 10. Testing and evaluation ledger

These are **future implementation acceptance checks**, not claims of tests already run.

| Check | Smallest useful evidence |
|---|---|
| Existing feature parity | Fixture-backed API assertions plus one browser journey for filters/detail/export/selection; mechanically enumerate expected routes. |
| Correct collection | Existing fake-API contract cases: engine-empty mismatch, rotating IDs, 302/401/403, duplicate/suppressed rows, null fields, owner scope, interval floor. |
| No false closure | Failed/filtered/limited/owner-only runs cannot globally resolve; only safe owner scope retires its placements. Unknown/stale evidence never becomes “not affected.” |
| Migration safety | Read-only input, integrity/schema validation, transactional failure rollback, deterministic ID maps, repeated import and count/history reconciliation. |
| Durable review | Restart/reload, expected-version conflicts, append-only corrections, separate contexts, atomic review+audit, evidence supersession. |
| Shared interface security | Unauthenticated/unauthorized denial, CSRF/host/proxy-boundary negative tests, identity attribution, escaped CVE text and CSV formula payloads. |
| Job reliability | Double-click, crash/cancel, stale claim, retry and partial evidence retention; no false successful job or duplicate lifecycle event. |
| AI guardrails | Malformed JSON/duplicate keys/unknown fields/fabricated refs/forged approvals/injection/stale snapshot; preserve blocked raw output and continue manual workflow. |
| Remediation gate | Wrong artifact/commit, missing or partial scan, suppression hiding the CVE, still-vulnerable lockfile, unrelated diff, nonexistent target, stale verification and missing deployment proof all block success. |

When implementing, keep an acceptance ledger per PR: requirement -> code path -> targeted automated test -> direct browser/CLI probe. Run the smallest checks covering the change; a build/typecheck alone is not done. Do not use live public-intelligence smoke tests or schema codegen checks as if they were offline unit tests.

Start recording baseline reviewer effort with the first human-review slice. Compare manual handling, evidence/rules only, and evidence/rules plus AI using comparable cases. Count wrong/unsure/blocked outcomes and correction work; distinguish time-to-review, time-to-PR, time-to-merge and runtime-verified remediation. Set thresholds with Security before the live trial. Stop publication on unsafe dismissal proposals or broken isolation/verification; evidence-only operation may remain useful.

## 11. Decisions needed before implementation

1. **Language:** accept TypeScript reuse for the first release, or confirm that Go is mandatory? Recommendation: TypeScript first.
2. **First audience:** one local analyst or a shared team service? Recommendation: local fixture-based slice first, with shared access gated by M4.
3. **Meaning of “manage”:** local cases/reviews/notes and links, or authoritative scanner changes? Recommendation: local workflow plus explicit external decision references; no scanner mutation in the pilot.
4. **Pilot scope and data:** which owner/repositories and approved snapshot destination? No live import until agreed.
5. **Identity and deployment:** approved internal host/SSO, reviewer roles and source read-only identity. Do not assume a developer cookie is deployable authentication.
6. **AI:** approved data handling and whether manual Kiro proposal import is enough initially. Recommendation: close the manual loop before adding headless calls.
7. **Remediation:** can CI provide source/manifest/build/digest provenance, SBOM, complete unsuppressed candidate scans and comparable baseline results? Until proven, this remains a later unverified capability.

## 12. Concrete starting point

Start with PR 1 above, not Renovate and not Kubernetes. The first meaningful demo is:

> Open the web app -> filter a CVE -> inspect one affected-context case and its evidence -> record a human decision with rationale -> restart -> see the same decision and history, without changing any source-system finding.

Once that is reliable, bring in an approved legacy snapshot, then collection, then team access. Only add AI and remediation where measured value and verified capabilities justify them.


## PR6 integration (2026-09-11) — two-way fanout integrated

Confirmed: compile --warnings-as-errors exit 0; `test/triage/collection/ --seed 0` 66 passed
(targeted_final.log); ONE `mix precommit` 401 passed, 2 skipped, exit 0. Guarded owned DB
`triage_test_pr6_integ_final` (literal, absent before create) with explicit
`MIX_ENV=test MIX_TEST_PARTITION=_pr6_integ_final` on every Mix/DB step. Protected
`triage_dev`/shared `triage_test` full-row+schema hashes unchanged
(`5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`); protected source
manifest unchanged vs predecessor. Integration fixes: struct-literal `@defaults`, list `++`,
dead-clause/`inspect` removal, `map_size/1`, compile-time `Mix.env() == :test` transport/entry
gates, detail reconciliation ignores rotating id + owner-scoped `usedInNamespaces`, and a new
`Config.max_payload_depth` so the client envelope-depth guard is decoupled from the normalize
record `max_depth` budget. Prior FAIL/verification history above is preserved; the earlier
3-way fanout failure is not rewritten. See /tmp/triage-pr6-integration-final/INTEGRATION_SUMMARY.md.



## PR6 integration closure (2026-09-11, partition `_pr6_integ_final`)

Post-doc verification added after the integration section above:

- Direct contract probes (`/tmp/triage-pr6-integ-final/probe2.exs`, `probe2.log`): **15/15 PASS,
  PROBE2_EXIT=0**. Covers controlled `run(%{})`/`run(config: nil)`, no-endpoint/https/localhost
  rejection, arbitrary-transport rejection, forged `Transport.Req` state (post and poisoned `new/1`)
  rejection, `Preview.build_snapshot/1` absent, provenance blocker, non-actionable default report,
  incomplete => not complete, Bearer/token-KV sanitization.
- Probe-found defect fixed: `Report` list fields default to `[]` and `Preview.blockers/1` guards
  `findings/suppressed/images`, so `Preview.to_snapshot/1` no longer crashes (`:erlang.++(nil, nil)`)
  on a minimally-constructed `%Report{}`.
- Final re-verify (`/tmp/triage-pr6-integ-final/final_verify.log`): compile `--warnings-as-errors`
  COMPILE_EXIT=0; `mix test test/triage/collection/ --seed 0` **66 passed**, TEST_EXIT=0; ONE
  `mix precommit` **401 passed, 2 skipped**, PRECOMMIT_EXIT=0; owned DB dropped (`DROP DATABASE`,
  ABSENT_AFTER=[]).
- Baselines (`/tmp/triage-pr6-integ-final/compare.log`): own protected-after manifest equals
  predecessor before AND after (`PROTECTED_MATCH_BEFORE`/`PROTECTED_MATCH_AFTER`); dev/test full-row
  hashes equal predecessor before (`DEV_ROWS_MATCH`, `TEST_ROWS_MATCH`); dev/test schema sha
  `5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`; 0 `triage_test_pr6%`
  databases remain.
- Pre-existing unrelated warning retained: `test/triage/import_concurrency_test.exs:63`
  `dynamic(false)` type warning (protected test scope, unchanged).



## Independent final Astra recheck (2026-09-11) — **FAIL**

Fresh serialized pass, own literal guard: partition `_pr6_astra_final_r82`, owned DB
`triage_test_pr6_astra_final_r82` (confirmed absent before `ecto.create`; explicit
`MIX_ENV=test MIX_TEST_PARTITION=_pr6_astra_final_r82` on every Mix/DB step; guard
`GUARD_OK=triage_test_pr6_astra_final_r82`; `CONNECTED_OK`; owned DB dropped,
`0` `triage_test_pr6%` databases remain). `app/config/test.exs:12` literal and the
runtime `current_database()` were checked before each effect. No dev/shared writes.

- `mix compile --warnings-as-errors` → exit 0. Owned `ecto.create`/`ecto.migrate` → exit 0.
- `mix run --no-start --no-compile -e 'Mix.Tasks.Test.run(["test/triage/collection/", "--seed", "0", "--no-compile"])'` → **66 passed**.
- Direct fake-loopback probe `/tmp/triage-pr6-astra-final-r82/probe_final.exs` (real Bandit on `127.0.0.1`, no external/live source) → **29 checks: 20 passed, 9 failed**.
- Fresh **compile-time non-test gate**: with `Mix.env(:prod)`, `Code.compile_file` of `collection.ex`/`transport.ex` then `Collection.run(config+transport)`, direct `Transport.Req.post/3` and `Collection.run([])` all returned `DisabledError` with **0 loopback requests** (`NONTEST_GATE=PASS`).
- Protected `triage_dev`/`triage_test` full-row + schema hashes unchanged
  (`5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`); 114-file source
  manifest identical before/after (`ALL_PROTECTED_IDENTICAL`); predecessor 50-file
  protected manifest `PREDECESSOR_50_IDENTICAL`. Prior FAIL/verification history above is
  retained unchanged; the earlier 3-way fanout failure is not rewritten.

**Reproduced residual FAILs (9):** forged `Transport.Req` `Authorization: Bearer
SYNTHETIC_SECRET` header sent on the wire; poisoned `.error` returned verbatim with
`token=SYNTHETIC_SECRET`; actual **inflight cancellation** not honoured (returned `CancelledError` only
after 401 ms when the response arrived, despite cancellation flipping mid-request); stalling signal exceeded the
20 ms total deadline (returned at 251 ms); **aggregate** text budget not enforced (50x100 B
under a 200 B budget reported `complete: true`); `max_images: 1` issued **2** detail
requests (bounds digests, not API ids); `Errors.sanitize_message({:token,"SYNTHETIC_SECRET"})`
leaked; injected transport `reason` leaked `{:token,"SYNTHETIC_SECRET"}`; malformed image id
`not-a-uuid-SYNTHETIC_SECRET` landed in `report.failures`. Separately observed:
`Report.actionable?(%Report{historical_provenance: true})` is `true` on a forged boolean
while `Preview.to_snapshot/1` refuses the same report as malformed provenance. The raw
harness counted that weak conjunction assertion as a pass; under the requested
no-forged-actionability contract it is a failure. Contract evaluation of the same
29 recorded observations is therefore **19 passed / 10 failed** (raw harness
**20 passed / 9 failed** retained; no rerun). The 114-file identical manifest was
captured before these three authorized verdict-document edits.

Per the bounded-review instruction, no remediation was attempted: extensive residual
safety failure ⇒ **FAIL**, not endless work. The integrator's inherited 66 tests / 15 probes
/ 401 passed + 2 skipped full run is **not** independent signoff. No commits; repo HEAD
`dc4843141b94aa8f9a040eec6aa0ea61978784cc`; `app/` untracked. Full artifact:
`/tmp/triage-pr6-final-astra.md`.

## PR6 residual repair + independent recheck (2026-09-11) — ten blockers fixed

The Astra FAIL above (raw harness 20 passed / 9 failed; contract 19 passed / 10 failed) is
retained unchanged as the historical baseline. A serialized repair then fixed the ten
reproduced blockers, and a fresh independent recheck was run on the post-repair tree.

Ten fixes (production only, `app/lib/triage/collection/`):

1. `transport.ex` sends only the fixed `content-type`/`accept: application/json`; a forged
   `state.headers != []` is rejected before any post, as is any forged `.error` (struct or not).
2. A forged `.error` becomes the constant `InvalidOptionsError{message: "transport state is invalid"}`.
3. `client.ex` runs the request in an unlinked, monitored worker; the caller polls
   cancellation/deadline and kills+drains the worker on cancel/timeout; exceptions are caught
   inside the worker so payloads never reach OTP logs.
4. The signal callback budget is `min(remaining deadline, 100 ms)`, never a fixed 250 ms.
5. `config.ex` adds a distinct aggregate `max_total_bytes`; `normalize.ex` charges it
   incrementally across owner/inventory/detail/raw metadata. `max_text_bytes` stays per-string.
6. `crawl.ex` budgets `max_images` over detail *ids* (not digests) and flags truncation incomplete.
7. `errors.sanitize_message/1` returns the constant `"invalid message"` for any non-binary input.
8. `errors.safe_reason/1` coerces every reason to a closed atom set.
9. Invalid upstream ids are never echoed; failures are constant path/classification strings.
10. `Report.actionable?/1` is always `false`; `Preview.to_snapshot/1` always returns the
    controlled historical-provenance blocker; no valid snapshot builder exists in scope.

Recheck (own literal guard; `MIX_ENV=test MIX_TEST_PARTITION=_pr6res_verify`; disposable
`triage_test_pr6res_verify` confirmed absent, created, migrated, dropped; `0` `triage_test_pr6%`
remain):

- `mix compile --warnings-as-errors` → exit 0
- `mix test test/triage/collection/ --seed 0` → **77 passed, 0 failed**, exit 0
- adapted retained probe (`/tmp/pr6-residual-probe-adapted.exs`; only the guard literal changed)
  with nonzero-on-failure → **29/29 passed**, exit 0 (`PROBE_SUMMARY={"total":29,"failed":0,"passed":29}`)
- full `mix test --seed 0` (crosscutting Config/Transport/Client change) → **412 passed, 2 skipped**, exit 0
- `mix format --check-formatted` on the PR6 files → exit 0
- protected sources byte-identical before/after; `triage_dev`/`triage_test` rows identical and
  schemas identical to baseline `5fb8fc152d624c077e5a0ac4ec65198b334505ecd73afbd41c5ef478b269e2cd`
  (raw `pg_dump` differs only by PG18's per-run random `\restrict` token)

Two low-severity gaps raised by an earlier executor were also fixed in the final pass:
non-struct forged `.error` rejection, and draining `__collection_signal__` in `kill_worker`.
The full `mix precommit` alias was not run as one command; its compile/format/test parts were
run individually. Evidence: `/tmp/pr6-residual-verify.log`, `/tmp/pr6-residual-full.log`,
`/tmp/pr6-residual-probe-results.json`; full report `/tmp/pr6-residual-fixes.md`.


<!-- PR6 closeout 2026-09-11 -->
## PR6 closeout 2026-09-11 — independent Astra re-verification: PASS (limited offline contract)

Fresh guarded run, partition `_pr6_astra_close_q7` (owned disposable DB, MIX_ENV=test/MIX_TEST_PARTITION explicit on every Mix call). Results: compile/create/migrate/drop exit 0; collection suite exit 0; focused probe 3/3 PASS; adapted 29-check probe 29/29 PASS; format exit 0; protected dev/shared DB full-row+schema and protected source manifest unchanged. Call sites local: `app/lib/triage/collection/crawl.ex:79` (`Client.new/4`), `:131/:155/:200/:399` (`Client.query/3`). Bounded offline contract only; no full precommit; no commits. Full record: `/tmp/pr6-astra-closeout.md`.

<!-- PR6 closeout correction 2026-09-11 -->
Correction: the PASS verdict above is amended to **bounded FAIL**. Independent probe
`/tmp/pr6-astra-boundary-probe.exs` (partition `_pr6_astra_close_ind2`) shows a forged client whose
`budget` is a valid `:atomics.new(1, ...)` reference passes `valid_atomics?/1` and then raises
`ArgumentError` (slot 2 out of range) out of `Client.query/3` instead of a controlled error; no
transport call is made. The 80-test collection suite, 3/3 focused probe and 29/29 adapted probe
still pass; only the forged wrong-sized-atomics invalid-state boundary is open. Not repaired per the
bounded instruction. Full record: `/tmp/pr6-astra-closeout.md`.

<!-- PR6 closeout final 2026-09-11 -->
Final: the forged wrong-sized-atomics budget boundary is fixed (`Client.valid_budget?/1` reads atomics
slots 1 and 2) and residual test (13) covers it. Post-fix partition `_pr6_astra_close_ind3` with explicit
MIX_ENV=test/MIX_TEST_PARTITION: compile/format exit 0; `mix test test/triage/collection/ --seed 0` ->
**80 passed, 0 failed**; focused probe 3/3; adapted probe 29/29; owned DB dropped, `triage_test_pr6%` = 0.
Final `client.ex` sha256 `944b8d8320e2a3b75afbac5eaa5186eb01908af1e0f5663951bf8269b3addc0c`,
`residual_test.exs` `f22a8ab500232e9d206fb6c528c9e17010300186834355ddd088cc59d2201d30`.
Verdict **PASS (limited offline contract)**. Full record: `/tmp/pr6-astra-closeout.md`.

