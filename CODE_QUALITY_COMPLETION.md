# Code-quality review completion

## Scope decisions and acceptance ledger

The original review included speculative and incorrect recommendations. This
implementation preserves domain contracts rather than applying every suggestion
literally. Existing unrelated documentation and `.pi/` edits are left untouched.
No staging, commit, PR, deployment, database migration or live-source fetch is
part of this change.

| Review finding | Disposition and acceptance check |
| --- | --- |
| 1. Library `Mix.env()` gates | Implemented with `Application.compile_env/3`; `config/config.exs` defaults collection loopback transport off, `config/test.exs` enables it. All three compiled gate consumers agree. Runtime changes cannot enable a previously disabled build. |
| 2. Analyzer workarounds | Correction: preserve forged-atomics rejection and the documented narrow Dialyzer suppression. Elixir structs are forgeable; deleting these checks would regress the zero-network rejection contract. Dynamic dispatch prevents erroneous dead-path inference, rather than making the whole client unanalyzed. The Credo Apply waiver now covers only `collection/client.ex`. |
| 3. Tail appends | Implemented prepend/reverse accumulation for normalization images, findings, suppressed findings and diagnostics. Public ordering is restored before blocker derivation. Added direct order and budget regressions. Import documentation now limits its linearity claim to record collection. |
| 4. Risk ranking/reasons | Implemented compile-time rank map with strict lookup and a single ordered additional-reason list. Tests cover all priorities, ties and invalid priorities. |
| 5. Stored SQL severity rank | Withdrawn: per-row indexing does not make scope-dependent grouped `MAX` and counts index-backed. The existing generated SQL uses server-owned literals and parameterized values. A migration would require measured query-plan evidence and is not justified by the review. |
| 6. HTTP duplication | Implemented `Triage.HTTP.options/1` and `bounded_body/2`, shared by collection and intelligence adapters. Redirects, retries, decode, time and streaming byte limits are shared; endpoint policies and public domain-specific errors remain separate. Collection retains its fixed Finch pool and excludes incompatible `connect_options`. |
| 7. Global Credo waivers | Implemented explicit per-file exclusions for nesting, complexity and Apply. New files retain default checks. AliasUsage retains its documented naming-policy exception. |
| 8. Findings UI | Implemented common filter/result assignment helpers; invalid events and URL loads reset the same derived stream state. Reuses one teams read. Added escaped `UIComponents.counted/1` and migrated package/image/occurrence/team counts. Streams still require separate count/empty assigns; those are not intrinsically a smell. |
| 9. Timeout documentation | Implemented module attribute before moduledoc; the displayed timeout is interpolated from the actual constant. |
| 10. Generated root stub | Removed unused `app/lib/triage.ex`; no root-module callers existed. Domain modules and application startup are independent of it. |
| 11. Duplicate size check | Removed unreachable second check in collection `classify_response/4`; response admission still enforces individual and shared byte budgets before decoding. |
| Repository hygiene | Added `/evidence/` ignore without removing existing tracked artifacts. Preserved `architecture(3).md`, `tmp/cve-collector/` and linked plan documents: these are intentional project inputs, not established junk. The earlier claim that all work was uncommitted came from a historical report and was not a valid current-workspace finding. No unrelated work is committed or stashed. |

## Follow-up scope and acceptance ledger

All six follow-up items are implemented. The scope was corrected where the
suggested mechanics would change contracts or leave the feature incomplete.

| Item | Implementation and acceptance check |
| --- | --- |
| 1. Inventory file split | Extracted `app/lib/triage/inventory/{image,cve_detail,image_placement,finding,finding_event}.ex`. Public module names, tables, fields, defaults and changesets are unchanged. Image associations use fully-qualified targets; `FindingEvent` intentionally has **no** association back to `Finding`. `CveDetail` keeps its type and hidden moduledoc. `app/test/triage/inventory/schema_test.exs` checks reflection, association targets and changesets without PostgreSQL. No migration or external call-site rename. |
| 2. Small pure UI helper | `app/lib/triage_web/filter_assigns.ex` supplies `filter_form/1` and `cleared_page/0` to `app/lib/triage_web/live/case_live/index.ex` and `app/lib/triage_web/live/whats_new_live.ex`. Only scope-form data and four identical pagination-reset keys are shared. Each view retains its parser, queries, error flags, KEV state and explicit stream reset. Timeline and findings behavior is untouched. Tests: `app/test/triage_web/filter_assigns_test.exs`. The previous claim that both views already constructed the same selected-value form was inaccurate: the queue previously initialized only an empty form. Its inputs still use the explicit selected filter values. |
| 3. First-class DB-free tests | `app/mix.exs` recognizes `TRIAGE_SKIP_DB_SETUP=1` or `true`; it skips Ecto create/migrate **and** passes `--no-start --exclude db`. Merely skipping migrations would still start the application Repo. `app/test/test_helper.exs` shares `app/test/support/db_free.ex` with the retained focused runner, starting dependencies, PubSub and a non-listening endpoint, never the Triage application or Repo. `DataCase`, `ConnCase` and the direct import-concurrency suite carry `:db`. The ordinary alias still creates/migrates/tests; the owned-DB verifier refuses a DB-free override. |
| 4. HTTP options and compile-time gate | Both production adapters and all HTTP tests use `Triage.HTTP.options(timeout: ..., max_bytes: ...)`; missing or non-positive limits fail explicitly. `app/lib/triage/collection/loopback.ex` is the sole `compile_env/3` source. Collection, Transport and nested Req consume its value at module compilation, retaining compiled-out offline request paths. The existing public `Transport.loopback_enabled?/0` remains available for layouts. No macro or runtime gate was introduced. |
| 5. Runtime intel byte cap | `Triage.Intel.Config.max_response_bytes/0` reads `Application.get_env(:triage, :intel, [])` then the keyword value; a list path is **not** valid nested lookup for `Application.get_env/3`. Default: `8_000_000`. Each fetch validates and snapshots one cap for both Req streaming and final/injected body admission. Invalid configuration rejects before transport. Oversize responses retain `{:error, {:response_too_large, limit}}`, discard partial success and warn with the source and limit only, never body or credentials. Full config/transport modules cover exact boundaries, runtime changes, mid-fetch changes, streaming overflow, malformed transports and safe diagnostics. |
| 6. Durable verification report | Replaced ephemeral log citations and the nonexistent precommit-log claim with the commands and observed results below. Temporary logs are supplementary same-session artifacts, not required evidence. |

### Runtime cap configuration

For a release, set this in `app/config/runtime.exs` (choose an explicit finite
positive integer appropriate for the approved feed). It does not enable network
access or change the source allowlist:

```elixir
config :triage, :intel, max_response_bytes: 16_000_000
```

The cap is read on every fetch, not compiled into the client. Invalid values
return `{:error, {:invalid_config, :max_response_bytes}}`; they never disable the
bound. Both KEV and NVD use this shared policy.

## Verification

Observed after the follow-up implementation:

| Command (run from `app/`, unless noted) | Observed result |
| --- | --- |
| `TRIAGE_SKIP_DB_SETUP=1 mise x -- mix test --exclude db` | **317 passed, 529 excluded**. No Triage application or Repo started. Excluded modules are still compiled; two pre-existing unused-helper warnings in `test/triage_web/live/cve_presentation_test.exs` remain. |
| `mise x -- mix compile --warnings-as-errors` | Exit 0. |
| `MIX_ENV=test mise x -- mix compile --warnings-as-errors` | Exit 0. The unused `CveDetail` alias caught during the first test run was removed. |
| `mise x -- mix format --check-formatted` | Exit 0. |
| `mise x -- mix credo --strict` | Exit 0; 68 checks on 180 source files. |
| `MIX_ENV=test mise x -- mix dialyzer` | Exit 0; zero errors, skipped warnings or unnecessary skips. |
| Focused runner command below | **19 passed**, exit 0. |
| Compile-time gate probes below | Both exit 0: dev remains offline after runtime enable; test remains enabled after runtime disable; normal test alias still includes Ecto setup. |
| `git diff --check -- app CODE_QUALITY_COMPLETION.md` (repository root) | Exit 0. |
| `sh app/scripts/verify_owned_db.sh precommit` (repository root) | **Blocked**, exit 69: `verify-owned-db: psql unavailable`. No integration pass is claimed. |
| `TRIAGE_SKIP_DB_SETUP=1 sh app/scripts/verify_owned_db.sh target` (repository root) | Expected rejection, exit 65: `verify-owned-db: refuse DB-free test override`. |

### Reproduce the focused full-module regressions

```sh
cd app
MIX_ENV=test mise x -- mix run --no-start scripts/verify_code_quality.exs \
  test/triage/inventory/schema_test.exs \
  test/triage_web/filter_assigns_test.exs \
  test/triage/http_test.exs \
  test/triage/intel_config_test.exs \
  test/triage/intel_transport_test.exs
```

Omit the explicit file paths to run the retained affected-module selection.
The first-class `TRIAGE_SKIP_DB_SETUP=1 mise x -- mix test --exclude db` command
discovers the entire DB-free subset automatically, including new test modules.
It is not a substitute for the database suite.

### Reproduce the compile-time gate probes

These probes do not start the application or make a network request:

```sh
cd app
MIX_ENV=dev mise x -- mix run --no-start -e '
alias Triage.Collection.{Config, Loopback, Transport}
alias Triage.Collection.Errors.DisabledError
false = Loopback.enabled?()
false = Transport.loopback_enabled?()
Application.put_env(:triage, :collection, loopback_transport: true)
false = Loopback.enabled?()
false = Transport.loopback_enabled?()
{:ok, cfg} = Config.new(endpoint: "http://127.0.0.1:1/graphql", environment: "test")
state = Transport.Req.new(cfg)
{:error, %DisabledError{}} = Transport.Req.post(state, "{}", [])
{:error, %DisabledError{}} = Triage.Collection.run(config: cfg, transport: {Transport.Req, state})
'
MIX_ENV=test mise x -- mix run --no-start -e '
alias Triage.Collection.{Loopback, Transport}
true = Loopback.enabled?()
true = Transport.loopback_enabled?()
Application.put_env(:triage, :collection, loopback_transport: false)
true = Loopback.enabled?()
true = Transport.loopback_enabled?()
{:error, %Triage.Collection.Errors.InvalidOptionsError{}} = Transport.Req.post(%Transport.Req{}, "{}", [])
["ecto.create --quiet", "ecto.migrate --quiet", "assets.setup", "test"] = Mix.Project.config()[:aliases][:test]
'
```

### Remaining integration boundary

Full PostgreSQL/LiveView integration and `precommit` remain **blocked, not green**.
Run `sh app/scripts/verify_owned_db.sh precommit` from the repository root in the
approved disposable PostgreSQL environment. Do not substitute a shared database.
The DB-free suite tests schema reflection and pure UI data, not SQL execution or
end-to-end LiveView database behavior.

Same-session artifacts only (not durable dependencies of this report):
`/tmp/triage-followup-db-free.log`, `/tmp/triage-followup-static.log`,
`/tmp/triage-followup-probes.log`. The earlier `/tmp/verify-scoped.log` describes
the previous 136-test baseline, not the current broader run.

No commit, PR, issue, migration, deployment or live intelligence fetch was made.
