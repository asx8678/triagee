# Tailwind asset pipeline — execution record (2026-09-15)

Working tree: `/home/adam/projects/triagee`, app at `app/`, uncommitted on
`e753750` ("Add a connected, arrowed chart to the Timeline"). This record covers the
asset migration only; it does not authorize a push, a deploy or C–F.

## What changed

- `app/assets/css/tailwind.css` (new, tracked source): Tailwind v4.1.18 entrypoint,
  `@import "tailwindcss" source(none)` plus exactly one `@source "../../lib"`, and a
  two-token `@theme` bridge (`--color-error: #a02222`,
  `--color-base-content: #182539`) onto this application's own palette.
- `app/mix.exs`: `{:tailwind, "~> 0.5", runtime: false}`, profile `triage` in
  `app/config/config.exs` (CLI pinned to 4.1.18), built by `mix assets.setup` before
  the pinned vendor copies, and reached by the `setup`/`test`/`precommit`/`ci` aliases.
- `app/lib/mix/tasks/assets_setup.ex`: builds the stylesheet, then copies the Phoenix
  distributions; `app/config/dev.exs` runs the CLI with `--watch`.
- `app/lib/triage_web/components/layouts/root.html.heex`: loads
  `/assets/css/tailwind.css` before `/assets/css/app.css`, so the tracked,
  hand-written `app.css` stays authoritative (its rules are unlayered, the generated
  utilities are layered).
- `app/priv/static/assets/default.css` (deleted): 2,590-line frozen Tailwind v4.0.9 +
  daisyUI artifact with no build behind it. The classes it uniquely supplied are now
  emitted by the build or defined in `app.css`, including the three `hero-*` icon
  masks that `CoreComponents.icon/1` renders.
- `.github/workflows/ci.yml`: the `_build` cache key now hashes
  `app/config/config.exs` as well as `app/mix.lock`, because the standalone CLI
  version is pinned there and a CLI bump alone must not restore a stale cache.

## Evidence (all commands run in `app/` via `mise x --`)

| Check | Result |
| --- | --- |
| `mix assets.setup` | exit 0 — `≈ tailwindcss v4.1.18`, then the three vendor copies |
| generated stylesheet sha256 | `05734178f35cd213252180a8921fc4d3fd8fb5b9940e1293e50941d67b8a635c` |
| reproducibility | identical after an incremental rebuild, after deleting the output, and after a second `Mix.Task.run` |
| `mix format --check-formatted` | exit 0 |
| `mix compile --warnings-as-errors` (test) | clean |
| `mix deps.unlock --check-unused` | exit 0 — the new dependency is seen as used |
| `mix credo --strict` | exit 0 — no issues, 138 files, 65 checks |
| `mix dialyzer` (`MIX_ENV=test`, the environment `mix ci` selects) | exit 0 — `Total errors: 0, Skipped: 0, Unnecessary Skips: 0` |
| `mix test test/triage_web/assets_test.exs --trace` | exit 0 — 14 tests, 0 failures |
| `mix test` (full suite, local PostgreSQL 16 cluster) | exit 2 — **696/703 passed, 2 skipped, 7 failed**, every failure a pre-existing Timeline window test |
| `mix test` from a clean `git archive HEAD` (`e7537508`, `/tmp/base`) | exit 2 — **689/696 passed, 2 skipped, 7 failed** — the identical seven |
| `mix ci` (all seven steps, cluster up) | exit 2 — compile, format, unused deps, credo, assets and dialyzer all pass; only the test step fails, on those seven |
| `sha256sum -c evidence/checkpoint/MANIFEST.sha256` after the suite | 224 OK — the suite rewrote git-ignored output only, no tracked file moved |
| `scripts/tailwind_assets_probe.exs` | 22/22 checks (16 green, 6 red) |

The probe covers what the asset tests assert without needing a database: layout order
and same-origin, served bytes equal to the generated file, both theme tokens,
`.size-5` and `.w-full` emitted for real call sites, exactly one live `@source`, a
repeat-build rebuild, a fresh-destination build whose bytes must equal the shipped
sheet, and per-icon `mask-image` artwork. Its red cases mutate or withhold inputs to
prove the assertions bite: deleting the per-icon mask rules fails the artwork check
while the former name-only check still passed, a second `@source` fails the scan
check, a commented-out directive no longer satisfies it, mutating the clean-build hash
fails that check, the witness class is absent from the build whose tree has no witness
template, and no `class="grid"` exists anywhere under `lib/` (the previous
`.grid {` witness was incidental — the token comes from prose and `attr :grid`).

## Fan-out (2026-09-15)

Run as "start implementing fan out astra": three read-only Astra audits, then two
Astra writers on disjoint files, integrated and verified by the coordinator.

- **Audits** — `astra-pipeline-audit` (`938f77d622024caca6680d9800959b85`),
  `astra-style-audit` (`033e24c52fc34965b16658f7583776df`) and
  `astra-test-audit` (`bb753c0c0c0249acb5f5fae5e2c2358b`), all on
  `openai-codex/gpt-6-astra`, all read-only, all completed. Their punch list is what
  this section implements: the exact CLI version contract, a template-specific scan
  witness, configuration-level profile and watcher assertions, clean-generation
  evidence, cascade-layer wording for `app.css` authority, and the release /
  cold-offline-CI notes. The audits also confirmed as already fixed the two items
  they had raised against an older tree (the `_build` cache key now hashes
  `app/config/config.exs`, and the `@source` check strips comments and asserts the
  complete directive set).
- **Writers** — `astra-writer-assets-test` (`a3335aeabcca4c3cb504107feeddd8f8`) on
  `app/test/triage_web/assets_test.exs` and `astra-writer-probe`
  (`59af2acfb4b948209c9e613764f67642`) on `scripts/tailwind_assets_probe.exs`.
  Both completed. One honest block was reported: no utility class in this repository
  is used only by a template (`sr-only` was the only candidate, and
  `core_components.ex` uses it too), so the template-scan witness could not be a real
  call site. The coordinator closed it synthetically instead of editing product markup
  to satisfy a test: the probe adds a `.heex` file carrying `w-[37px]` to its
  temporary tree, asserts the class is emitted there, and asserts `37px` appears in
  neither the shipped sheet nor the build without that template.
- **Harness blocker, and the fix.** Five Astra children in a row were killed with
  `Fabric model selection failed for openai-codex/gpt-6-astra: requested
  openai-codex/gpt-6-astra, but assistant reports hypercharm/deepseek-v4.1-flash;
  terminating child` — including the three `astra-*` audits listed above. Cause:
  `.pi/fabric.json` had `prewalk.alwaysRearm: true` with `mode: in-place`, so every
  child Pi process was re-armed onto the prewalk model before it could validate
  against the explicit request. Setting `alwaysRearm` to `false` for the duration let
  a capability probe and both writers run to completion; the original value was
  restored afterwards. This is the first fan-out recorded here that ran the model it
  asked for, after the earlier "3-way fanout remains unmet" entries.
- **Coordinator integration** — split the merged pin/watcher/scan test into three
  accurately named tests, added the synthetic witness, annotated the cascade order in
  `root.html.heex`, documented the release and cold-cache requirements in the README
  and the CI cache comment, and re-verified the staged index (see below).

## Limits

- **The suite runs here, against a local PostgreSQL 16.** The earlier "no PostgreSQL
  on this host" note was wrong: extracted apt roots already carried a server at
  `~/.local/share/konstruct-postgres/root/usr/lib/postgresql/16/bin`. `initdb -U
  postgres --auth=trust -D /tmp/pgdata` plus `pg_ctl -o "-p 5432" start` satisfies
  `config/test.exs` (`postgres` / `localhost` / trust, no password) exactly as CI's
  `postgres:18` service does, except for the major version. Full suite on the frozen
  tree: **696/703 passed, 2 skipped, 7 failed**, and the 14 asset tests of this
  checkpoint pass (`--trace`, exit 0).
- **Seven pre-existing Timeline failures, none from this change.** All seven assert
  full Monday-aligned weeks (`length(view.days) == 56` and `== weeks * 7`, the
  `#tl-band-list > li` and `#tl-chart .tl-c-weekday` counts, `empty_days == 54` and
  `== 56`) while the window ends *today*: the implementation returns `from = Monday of
  this week − (weeks−1)·7` through today, so the day list is `weeks·7 − (7 −
  day_of_week(today))`. Every count is exactly five short (51 for 56, 23 for 28, 49 for
  54) because today is a Tuesday; those assertions only hold on a Sunday. Proven
  unrelated: the same suite from a clean `git archive HEAD` in `/tmp/base` fails the
  identical seven (**689/696 passed**). Closing it means choosing a full-weeks window
  or a today-clamped one — the tests assert both — so the semantics decision belongs to
  the owner, not to this checkpoint.
- **`mix dialyzer` passes** in the environment `mix ci` uses (`MIX_ENV=test`): exit 0
  with `Total errors: 0, Skipped: 0, Unnecessary Skips: 0`, PLT built under
  `_build/test`. Dialyzer analyses the compiled `lib/` modules, so it covers the
  staged `.ex` delta (`assets_setup.ex`, `core_components.ex`) and not the `.exs`
  test and probe files, the `.heex` template or the config.
- **`mix ci` runs end to end here now that the cluster exists, and exits 2 for those
  seven tests alone.** Its steps are `compile --warnings-as-errors`, `format
  --check-formatted`, `deps.unlock --check-unused`, `credo --strict`, `assets.setup`,
  `test`, `dialyzer`: credo reports no issues and dialyzer 0 errors, so this change is
  green across the whole gate.
- **No production digest or manifest** (`cache_static_manifest`, `assets.deploy`,
  `phx.digest`, `rel/`) is configured, because this repository has no deployment
  target. The generated stylesheet and vendor scripts are git-ignored output, so a
  future deploy path must run `mix assets.setup` before packaging.
- Browser rendering of the served stylesheet was not exercised; the checks are byte
  and wiring level.
