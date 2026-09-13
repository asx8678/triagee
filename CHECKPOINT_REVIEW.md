# Prospective checkpoint review

> **Superseded 2026-09-13 for inventory purposes** by the regenerated inventory
> below. The A+B-era review further down is retained unchanged as history: its file
> counts and pending-B wording describe the tree as of 2026-09-12.

Status: **staged for the checkpoint commit after owner approval of the recommended
plan.** HEAD was `dc4843141b94aa8f9a040eec6aa0ea61978784cc` and the app untracked
before staging. No push and no deployment occurred.

## Regenerated inventory (2026-09-13)

The inventory is now generated rather than hand-written, so it can be re-derived
from the tree at any time:

```
scripts/checkpoint_inventory.sh          # read-only; writes evidence/checkpoint/
```

It produced **197 source-only paths** (`evidence/checkpoint/source-only.paths`) with
a per-file hash manifest (`evidence/checkpoint/MANIFEST.sha256`, 197/197 entries) and
an exclusion summary (`evidence/checkpoint/excluded.paths`). The script refuses to
emit an inventory containing a credential, database, dependency, build, or crash
artifact class.

Enumeration is content-based (`git ls-files --cached --others --exclude-standard`),
not git-state-based. The first version enumerated untracked files only, so once this
commit tracked `app/` the inventory silently collapsed from 197 paths to 13. That
defect is fixed: the script now produces 197 paths both before and after the commit,
and its regenerated list is byte-identical to the committed file list.

Included, by class:

- `app/` source taken whole (165 paths) under its own ignore rules: `mix.exs`,
  `mix.lock`, `config/`, `lib/` (32 `lib/triage`, 25 `lib/triage_web`), `test/`
  (27 `test/triage_web`, 23 `test/triage`, support and replay fixtures), `priv/`
  (`repo/migrations`, `repo/seeds.exs`, 11 versioned `priv/static` sources including
  the logo/wordmark images), `scripts/verify_owned_db*`, and app metadata/docs
  (`AGENTS.md`, `README.md`, `LOCAL_RUNTIME.md`, `OWNED_DB_VERIFICATION.md`,
  `PR2`–`PR7` plans, `UI_WORKFLOWS_PLAN.md`).
- Root records: `CURRENT_STATUS.md`, `CHECKPOINT_REVIEW.md`, `NEXT_STEPS_PLAN.md`,
  `A_B_EXECUTION.md`, `FINDINGS_PAGING_EXECUTION.md`, `INTEL_WIRING_EXECUTION.md`, the `UI_REDESIGN_*` and
  `UI_IMPROVEMENTS_*` plan/report/brief documents, `OVERVIEW_INTELLIGENCE_PLAN.md`,
  the reviewed `IMPLEMENTATION_ROADMAP.md` modification, `.gitignore`, and
  `scripts/checkpoint_inventory.sh` itself.
- Durable text records only under `evidence/`: 16 markdown ledgers and reviews
  (independent reviews, ownership, baseline, leaf reports, reviewer ledger/probe
  notes). Binaries, screenshots, logs, JSON results, diffs and probe scripts stay
  outside git.

Excluded, by class (see `evidence/checkpoint/excluded.paths`):

- All `.pi/` harness configuration and state, including the three inherited tracked
  modifications, plus the untracked mesh journals.
- `architecture(3).md` — the input architecture brief. It is a legitimate candidate
  for the repository, so it is called out separately for explicit owner approval
  rather than folded silently into this checkpoint.
- `tmp/` (103 scratch files: the headless-browser verification screenshots and the
  collector working tree).
- `evidence/` artifacts other than the 16 markdown records (386 untracked files).
- Ignored build/dependency/generated classes: `app/deps/`, `app/_build/`,
  `app/.elixir_ls/`, `app/priv/static/assets/vendor/`, `app/erl_crash.dump`.

## Bounded secret review (2026-09-13)

- No `.env` file exists in either the repository root or `app/`; `.env`, `.env.*`,
  `*.pat`, `*.pem`, `*.key`, `*.p12`, `*.pfx` and every database/export extension are
  ignored by the reviewed root rules.
- `config/prod.exs` contains no credential, hostname, or signing key; production
  values come from `config/runtime.exs` via environment lookups. `config/dev.exs`
  and `config/test.exs` contain only local development/test framework values.
  Credential files were not opened and no values are reproduced here.
- A bounded long-token scan over prospective source and records returned 153
  matches, all classified: hex digests recorded in the execution/review documents,
  the deliberate fake placeholders in `lib/triage/seeds.ex` (`aaa111…`), and Azure
  DevOps repository URLs in the collector whitelist. No apparent secret, private key,
  or production credential value was found in the inventory.

Limits: this is a pattern-based review of a working tree, not entropy analysis,
history scanning, or artifact scanning. Because nothing is staged, no staged-content
scan exists. The exact staged diff must be scanned before approval.

## Proposed checkpoint (approval required — not executed)

Staging would be path-scoped from the generated inventory, never a blanket add:

```
git add --pathspec-from-file=evidence/checkpoint/source-only.paths
```

Proposed message:

```
Checkpoint the triage application source and its verified local runtime

Add the Phoenix triage app that has been developed locally but never committed,
with the planning, status and execution records that describe it.

- app/: mix.exs, mix.lock, config, lib, priv source, tests and verification
  scripts; sources only, no dependencies, build output or generated vendor assets
- bounded findings list: paged Inventory.list_groups/1 with total orders, a
  sort/page filter contract, page controls and honest overview captions
- advisory intelligence wired to the review-priority policy, with per-placement
  severity and cached exploitation evidence, plus read-only and source-conflict
  boundary tests
- root records: current status, checkpoint review, next-step plan, A+B execution
  record, findings-paging record and the UI design/improvement documents
- verified locally: mix precommit 608 passed / 2 skipped, exit 0

Excludes .pi/ harness state, architecture(3).md, tmp/ scratch output, and
evidence binaries/logs/probes. No deployment; the app remains unauthenticated
and loopback-only.
```

Owner approval of this list was given ("do what's recommended").
`architecture(3).md` remains excluded pending an explicit decision, and the
staged-diff scan result is recorded above. Original historical-baseline proof
remains unresolved.

## Inventory reviewed (2026-09-12, A+B era — historical)

A+B writers and integration are complete; fresh integration passed 484 full-suite
tests / 2 skipped plus 2 separately opted-in concurrency tests. Fresh independent
Astra verification PASS is recorded in `evidence/a_b/ASTRA_REVIEW.md`. Exact source-only paths are in
`evidence/a_b/checkpoint-source.paths`; sanitized evidence paths are separately
listed in `evidence/a_b/checkpoint-evidence.paths`. These are inventories, NOT
staging commands. No staged diff or checkpoint commit exists; approval remains gated.

The A leaf's initial review below is retained with its timing/limits. Current
coordinator results supersede its pending-B wording; see `A_B_EXECUTION.md`.

## Inventory reviewed

At review time `git status --short --untracked-files=all` exited 0 and showed the
entire application untracked, inherited modifications to `IMPLEMENTATION_ROADMAP.md`
and tracked `.pi` harness files, untracked A+B evidence, and no staged files. The
initial sanitized app inventory contained 137 files outside excluded credential,
dependency, build, editor, fetch-cache, and generated-vendor paths; concurrent B files
were added afterward and require inclusion in the coordinator's regenerated final inventory. `app/assets/` is absent;
versioned static source/output currently lives under `app/priv/static/`.

### Source-only prospective staging list

This is an inventory, not a staging command. Include only after final review:

- Root checkpoint docs: `CURRENT_STATUS.md`, `CHECKPOINT_REVIEW.md`,
  `NEXT_STEPS_PLAN.md`, and the coordinator-produced `A_B_EXECUTION.md`.
- Root ignore policy: `.gitignore`.
- App metadata/docs: `app/.formatter.exs`, `app/.gitignore`, `app/.mise.toml`,
  `app/AGENTS.md`, `app/README.md`, `app/PR2_PLAN.md` through `app/PR6_PLAN.md`,
  `app/PR7_PLAN.md`, `app/PR7_CLI.md`, `app/PR7_HISTORY.md`,
  `app/UI_WORKFLOWS_PLAN.md`, and B's `app/LOCAL_RUNTIME.md` and
  `app/OWNED_DB_VERIFICATION.md` when present and reviewed.
- Build/dependency manifests: `app/mix.exs`, `app/mix.lock`.
- Runtime source: all reviewed files under `app/config/` and `app/lib/`.
- Database source only: `app/priv/repo/migrations/` and `app/priv/repo/seeds.exs`.
- Versioned static files: `app/priv/static/` except
  `app/priv/static/assets/vendor/`.
- Tests/fixtures/support: all reviewed files under `app/test/`.
- B verification source: `app/scripts/verify_owned_db.sh`,
  `app/scripts/verify_owned_db.exs`, and `app/scripts/verify_owned_db_test.sh`
  when present and reviewed.

The final prospective list must be derived from the final tree, compared with the
A+B manifests/evidence, and inspected path-by-path before staging. Evidence under
`evidence/a_b/` is coordinator-owned and is not included here; the coordinator must
separately decide which sanitized durable records belong in the checkpoint.

## Explicit exclusions

Do not stage:

- `.pi/` configuration/state/journals, including inherited tracked modifications and
  untracked mesh event/sequence files.
- `app/deps/`, `app/_build/`, `app/.elixir_ls/`, `app/.fetch/`, or generated
  `app/priv/static/assets/vendor/`.
- `.env`, `.env.*` (except a deliberately sanitized `.env.example`), credential/key
  material (`*.pat`, `*.pem`, `*.key`, `*.p12`, `*.pfx`), or reports.
- Databases and exports (`*.db`, WAL/SHM companions, `*.dump`, `*.sql`), legacy DB
  content, crash dumps, screenshots, browser profiles, logs, temporary probes, or
  other `/tmp` evidence.
- The tracked legacy collector under `tmp/cve-collector/`, `architecture(3).md`,
  inherited `IMPLEMENTATION_ROADMAP.md` changes, or any other unrelated root change,
  unless a separate owner explicitly approves it after review.
- `evidence/a_b/before/` snapshots or other coordinator evidence merely because they
  are untracked; provenance and sanitization require coordinator review.

Root ignore rules cover dependency, secret, database/export, report, and local harness
journal classes. `app/.gitignore` covers BEAM dependencies/build/editor/fetch output,
`.env`, crash dumps, and generated vendor assets. Tracked `.pi` files remain visible
because ignore rules do not conceal tracked changes.

## Accidental-secret review

A filename-only indicator scan of sanitized `app/` source/configuration exited 0.
It excluded credential files, dependency/build/editor/fetch caches, generated vendor
assets, and database/key extensions; values were not emitted. Matching files were
reviewed as expected documentation, test canaries/redaction cases, environment-variable
lookups, development/test-only framework signing values, or credential-safety code.
No apparent production credential value or private-key block was identified in the
reviewed source. Credential files were never opened.

Limits: this was a bounded pattern review, not entropy analysis, history scanning,
artifact scanning, or a guarantee that secrets are absent. The app is untracked, so
there was no staged-content secret scan. The final coordinator must inspect the exact
staged diff with a secret scanner that reports locations safely, without printing
values, before approval.

## Checkpoint blockers and handoff

- B runtime/verification integration and independent review are not recorded here.
- Concurrent B source appears to replace the initial production all-interface bind
  with a fail-closed loopback policy; only coordinator-owned checks may establish it.
- Original historical-baseline proof remains unresolved.
- No fresh full suite, precommit, concurrency test, listener probe, or DB integration
  was run by A. Upcoming results belong in [`A_B_EXECUTION.md`](A_B_EXECUTION.md),
  not in this prospective report.
- A final staged diff does not yet exist. Therefore staged coverage, final hashes,
  and checkpoint approval remain pending, and no checkpoint commit has occurred.
