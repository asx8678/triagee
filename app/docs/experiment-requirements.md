# Experiment requirements and acceptance ledger

- **Ledger version:** 1.3 — third coding pass (W01c), 22 September 2026
- **Plan:** [CVE_TRIAGE_REMEDIATION_IMPLEMENTATION_PLAN.md](../../CVE_TRIAGE_REMEDIATION_IMPLEMENTATION_PLAN.md) is the specification; this file is the living acceptance ledger it requires.
- **Baseline:** HEAD `eef81e26b542325912e133059349ecf74bc2cdd0` (branch `main`) plus pre-existing uncommitted work and the two slices below.
- **Execution rules:** coordinator-only owned disposable databases via `./scripts/verify_owned_db.sh`; pinned `mise` toolchain; no shared `triage_test`, no `triage_dev`.

## 1. Slice records

### W01a — contain the current AI/decision hazards (complete)

| Change | Meaning |
|---|---|
| Explicit-off analysis (`config/runtime.exs`, `lib/triage/ai_triage.ex`) | `TRIAGE_ANALYSIS_ENABLED` strict default-off plus `TRIAGE_KIRO_CLI`; PATH discovery removed; `assess/2` refuses `{:error, :analysis_disabled}` |
| Request-bound async delivery (`lib/triage_web/live/workspace_live.ex`) | `start_async` binding to request + row CVE + fresh target fingerprints + reviewer permission; duplicates bounded; navigation resets; pre-binding shapes discarded; crashed runners contained; drafts untouched |
| Nonblank acceptance rationale (`decisions.ex`, `workspace/commit.ex`) | `accepted_risk` requires a trimmed nonblank reason at both context levels; history preserved verbatim |
| Truthful reported-fix attention (`attention.ex` v2, `workspace/query.ex`, components) | `fixed` is band 1 "Reported fix awaiting verification" with a read-only reason; `request_verification` stays the recognized band-2 work |

### W01b — immutable intelligence generations and bounded exposure (complete)

| Change | Files | Meaning |
|---|---|---|
| Immutable generations + current pointer | migration `20260922092921_intel_generations_and_exposure_policy`, `intel.ex`, `intel/generation.ex`, `intel/current_generation.ex` | `intel_generations` holds one immutable validated snapshot per commit; `intel_current_generations` names the served one; `intel_advisories` rows carry `generation_id`; the old per-(source, external_id) unique index became a partial index for legacy rows plus a per-generation index |
| Atomic commit | `Intel.commit_generation/3` | Generation, rows, pointer move and success receipt commit in one transaction; a per-source advisory transaction lock serializes commits; the pointer moves only for a strictly newer attempt (`started_at`), so an older refresh finishing last is stored as history and cannot displace it |
| Catalogue validation | `intel/client.ex` (`fetch_generation/2`) | KEV is validated as a catalogue: declared `count` must exist and match the parsed entries, entries must all parse, ids must not repeat, and an empty catalogue is refused (`:kev_declared_count_missing`, `:kev_declared_count_mismatch`, `:kev_parse_failed`, `:kev_empty_feed`). NVD stays a per-CVE contract: an empty per-CVE response is a real answer, with `totalResults` checked when present |
| Generation-scoped readers | `intel.ex` (`current_rows/1`) | `cached_kev`, `kev_index`, `kev_row`, `cached_nvd`, `cached_advisories`, `cached_advisory_count` read the current generation, falling back to legacy NULL-generation rows only while no generation exists |
| Exposure validity and policy | `exposure.ex`, `exposure/policy.ex`, `workspace/query.ex` | Record-time rules (future observations beyond the approved tolerance, expiry before its own observation); structured `current_evidence/2` with `:current | :expired | :future_dated | :conflicting`; equal-time conflicts are never resolved by row id; `Policy.usable?/2` is a separate fail-closed dismissal-support flag requiring an approved bounded age; the SQL lateral join mirrors the display rules including the tolerance/interpolation constant |
| Evidence-lock completeness | `workspace/commit.ex` | The commit evidence lock now also covers `intel_current_generations` and `intel_generations`: which advisories are visible decides KEV escalation, so a pointer move during a commit would otherwise change the fingerprint the commit just validated |

### W01c — shared evidence v2 and current-usability projections (complete)

| Change | Files | Meaning |
|---|---|---|
| Packet v2 | `evidence.ex`, `evidence/packet.ex` | Immutable material-evidence packet per exact target scope: placement, image digest, findings, *material* exposure (displayed value + validity class) and *material* per-CVE KEV facts. Provenance and capture timestamps are excluded from the hash, so a repeated identical observation or an unrelated advisory elsewhere changes nothing. Unavailable live edges (register/scan-run provenance) are explicit blockers, never fabricated facts. |
| Coverage rule | `Triage.Evidence.coverage_state/2` | A dismissal claim (`accepted_risk`, `fixed`, `not_affected`, `mitigated`) covers only while its stored `packet_hash` equals the current one. Pre-packet (v1 or nil) dismissals report `:legacy_unverified` and return to review. Work requests keep their v1 binding; retired scopes stay `:historical`. |
| Both projections | `workspace.ex`, `workspace/query.ex`, `workspace/evidence_sql.ex` | The application projection and the SQL page compute the *same* packet hash (shared canonical encoding, refactored v1/v2 encoders, boolean material columns via `bool_or`) and apply the same coverage rule. |
| Commit boundary | `workspace/commit.ex`, `workspace_live.ex` | Decisions store `metadata["packet_hash"]`. A dismissal is refused (`{:dismissal_basis_invalid, id, state}`) when a selected target's exposure evidence is expired, future-dated or conflicting; the UI explains it. |
| Attention | `attention.ex` | Uncovered-but-decided targets report the truthful reason ("Material evidence changed since this decision", "Recorded before evidence packets; needs review again"). |

**Intentional, owner-visible behaviour change.** Every dismissal recorded before W01c — including seeded and legacy CVE-global acceptances — is no longer current coverage: those targets return to the needs queue with an explanatory reason and must be re-approved against a v2 packet. This makes the plan's "old nil/legacy hashes are not valid production approvals" rule real. No data is migrated and no stored row is rewritten (verified: the legacy row's metadata is byte-identical after a fresh read); rolling back is a code revert. CVE-global decisions cannot bind one placement's packet, so they remain legacy by construction — the exact-scope rule the plan requires.

### Execution evidence (W01c)

| Command | Outcome |
|---|---|
| `./scripts/verify_owned_db.sh focused` (packet, currency, workspace query/parity, workspace, decisions, attention) | **60 passed** |
| `./scripts/verify_owned_db.sh ci` | **1246 passed, 2 skipped, exit=0** — all phases clean, including Credo and warnings-as-errors |

### Production defects and test-isolation issues found and fixed during W01b

1. **Current-generation table declared with the default primary key.** `create table(:intel_current_generations)` without `primary_key: false` still created an `id` primary key, so `ON CONFLICT (source)` had no matching constraint (42P10) and every commit failed. Fixed by declaring the table without the default key.
2. **Evidence lock missed the generation tables** (above): a real correctness gap introduced by generations, caught while diagnosing the flake below and fixed in the same pass.
3. **Synthetic-clock fixtures and validation.** The query parity suite genuinely runs on a 2035 clock, so the new observation-time rule refused its fixture rows. `Exposure.record/6` now takes an explicit clock (default: the real one) and callers state theirs; the boundary keeps refusing real future observations. One fixture that deliberately built "newest evidence, already expired" (a contradictory window the boundary now refuses) writes that legacy-shaped row directly, because such rows must still be displayed safely.
4. **Cross-test inventory truncation.** `decisions_test.exs`, `guided_review_query_test.exs` and `impact_test.exs` were `async: true` while truncating the shared inventory; concurrent truncation corrupted the fingerprint-bound ticket-operations suite (11 of its 12 tests failed in one full run, all passing in isolation). Those three modules are now serialized.
5. **Known remaining flakiness (pre-existing, not introduced here).**
   - `test/triage/review_integrations_lifecycle_test.exs` "the deadline terminates a hung wrapper and its children" is a process-death timing race under full-slice load; it passes in isolation (3/3). Untouched by this work.
   - `test/triage/` `WorkspaceTicketOperationsTest` remains intermittently sensitive to `Commit.lock!/0`'s `LOCK TABLE ... NOWAIT`, which fails fast with `:conflict` whenever any concurrent sandbox transaction holds a write on one of the six locked tables. Observed in one of three full runs (4 tests) and absent in the other two. Remediation (brief lock retry, or serializing the remaining async DB writers) belongs to the W01c locking/revision work; it is recorded here rather than masked by further test churn.

### Execution evidence

| Command | Outcome |
|---|---|
| `./scripts/verify_owned_db.sh focused` (12 intel/exposure/parity/consumer suites) | **90 passed** |
| `./scripts/verify_owned_db.sh focused test/triage/workspace_ticket_operations_test.exs test/triage/workspace_test.exs test/triage/intel_generation_test.exs` | **34 passed** |
| `./scripts/verify_owned_db.sh focused test/triage/review_integrations_lifecycle_test.exs` | **3 passed** (flake does not reproduce in isolation) |
| `./scripts/verify_owned_db.sh ci` run A | **1234/1235 passed, 2 skipped** — 1 failure: the lifecycle flake above |
| `./scripts/verify_owned_db.sh ci` run B | **1231/1235 passed, 2 skipped** — 4 failures: the ticket `NOWAIT` contention above |
| `./scripts/verify_owned_db.sh ci` run C (after the evidence-lock fix) | **1234/1235 passed, 2 skipped** — 1 failure: the lifecycle flake above |
| `node --test test/workspace_hooks_test.cjs test/saved_queue_filters_test.cjs` | **9 pass, 0 fail** (carried from W01a; unaffected) |
| `mise x -- mix format --check-formatted`, `credo` via ci | clean (one Credo nesting finding fixed by extracting helpers) |

No real provider, source, SCM call, live publication, production migration, git commit or push was performed. No live KEV/NVD refresh ran: every fixture is local and the CLI's validated path is exercised through `Client.fetch_generation/2` + `Intel.commit_generation/3` tests rather than a live call.

## 2. Configuration contract

| Entry | Default | Contract | Test |
|---|---|---|---|
| `TRIAGE_ANALYSIS_ENABLED` | `false` | Exactly `true`/`1` or `false`/`0`; anything else raises at boot; never implied by an installed binary | `Triage.RuntimeConfigTest` |
| `TRIAGE_KIRO_CLI` | unset | Reviewed runner path; carried but never implies enablement | same |
| `config :triage, :exposure_policy` | `%{}` (nothing approved) | Per-source `%{max_age_days: pos_integer, require_expiry: boolean}`; an unknown or malformed entry is unbounded, so that source's evidence can never support a dismissal | `Triage.ExposureTest` |

Application environment (`:triage, Triage.AiTriage`) is the single in-process source for analysis enablement; tests override it per scenario and restore it on exit. Exposure policy is non-secret administrator configuration, documented in the README.

## 3. Integration-contract gates

| Gate | Contract | Status | Evidence |
|---|---|---|---|
| G01 | Approved read-only live source vocabulary and credentials | unresolved | none — no live source touched |
| G02 | Exact register join evidence for the two pilot repositories | unresolved | none |
| G03 | Register deployment coverage and mapping edges | unresolved | none |
| G04 | Pending isolated Kiro runner documentation/configuration | unresolved | fake runner only |
| G05 | Constrained updater tooling contract | unresolved | none |
| G06 | Candidate verifier contract | unresolved | none |
| G07 | Restricted publisher/SCM credential boundary | unresolved | none |
| G08 | Pre-registered evaluation protocol incl. the majority-agreement denominator | unresolved | none |

Live activation of any W02+ capability remains blocked on these gates regardless of code readiness.

## 4. Acceptance ledger (A01–A44)

Statuses: `passed` = every applicable condition evidenced by an executable test or probe; `partial` = some conditions evidenced, the rest named; `unresolved` = owner package not started. Nothing is marked passed on documentation alone or on a fixture that only parses (the boundary effect must be exercised).

| ID | Owner | Current behavior | Permanent test | Live evidence | Status |
|---|---|---|---|---|---|
| A01 | W01b | The 51st and 80th entries of an 80-entry KEV feed parse, persist as one generation, are readable through `kev_index` and escalate review priority to `critical`; whole-source counts are reported, never a display prefix | `intel_generation_test.exs` "A01", `intel_client_test.exs` 80-entry test, `intel_cache_test.exs` counts | none (fixture) | **passed (fixture)** |
| A02 | W01b | Declared/actual count mismatch, missing count, empty feed, malformed entry and duplicate ids are each refused before any write; the previous generation and its history stay current; the failure records a receipt and no success receipt is written | `intel_generation_test.exs` "A02", `intel_client_test.exs` count test | none | **passed (fixture)** |
| A03 | W01b | A failing refresh preserves the current generation; an older attempt committing last is stored as history without moving the pointer; history rows stay readable; a fresh read yields the durable pointer | `intel_generation_test.exs` "A03" (re-read; a real process restart is not simulated in-process) | none | **passed (fixture)** |
| A04 | W01c | An exposure change (or expiry) after an acceptance makes the old outcome unusable: the target returns to needs in both the Elixir projection and the SQL page | `workspace_evidence_currency_test.exs` "A04" | none (fixture) | **passed (fixture)** |
| A05 | W01c/W03 | A new per-CVE KEV fact invalidates the affected binding while an unrelated advisory in the same generation does not; scope-exact, no stale approval | `workspace_evidence_currency_test.exs` "A05", `evidence_packet_test.exs` | none | **passed (fixture)** for KEV; deployment/repo/manifest mapping change stays W03 |
| A06 | W01c | A v2 acceptance is not covering at its exact exclusive expiry instant, and the newer expired decision does not revive the older acceptance | `workspace_evidence_currency_test.exs` "A06" | none | **passed (fixture)** |
| A07 | W04/W05 | No guard pipeline; analysis is disabled by default (W01a subcheck evidenced) | `ai_triage_test.exs`, `runtime_config_test.exs` | none | partial |
| A08 | W01b/W01c | Future-dated (beyond the approved tolerance), expired, conflicting (equal observation times) and unbounded-source evidence each have an explicit state; only an approved bounded-age source is `usable?`; display and trust are separate, the SQL twin agrees, and the decision boundary now refuses a dismissal whose selected target carries expired/future-dated/conflicting exposure evidence | `exposure_test.exs`, `exposure_parity_test.exs`, `workspace_query_test.exs`, `workspace_evidence_currency_test.exs` "A08 consumption" | none | **passed (fixture)** for states and the dismissal refusal (absent exposure remains acceptable by documented policy) |
| A09 | W01c | Legacy v1 and nil-hash dismissals are readable, byte-identical and never promoted to current approvals; pre-generation advisory rows stay readable and uncertified | `workspace_evidence_currency_test.exs` "A09", `evidence_packet_test.exs`, `intel_generation_test.exs` | none | **passed (fixture)** for advisory and decision hashes (a real process restart is not simulated in-process) |
| A10 | W01c | A material change in one scope does not uncover a sibling scope; queue membership stays scope-exact in both projections; identical material with different capture provenance hashes identically (no needless re-review) | `workspace_evidence_currency_test.exs` "A10", `evidence_packet_test.exs` | none | **passed (fixture)** |
| A11 | W01a/W05 | Principal revalidated server-side; forged actor ignored; revoked session blocked before mutation | `auth_test.exs` | none | partial (W05 analyst identity pending) |
| A12 | W01a/W05 | Stale/out-of-order/after-navigation/evidence-changed results discarded; drafts preserved; duplicates bounded | `daily_and_ai_live_test.exs` | none | partial (W05 durable runs) |
| A13 | W01a/W03/W05 | Empty/whitespace/short acceptance rationales rejected at both context levels; historical rows preserved | `workspace_test.exs`, `decisions_test.exs`, `review_actions_test.exs` | none | partial |
| A14 | W02 | No live ingestion exists | to create | — | unresolved |
| A15 | W02 | No live ingestion exists | to create | — | unresolved |
| A16 | W02 | No live ingestion exists | to create | — | unresolved |
| A17 | W03 | Placement still identifies image/team/namespace/env, not a workload | to create | — | unresolved |
| A18 | W03 | Ambiguous cases rely on human care only | to create | — | unresolved |
| A19 | W04/W05 | Output schema is structural only; no guard/citation pipeline | to create | — | unresolved |
| A20 | W05 | argv-only isolation; tools/filesystem not contained | to create | — | unresolved |
| A21 | W04/W05 | Port deadline and process-tree teardown exist; no durable attempt records | to create | — | unresolved |
| A22 | W04 | No persisted run intent | to create | — | unresolved |
| A23 | W04/W09 | No pause/incident control | to create | — | unresolved |
| A24 | W01a/W09 | Reported `fixed` is band 1 "Reported fix awaiting verification"; label truthful; verification request is recognized band-2 work | `workspace_test.exs`, `workspace_progress_parity_test.exs`, `workspace_live_test.exs` | none | partial (W09 reconciliation) |
| A25 | W01c/W03 | Advisory generation reads, exposure states, the v2 packet hash and the coverage rule are parity-tested across the Elixir projection and the SQL page; progress-mode divergence found and fixed in W01a | `workspace_query_test.exs`, `exposure_parity_test.exs`, `workspace_progress_parity_test.exs`, `workspace_evidence_currency_test.exs` | none | partial (register/selected-target cardinality stays W03) |
| A26 | W04/W09 | No cohort/denominator records | to create | — | unresolved |
| A27 | W04/W09 | No effort capture | to create | — | unresolved |
| A28 | W05/W09 | No feedback/adjudication records | to create | — | unresolved |
| A29 | W06 | No updater exists | to create | — | unresolved |
| A30 | W06 | No updater exists | to create | — | unresolved |
| A31 | W06 | No updater exists | to create | — | unresolved |
| A32 | W02 | Collection production entry disabled; no live transport | to create | — | unresolved |
| A33 | W07 | No verifier exists | to create | — | unresolved |
| A34 | W07 | No verifier exists | to create | — | unresolved |
| A35 | W07 | No verifier exists | to create | — | unresolved |
| A36 | W07 | No verifier exists | to create | — | unresolved |
| A37 | W07 | No verifier exists | to create | — | unresolved |
| A38 | W08 | Azure adapter is work-items only; no PR publishing | to create | — | unresolved |
| A39 | W08 | No PR publishing exists | to create | — | unresolved |
| A40 | W08 | No merge/mutation authority exists (preserved) | to create | — | unresolved |
| A41 | W08 | No PR publishing exists | to create | — | unresolved |
| A42 | W08 | No exception proposal generator exists | to create | — | unresolved |
| A43 | W09 | No deployment reconciliation exists | to create | — | unresolved |
| A44 | W09 | No scorecard exists | to create | — | unresolved |

Boundary levels stay distinct: a fake runner cannot prove operating-system isolation; a fixture SCM cannot certify branch policy; no application test certifies a live artifact scan. The `passed (fixture)` rows above are boundary-behavior evidence, not live-contract evidence.

## 5. Preserved work and drift warning

The worktree carries unrelated pre-existing uncommitted work (daily timeline, daily components, workspace CSS, `IMPLEMENTATION_REPORT.md`, `.pi/` state, untracked AI/daily tests). Do not reset, stage, delete or reformat it. Subsequent agents must re-verify this list before editing; this ledger describes the tree as of the last CI run above.

## 6. Next dependency-ready slice

**W02** — approved live collection and observation ingestion (`collection/`, new `observations.ex`, a bounded `mix triage.collect` task; A14–A16, A32). Every real source call needs the G01 live-contract approval, so the next *offline-available* work is: (a) the lock/revision hardening the ticket-suite `NOWAIT` flake points at (a brief lock retry, or serializing the remaining async DB writers) plus the known `ReviewIntegrations` lifecycle flake; (b) the W03 register joins and selected-target cardinality that extend W01c's packet binding to exact workloads. W03–W09 follow; live activation stays blocked on G01–G08.
