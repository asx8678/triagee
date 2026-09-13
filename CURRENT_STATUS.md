# Triage current status

**Code review findings implemented (2026-09-13: `mix ci` exit 0 — `credo --strict`
reports no issues, 634 passed / 2 skipped, `dialyzer` 0 errors).** The findings
list now pages by keyset position like the review queue; `credo` and `dialyzer`
are part of the gate and the CI workflow; the case detail view's 1415-line module
is now a LiveView plus section components and a formatter, with per-section tests.
Open, deliberately and in writing: the `Triage.Import` split, spec coverage (9 of
346 public functions), and two advisory complexity metrics disabled with their
counts and worst offenders recorded in `.credo.exs`. See
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
