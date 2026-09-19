# Review fixes — plan (2026-09-19)

Implements the prioritized fixes from the full-app review (score 76/100). Behavior-preserving refactor, targeted tests and doc corrections only. No new features, routes or dependencies; the app stays unauthenticated and loopback-only.

## Ordered steps

1. **Credo nesting fix — `app/lib/triage/guided_review.ex:156` (bulk planning).** Reduce excessive nesting with early returns or extracted private helpers. Behavior must stay identical. Gate: `mix credo --strict` exit 0.
2. **Graceful progress-save failure — `app/lib/triage/review_progress.ex`.** Replace the `Repo.insert!` crash path with handled `Repo.insert` results; callers in `app/lib/triage_web/live/guided_review_live.ex` must not crash the LiveView on save failure.
3. **Fingerprint-bind async AI results — `app/lib/triage_web/live/guided_review_live.ex`.** Key asynchronous AI advice to the reviewed evidence's fingerprint (occurrence-identifying fields), not the CVE alone; discard/refresh stale results when evidence changes. Add a LiveView test asserting stale advice is not displayed.
4. **Race regression test — `Triage.GuidedReview.accept_review/5` (`app/lib/triage/guided_review.ex`).** Add a test pinning that evidence validation and risk-acceptance insertion cannot accept a review against changed/stale evidence. Verify first; fix only if a real defect is confirmed — no speculative fix.
5. **Doc correction — `app/README.md`.** Queue-order wording must match the priority-first implementation in `app/lib/triage/guided_review/query.ex`.

## Verification gate (all must pass)

- `mix compile --warnings-as-errors` exit 0
- `mix format --check-formatted` exit 0
- `mix credo --strict` exit 0
- Targeted suites: `app/test/triage_web/live/guided_review_live_test.exs`, guided-review context tests, `review_progress` tests — 0 failures
- Full DB-free suite: at least 317 passed, 0 failures
- Re-establish DB-backed verification with the coordinator-owned disposable database procedure. PostgreSQL clients exist at `/opt/homebrew/opt/postgresql@17/bin/psql` and `/opt/homebrew/opt/postgresql@18/bin/psql`, although `psql` is absent from the current PATH. Add the approved client directory to PATH, verify server access/ownership, and run the guard; do not assume the historical exit 69 is a permanent blocker or claim unrun tests.

Record results in an execution note at the repo root, following the existing convention.

## Deferred to a follow-up turn

- Security #81–90 Option A hardening (local single-operator hardening) — needs its own scope in `app/lib/triage_web/router.ex` and related call sites
- Splitting the 784-line `guided_review_live.ex` into section components
- Operational reporting/telemetry additions (`app/lib/triage_web/telemetry.ex`)

## Execution status

Latest verification (supersedes historical notes below): DB-free suite **317 passed, 691 excluded**; compile, format check and strict Credo all exit 0. PostgreSQL 17.11 client confirmed at `/opt/homebrew/opt/postgresql@17/bin/psql`. Owned-DB full verification remains coordinator-only per `app/OWNED_DB_VERIFICATION.md` and was not run by this delegated worker. See `REVIEW_FIXES_EXECUTION.md` for fresh evidence, inherited 80-test results, locking caveat and remaining gates. Earlier statements below describing pending implementation or lint failure are historical, not current status.


2026-09-19 (second run): prewalk depth raised to 4; resuming execution of the remaining steps (psql/PATH owned-DB verification, evidence-version validation with concurrent-update tests, review_progress DB-unavailability test) and the verification gate.

Progress: review_progress DB-unavailability path implemented ({:error, :database_unavailable}; callers preserve step + retry message). Targeted suites green: 66 passed across cases_queue_test.exs, guided_review_live_test.exs, guided_review_test.exs. REMAINING: acceptance-concurrency coverage, full DB-free suite, psql/PATH owned-DB suite, execution note.

Next (single-purpose run): implement accept_review/5 evidence-version validation + concurrent-update tests only; all other steps deferred to the following pass.

Done: guided_review.ex locks seven evidence tables through revalidation/acceptance ({:error, :review_changed}); 14 concurrency tests added; 80 targeted tests passed. REMAINING: full DB-free suite, owned-DB suite, execution note.

NEW PASS (UI minimalism): reduce visual noise on the homepage and shell — dedupe notices, minimal cards, one-line posture band; preserve safety semantics and selectors; verify against the running server.

Done so far: review queue (/triage) simplified (collapsed help/filters/saved views, bulk actions on selection; 28 tests passed; live 200). NEXT PASS: homepage + shell minimalism (single-purpose run; other pages in later passes).

Progress: /triage, /findings, /cases, /whats-new, /statistics done; /intel simplified (collapsed explanations, 2 tests); home and timeline inspected - already compact, unchanged. NEXT: import, advisory/CVE, case detail, replay, reference data.

Done additionally: cve_live/show.ex instructions collapsed (22 tests green); replay_history_live.ex retention/ordering collapsed (13 tests green); case_live/show.ex exception guidance collapsed (31 tests across case/import/reference-data). REMAINING: final app-wide verification gate only.

Recheck: application fixes remain pending. Fresh `mix credo --strict` inspected 213 source files and exited 8 with one finding at `app/lib/triage/guided_review.ex:156:15` (nesting depth 4, allowed 2). No application source was changed by this recheck.

## Precision corrections and acceptance criteria

- AI callbacks currently match only CVE. Bind request identity to both the evidence fingerprint and a unique request generation; discard old success AND failure callbacks without clearing a newer request's busy flag. Cover same-CVE evidence refresh, navigation away/back, and overlapping requests with deterministic async tests.
- Progress persistence currently calls `Repo.insert!` and callers ignore the result. Merely replacing it with `Repo.insert` does not handle database connection exceptions. Define an explicit recoverable failure contract, show a non-persistence warning without losing navigation, and test both returned errors and expected operational failures. Do not broadly swallow programming errors.
- `accept_review/5` checks a fingerprint before `Decisions.record/1`, without a shared transaction in this path. A concurrent-evidence race is a review concern, not yet a reproduced failure. Use a controlled two-connection regression test; a transaction alone does not guarantee safety under read-committed isolation. Define whether acceptance covers a reviewed snapshot or future advisory-wide evidence before choosing locking/versioning.
- README says ascending CVE, but the query orders descending priority then ascending CVE. Correct the documentation without changing pagination semantics.
- Security #81–90 cannot be individually closed without the original findings. Retain Option A's loopback-only boundary; map each finding to a concrete control and negative test before claiming completion.
- Full DB verification, migration/reload persistence tests, browser keyboard/error-state checks, and eventual telemetry review remain required. Historic test totals are not current verification evidence.
- Split the large LiveView only after behavior is pinned by regression tests; module size alone is not a correctness defect.
