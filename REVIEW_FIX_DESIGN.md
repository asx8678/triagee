# Review correctness — grounded fix design

## Verified in this pass

- `app/lib/triage/guided_review.ex`: `whitelist/4` loads evidence before private `accept_review/5` validates its fingerprint and calls `Decisions.record/1`.
- `app/lib/triage/guided_review/query.ex`: hydration reads findings, placements, images, exposure, decisions, KEV, and remediation requests through multiple queries. A lock on one finding cannot protect this aggregate or newly inserted scopes.
- `app/lib/triage/review_progress.ex`: `Repo.insert` error tuples are handled by next/back callers; connection exceptions can still escape. `step/1` also performs an unguarded read.
- PostgreSQL clients exist at `/opt/homebrew/opt/postgresql@17/bin/psql` and `/opt/homebrew/opt/postgresql@18/bin/psql`. Tool installation is not established as a blocker; PATH must be corrected before the owned-database probe.

## Recommended acceptance fix

First define the invariant: acceptance applies to the evidence explicitly reviewed, not silently to new scopes or changed evidence. Current whole-CVE decisions have no stored evidence fingerprint; merely removing the validation/insert gap does not solve future evidence changes.

Prefer evidence-bound acceptance plus a shared evidence-generation protocol. Persist the reviewed fingerprint/generation with the decision. Every writer of acceptance-relevant evidence must participate in the same transactionally updated generation; acceptance locks/checks that generation, rehydrates and validates, then inserts in the same transaction. Start with a single local evidence-generation row if per-CVE invalidation across shared images, exposure and global intel would be incomplete. Adopt only after enumerating all writer paths and migration/backfill semantics. Legacy unbound decisions need an explicit policy, not automatic reinterpretation.

Do not substitute a plain default-isolation transaction, a lock on currently existing findings, or an optimistic version field updated only by the acceptance path. None protects all of this aggregate. Serializable execution can provide a serial ordering but does not by itself mean acceptance excludes evidence changed later; coverage semantics still need fixing. Do not automatically retry an acceptance against a new fingerprint.

Regression tests (real independent PostgreSQL connections, deterministic barriers rather than sleeps):
- `acceptance rejects evidence changed before commit`
- `acceptance does not cover a concurrently added placement`
- `evidence changed after acceptance requires a new review`
- `concurrent decisions preserve a coherent supersession history`

Test through public `whitelist/4`, not private `accept_review/5`. Ensure ordinary valid acceptance still succeeds and rejected operations insert no decision. This design is not yet implemented or concurrency-verified.

## Progress persistence recovery

Treat navigation storage as optional, but never treat approval/ticket writes as optional. Introduce a narrow context boundary for expected connection unavailability (for example DBConnection.ConnectionError), returning `{:error, :storage_unavailable}`. Do not catch all Postgrex errors or all exits: missing tables, schema errors and programming errors should remain visible.

Apply this to both loading and saving. Make load return a tagged result so LiveView can show step 1 with an explicit persistence warning on a failed read. On a failed save keep the current step and show the existing retry message; never claim progress was saved. Log only sanitized error classifications. Keep ticket confirmation and fresh-preview requirements unchanged.

Tests: `unavailable progress load starts at step one with a warning`, `unavailable progress save preserves the current step`, `progress storage recovery allows retry`, and `unexpected database errors are not silently swallowed`. Use a controlled repository boundary or isolated connection failure, never stop the shared test Repo or user database.

## Verification and sequencing

1. Correct PATH for the coordinator: `export PATH=/opt/homebrew/opt/postgresql@18/bin:$PATH`; verify `psql --version`. This does not prove a server is running or authorize touching an existing cluster.
2. Follow `app/OWNED_DB_VERIFICATION.md` exactly. It explicitly reserves `scripts/verify_owned_db.sh` for the coordinator, not workers. Use a disposable owned database and the documented port override where appropriate.
3. Add recovery tests and implement the narrow progress boundary.
4. Agree evidence-bound acceptance semantics, enumerate writers, then implement the generation protocol with concurrency tests.
5. Obtain actual Security #81–90 findings and complete Option A before any shared exposure. Do not claim they are fixed based on router inspection.
6. Only then extract LiveView components and add operational telemetry; keep those changes separate from correctness changes.

## Changes/checks in this pass

Fixed formatting only in `app/test/triage_web/live/guided_review_live_test.exs` after a fresh format check failed. Compilation passed before that check; subsequent repository format check and strict Credo passed (213 source files, no issues). No behavioral fixes or database test execution are claimed in this pass. No commit or deployment performed.
