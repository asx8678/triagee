# Coding-agent handoff — CVE Triage & Remediation

Use this prompt with access to the repository. The accompanying plan is the full specification; no preceding chat is required.

---

Implement the CVE triage and remediation experiment in this repository, following **[CVE_TRIAGE_REMEDIATION_IMPLEMENTATION_PLAN.md](CVE_TRIAGE_REMEDIATION_IMPLEMENTATION_PLAN.md)**.

## Start here

1. Read the entire plan, applicable `AGENTS.md` instructions, `app/README.md`, `app/OWNED_DB_VERIFICATION.md`, and relevant `app/docs/WORKSPACE.md` / domain / integration documentation before edits.
2. Inspect actual HEAD and `git status --short`. The plan was written against `eef81e26b542325912e133059349ecf74bc2cdd0` plus uncommitted AI/daily-workspace work. Reconcile drift; preserve all unrelated and existing uncommitted work. Do not restore files from HEAD over current edits.
3. Trace the current execution path and create `app/docs/experiment-requirements.md` with W00's acceptance and integration-contract ledger. Planning documents and historical test counts are not proof of implementation.
4. **For the first pass, complete W00 and W01a only**, as a coherent patch with permanent regression tests and validation. Stop and report at that checkpoint. If that slice is already complete, verify its evidence and identify the next dependency-ready slice before proceeding under the owner's continuation instruction.

## Non-negotiable implementation choices

- Extend Phoenix LiveView/Ecto/PostgreSQL. Use the active WorkspaceLive flow; do not rebuild retired case screens or introduce Go/a second coordinator.
- UI CVE/placement grouping is not a unique live workload or an approval scope. Bind live recommendations to exact finding/package/artifact/workload evidence; never approve a larger parent because one child is safe.
- Preserve legacy histories, hash domains, actors, source labels, chronology, durable drafts and uncertain Azure ticket recovery. Do not relabel synthetic/public-reference/legacy records as live or verified.
- Centralize decision-time evidence validity, including current clock, exposure, intelligence, register/source completeness and exact scope. Keep application/SQL projections consistent. A matching hash alone is insufficient.
- Keep model suggestions, deterministic guards, human decisions, artifact verification, merges and deployment verification separate. Record unsafe raw suggestions even if blocked.
- Isolate Kiro's own tools/filesystem/network/credentials; argv invocation and prompt text are not a sandbox. Do not use a locally installed CLI or ambient credentials as permission to make a real call.
- Never grant the model or publisher merge, scanner-mutation, final security-tag or exception-activation authority. Valid proposal preparation may later be automatic only under the plan's explicit approved mode/gates.
- Do not invent missing endpoints, paging/scan guarantees, register joins, ecosystem/version evidence, SCM provider, reviewer authority, Kiro flags or CI receipts. Record unresolved G01-G08 gates; continue independent fixture-backed work without claiming live readiness.
- No real source/model/SCM calls, external publication, production migrations, deployment, git commit or push without explicit owner authorization.

## Validation and completion

Maintain the plan's A01-A44 acceptance ledger. Implement negative tests at the effect boundary plus positive controls. For W01a, concentrate on explicit-off AI, stale/out-of-order result binding, nonblank risk acceptance and reported-versus-verified remediation attention, while preserving manual review and daily-feed work.

Use targeted tests first and the existing owned disposable-database wrapper; read its safety instructions and Mix task help. The coordinator alone manages the owned database. Never share/reset `triage_test` or touch `triage_dev`. Do not blindly rerun passing suites or report a build as behavior proof. Inspect nonzero exits and iterate. Run the applicable final code quality checks from the plan, review formatting/lockfile effects, and keep live validation separate from fake-adapter tests.

Return:

- Changed files and implemented acceptance IDs.
- Source-to-boundary explanation of each important safety behavior.
- Test/probe commands, actual results and migration/history compatibility evidence.
- Preserved work, unresolved integration gates and live operations not performed.
- Remaining risks and the next package/checkpoint.

Do not claim the full experiment is complete after the first safety patch or after Triage's own application CI passes.
