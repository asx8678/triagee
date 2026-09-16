# CVE triage restoration — acceptance ledger

## User request and observed cause

Restore missing action/assessment fields after clicking a CVE, and implement a useful CVE whitelisting/suppression/not-dangerous procedure. Phoenix `app/` is the active product; `tmp/cve-collector` is not the target.

Traced path: `CveLive.Show` reads `Inventory.fetch_cve/2`, shows risk/intel/packages/placements but no actions. `FindingLive.Show` only exposes Open case with explicit owner+environment, which leads to `CaseLive.Show` and `CaseLive.Sections.review_section/1`. Those four assessment fields still exist. `Cases` provides scoped, immutable evidence snapshots, append-only reviews, optimistic revision binding and idempotency; reviews deliberately do NOT activate suppression. Scanner `Finding.suppressed` is an imported observation, not a local decision.

## Remaining implementation

- [ ] Restore prominent CVE triage/action-required UI near the top; offer explicit occurrence + team/environment targets from valid active placements (preserving incoming scope), visible next-action/review status, and a direct route into existing assessment fields. Browsing must not create cases. Avoid sending users back to inventory just to discover how to act. If practical expose the selected review form directly; otherwise make one explicit scoped Open/continue assessment action land at the visible form.
- [ ] Add a distinct local disposition workflow: temporarily suppress/accept risk; not affected with evidence; reopen/revoke. It must actually persist and clearly communicate active versus expired/revoked/stale states, not just save an exception proposal. Keep existing manual-review contract and scanner observations intact.
- [ ] Scope each exception to ONE finding/package-version/image plus case owner/environment and reviewed evidence, NEVER all occurrences of the CVE implicitly. Require reason, evidence/reference for not-affected, and a future expiry/review date (bounded; 90 days maximum is a sensible default). Clearly distinguish risk acceptance from verified not-affected and remediation. No remote scanner API writes, authentication claims, or globally harmless wording.
- [ ] Bind writes to server-owned actor and displayed case/evidence/revision, validate malformed inputs/enums/dates and scope on the server, fail closed on stale evidence or invalid/out-of-scope targets, preserve drafts/errors, and make retries/concurrency safe. Retain history with auditable revocation rather than deletion. Reuse existing safeguards where practical; prefer a dedicated small exception context/schema/component to bloating `Cases`.
- [ ] Surface local decision status on the CVE/detail and review queue/action surfaces consistently. Expired or changed evidence returns to needs-review/action-required. Keep raw inventory, scanner suppression, severity, risk policy, Timeline/import/export facts unchanged; do not silently remove security findings. If a local workflow filter is introduced, label it as local and allow easy inclusion of exceptions. Clarify actual reporting effects.
- [ ] Document a concise operator procedure: choose scope, investigate/evidence, remediate vs timed risk acceptance vs evidenced not-affected, confirm, inspect expiry/staleness/history, reopen. Explain local unauthenticated operator limitations, no remote suppression and no automatic remediation.

## Verification / acceptance

- [ ] New context validation and lifecycle tests cover valid suppression/not-affected/reopen, blank and unsafe reason, missing evidence, invalid/past/oversized date, forged actor/scope/binding, stale evidence, expired decisions, exact scope isolation, unchanged scanner facts, durable history, repeated/conflicting submissions.
- [ ] LiveView tests follow CVE -> explicit scoped action -> existing assessment fields -> local exception save -> visible state/reload/revoke, invalid form recovery, scope tampering and zero writes on GET. Check actual form IDs and server event names mechanically. Unscoped CVE offers explicit valid targets; multi-image/multi-team CVEs cannot accidentally blanket suppress.
- [ ] Verify affected existing CVE/finding/case/queue suites; run project `mix precommit` once after targeted corrections. Build alone is not completion. Record real outcomes and blockers here, not inherited evidence.
- [ ] Direct behavioral probe (LiveView/Plug minimum, actual browser if available safely) proves restored action reachability and exception lifecycle. Browser is not implied by server-side tests.

## Safety and execution notes

Read `app/AGENTS.md` and follow Phoenix form/component/test conventions. Before generating a migration use documented `mix ecto.gen.migration` (read task help first). Inspect working-tree state before editing existing files, preserve unrelated work, no staging/commits/deployments. Fovea impact performed for CVE/finding/cases/inventory; Elixir import graph has coverage gaps, grep/tests are authoritative.

Read `app/OWNED_DB_VERIFICATION.md`: no shared/dev database tests/migrations/seeds. Coordinator alone may run `app/scripts/verify_owned_db.sh`; child executor must not run that wrapper. Read task help before mutating Mix tasks. If tools/owned DB are unavailable, run safe no-start/offline checks and report the exact blocker; do not install packages, touch existing services, or test on working data. No user ports/processes may be changed. Do not modify harness `.pi/` files. Use the configured Monty Python fabric_exec tool path, no nested agents unless explicitly requested.

Initial workspace reads show app with existing deps/migrations/tests and prior verification docs; no shell baseline was run before this first write to avoid the previous prewalk false-positive from `.pi/fabric/mesh/state.json`. The failed earlier handoff did not produce verified implementation; source reads above are the starting truth.
