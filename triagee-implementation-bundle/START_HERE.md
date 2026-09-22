# Triagee: action-first redesign — implementation handoff

**Version 1.0 · 22 September 2026**  
**Repository:** `asx8678/triagee`  
**Source baseline:** `33bc06f2dc46932a69b1e07ea35ffd87b223756a`

[Open the local bundle index](index.html) · [Master agent prompt](IMPLEMENTATION_AGENT_PROMPT.md) · [Primary concept](concepts/triagee-concept.html)

## The intended result

Turn Triagee into a decision workspace: **which CVE needs attention, where is it present, and what happens next?**

Use two primary workspaces, **Findings** and **Exceptions**, with **Grafana** as a reporting link. Merge inventory, review, and inspector into one findings table and one actionable CVE detail. Keep evidence, exact scope, authenticated decisions, and durable ticket recovery. Reduce repeated screens and repeated decisions, not auditability.

This package is the implementation brief for the redesign discussed with the owner. It is not an implemented application, a security certification, or evidence that application tests passed. Product and interface proposals are distinguished from repository observations in `references/REPOSITORY_REVIEW.md`.

## Hand this to the implementation agent

1. Extract the ZIP into the repository as `handoff/triagee-action-first/`, or provide the extracted directory as a readable attachment. Do not overwrite the older `PTV-Triage-Implementation/` package.
2. Give the agent **`IMPLEMENTATION_AGENT_PROMPT.md`**. It contains the full assignment and reading order. For a shorter launch instruction, use the text below.
3. The agent should inspect the current checkout, record drift from the source baseline, then implement in the milestones in `spec/04_IMPLEMENTATION_PLAN.md`. Do not stop after producing another plan.

### Copy-paste launch instruction

```text
Implement the Triagee action-first redesign using the attached/extracted
triagee-implementation-bundle (or handoff/triagee-action-first).
Start with START_HERE.md, then IMPLEMENTATION_AGENT_PROMPT.md and
DECISIONS_AND_PRECEDENCE.md. Inspect the actual repository and applicable
agent instructions before editing. Execute the core milestones in order,
with tests and real application screenshots. Preserve scoped evidence,
authentication, history, durable drafts, and ticket reconciliation.
Do not build a separate demo or copy synthetic prototype data into the app.
Use the existing Phoenix LiveView/Ecto/PostgreSQL stack. Treat live external
calls, credentials, production data changes, and deployment as separate
owner-authorized operations. Report exact blockers and continue independent
work. Do not claim a check passed unless you ran it.
```

## Reading map

| Location | Purpose |
|---|---|
| `IMPLEMENTATION_AGENT_PROMPT.md` | Master execution prompt; use this first. |
| `DECISIONS_AND_PRECEDENCE.md` | Settled direction, earlier-package conflicts, prototype limitations. |
| `spec/01_PRODUCT_SCOPE.md` | What to remove, merge, retain, and defer; queue semantics. |
| `spec/02_UX_AND_DESIGN.md` | Screens, flows, responsive behavior, copy, error states. |
| `spec/03_DOMAIN_AND_SAFETY.md` | Scope, decision lifecycle, validation, concurrency, priority policy. |
| `spec/04_IMPLEMENTATION_PLAN.md` and `tasks.json` | Ordered, bounded work with dependencies and acceptance IDs. |
| `spec/05_AI_ASSISTANCE.md` | AI draft architecture, contract, limits, and privacy boundary. |
| `spec/06_GRAFANA_CONTRACT.md` | Shared reporting semantics, counting units, drilldowns. |
| `spec/07_MIGRATION_AND_ROLLOUT.md` | Compatibility, migration rehearsal, release and rollback. |
| `concepts/` | Self-contained interactive concept, screenshot, earlier alternative. |
| `prompts/` | Phase prompts, review prompt, continuation prompt, AI runtime prompt. |
| `contracts/` | Proposed JSON schemas and synthetic AI examples. Not existing APIs. |
| `qa/` | Acceptance catalog and deterministic semantic fixtures. |
| `references/REPOSITORY_REVIEW.md` | Pinned source map and verification limitations. |
| `templates/IMPLEMENTATION_REPORT.md` | Evidence-based reporting template. |
| `tools/validate_bundle.py` | Bundle integrity, JSON, references, and optional schema validation. |

## Scope boundary

**Core:** M0 discovery, M1 one findings workflow, M2 typed exceptions and verification, M3 opt-in AI assistance and a shared reporting boundary. M3 must remain usable without external credentials. Live-provider validation may be blocked without blocking the rest of the implementation.

**Later, not part of the default build:** remediation campaigns/grouped tickets, automatic intelligence ingestion, broad exposure/reachability collection, EPSS integration, a general chat product, new dashboards, or a frontend rewrite.

The blue earlier preview is context only. The green interactive concept is the primary visual direction, with the behavioral corrections listed in `concepts/README.md`. Neither is production code or a pixel-perfect acceptance baseline.

## Check this package

```sh
python3 tools/validate_bundle.py
# Also require full JSON Schema example validation, when jsonschema is installed:
python3 tools/validate_bundle.py --require-jsonschema
```

The validator does not start Triagee, access a database, call AI/Azure/Grafana, or certify application behavior. Its only inputs are files inside this bundle.
