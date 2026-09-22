# Decision log and precedence

## How to read this handoff

This package carries forward the redesign recommendations the owner requested to hand to an implementation agent. The choices below are the working defaults for implementation, not claims that the current app already behaves this way. Verify code mappings during M0.

Within this handoff, behavioral specifications and safety invariants take precedence over the illustrative HTML and images. `tasks.json` controls scope/dependencies; numbered specifications define the behavior; the acceptance catalog checks it. Screenshots are visual direction, not executable truth. Repository operational and security instructions remain applicable.

## Settled direction

| ID | Decision |
|---|---|
| D01 | Primary navigation is Findings, Exceptions, and a configured Grafana link. Settings/account remain utility navigation. |
| D02 | Findings is the landing page; Needs attention is its default view. |
| D03 | Inventory, Review, and inspector share one actionable CVE detail. No parallel read-only and writable copies. |
| D04 | Four primary table columns: CVE/package, Affected, Why now, Next action. Owner/ticket sit within Next action. |
| D05 | History stays beside its CVE. Global Timeline is removed from daily navigation, not erased from storage. |
| D06 | Public News is removed from daily navigation. Relevant, sourced intelligence may appear on matching findings. |
| D07 | Existing backend evidence, authentication, exact scope, durable drafts, history, and ticket recovery are retained. |
| D08 | Exceptions distinguish risk acceptance from not-affected assessments. Neither is remediation. |
| D09 | New drafts have no preselected action, no prewritten conclusion, and no automatically selected mutation targets. |
| D10 | Reporting distinguishes observations, assessments, work, and verified outcomes. Grafana owns aggregate visualizations. |
| D11 | AI drafts are optional, explicit, evidence-bound, and untrusted until reviewed. No autonomous suppression. |
| D12 | Stay on Phoenix LiveView/Ecto/PostgreSQL. No framework replacement, generic agent dashboard, or new backend. |
| D13 | Shared-remediation grouping is a later enhancement, not another screen in this implementation. |
| D14 | Source facts are never invented to fill UI gaps. Unknown values remain explicit. |

## Earlier requirements that need reconciliation

The repository contains `PTV-Triage-Implementation/AGENTS.md`, historical visual fixtures, and a larger acceptance package. Its instructions include a four-destination design and an older visual identity. Current app documentation describes five destinations and newer authenticated behavior. The new two-workspace design is intentionally different. Sources are pinned in references/REPOSITORY_REVIEW.

| Earlier requirement or assumption | Treatment in this task |
|---|---|
| Preserve Overview and a separate Review workspace | Superseded by Findings and one shared detail. Record the mapping. |
| Preserve original navy/blue/orange geometry exactly | Superseded as visual direction by the green concept; functional/accessibility guarantees survive. |
| Prove parity by only matching old screenshots | Replace obsolete layout assertions with new screenshots; retain safety and scope assertions. Do not edit historical assets to conceal differences. |
| Global Timeline is a primary destination | Hide from primary navigation. Preserve read-only legacy deep links until an equivalent report/export transition exists. |
| Local actor text represents identity / historical no-sign-in assumptions | Do not downgrade current authentication. Preserve the current controlled local development shortcut and production restrictions, verified in source. |
| Old whitelist means the CVE is not applicable | Do not infer this. Preserve as legacy accepted risk unless an explicit new assessment supplies evidence. |
| Old `fixed` records are verified remediation | Do not infer this. Display legacy reported remediation separately from verified outcomes. |
| Old acceptance/security items can be closed by a new general suite | False. Map each retained requirement. Unavailable original security findings remain unresolved. |

If an applicable agent instruction creates a genuine authority conflict, identify the exact file and rule rather than silently ignoring it. Continue unaffected implementation. This package does not authorize deleting old instruction files or weakening security requirements.

## Practical defaults that are proposals

Use a seven-day exception review lead time, UTC validity semantics for new workspace decisions, and a versioned deterministic action-priority policy. These are documented defaults, not asserted organizational policy. Make them testable in one place rather than building an administrative policy editor. Preserve legacy time-boundary metadata exactly.

For a missing Grafana URL, show an accurate unconfigured utility state rather than a dead external link. For absent AI configuration, the manual workflow remains complete. No live credentials are required to implement or test the core features.
