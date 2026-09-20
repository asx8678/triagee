# 02 · Repository discovery and mapping

## 2.1 Do not start from a guessed stack

The screenshots show local operation and an Elixir-style command in evidence text. This does not establish the target repository's frontend framework, data schema, package versions, deployment model or authorisation. The accepted reference is standalone HTML only for portability.

First find the application root, its own `AGENTS.md`/README/development instructions, lock files, entrypoints, routes, layout components, styles, tests and data fixtures. Check the working tree and preserve unrelated user changes. Do not run production imports, modify external integrations or destroy local data during discovery.

Safe initial commands, adapted to the actual repository:

```bash
pwd
git status --short
git branch --show-current
git ls-files | head -100
rg --files -g 'AGENTS.md' -g 'README*' -g '*lock*' -g 'mix.exs' -g 'package.json' -g 'pyproject.toml'
rg -n 'Action required|Previous assessments|Triage|Timeline|Open assessment' .
```

Exclude vendor/build/secret directories where appropriate. Never paste credentials or full secret configuration into the audit. Use the repository's actual test commands after examining its setup; do not install a replacement framework to simplify the task.

## 2.2 Required inventory

Document actual files/routes for the global shell, vulnerabilities list/detail/occurrence detail, old and new review routes, wizard steps, previous assessments, saved reviews, timeline, statistics, data tools, settings and intelligence receipts. Map each visible legacy control to its handler and backend operation.

Trace query functions and any duplicated computation for distinct advisory totals, active occurrence totals, suppression, team/environment ownership, review eligibility, priority and first/last observations. Identify whether current filters apply to advisory IDs alone or correctly narrow underlying scopes.

Find persistence for advisory identity, aliases, package occurrences, immutable image identity, deployments/placements, scan coverage/runs, suppression source flags, human assessments, exceptions, assignments, external ticket links and recorded events. Where concepts share one field today, document the limitation rather than silently inferring facts.

Inspect existing local identity/author attribution. Determine whether typed names are self-declared. Inspect authorization only where it actually exists. Do not add login simply because the user described opening the app as “logging in.”

## 2.3 Trace a real-shaped record end to end

Use an existing development fixture or isolated copy, never production mutation without the user's explicit operation. Choose a CVE present in production and staging. Identify stable advisory/occurrence/placement IDs and the selected scope predicate. Follow it through list → detail → review → local decision → history → timeline and record which layers currently lose scope or context.

Run a second read-only trace for a scanner-suppressed record with unknown approver/date, and a third for disappearance without verification. Confirm whether the current UI incorrectly uses “Whitelisted” or “Fixed.”

For imports, establish whether absence is inferred from complete comparable scans or merely a missing row. Find completeness, target coverage, observed-at and ingested-at. A timestamp of the last import alone cannot establish complete current coverage.

## 2.4 Integration and side-effect inventory

List every network boundary: scanner ingestion, intelligence refresh, Azure DevOps, AI CLI/provider, telemetry and remote static assets. Identify what runs on page render, user click, scheduled job and explicit confirmation. Record local work-save and remote work-item submission transactions separately.

Do not execute integrations during the redesign to prove a button works. Use test doubles or a sanctioned sandbox. Mark existing limitations in duplicate prevention, unknown remote results, partial success and retry behavior.

## 2.5 Deliverables before implementation

Fill `templates/IMPLEMENTATION-AUDIT.md`. Include the route/component map, entity/state dictionary, field/query mapping, current test baseline, screenshots, risky mismatches, feature-flag seam, migration plan and rollback constraints. Use actual paths rather than the conceptual component names in this package.

Record the smallest viable vertical slice: one team's scoped inventory → reusable inspector → scoped local decision → history. The audit must identify enough backend support to complete it with real data.

**Gate A:** The agent can explain precisely what the existing app means by a CVE, occurrence, image, placement, assessment scope, suppression, exception and fixed state. Unknowns are named. No irreversible migration or model rewrite has begun.
