# PTV Triage — precision UI redesign

Prepared for Adam · 19 September 2026

## The decision

Keep four primary destinations: **Overview, Vulnerabilities, Review, Timeline**. Move setup and diagnostics into **Data & settings**. Put the operator's current team/environment scope directly below the main navigation and use that same scope everywhere.

Replace the mandatory four-page review wizard with a single review workspace: **queue → evidence and affected scope → decision**. Keep the primary actions outside the scrolling content. Preserve the observation timeline, but separate it from its event log and secondary daily-activity analysis.

The visual direction is crisp, compact and operational: flat white surfaces, narrow borders, 3px corner radii, navy navigation, restrained orange branding and blue actions. Red, amber and green communicate specific meanings rather than decorate every component.

## Open the prototype

Open `ptv-triage-prototype.html` in a modern desktop browser. It is a self-contained HTML file; there are no packages to install, remote fonts, CDNs or external API calls.

The file uses entirely synthetic records named `DEMO-2026-…`. Its fixed sample clock is 19 September 2026 at 10:00 UTC. The numbers are not reconciled production totals from the screenshots, and package names are not upgrade advice.

Browser policy may restrict local-file storage. The prototype detects unavailable storage and falls back to session-only edits. On a normal supported origin it attempts to store sample decisions, drafts and saved views in that browser. Do not enter secrets or production data. Reset sample state under **Data & settings → Reset synthetic data**.

## What works

The four main destinations, shared team/environment filters, metric and team drilldowns, vulnerability search and severity filters, priority/age sorting, multi-selection, review-selected workflow, JSON export, in-session saved views, the large CVE inspector, inspector expansion and history tabs, queue navigation, explicit affected-scope selection, decision validation, local demo decisions, confirm-before-accepting-risk, next-item navigation, decision history, timeline window/type controls, clickable observation markers, accessible event log, and daily-activity drilldowns are interactive.

Drafts are retained when moving between queue items within this prototype. The review and inspector action bars remain visible while their content scrolls. On narrow screens, review switches between the queue and the assessment rather than compressing three columns onto a phone.

The Azure DevOps preview explains the intended production handoff but cannot create a ticket. AI assistance is intentionally unavailable. The prototype makes no external requests.

## Read these files in order

| File | Purpose |
|---|---|
| `01-DESIGN-SPEC.md` | Screen-by-screen audit, hierarchy, layouts, interactions and visual specification. |
| `02-DOMAIN-AND-STATE-CONTRACTS.md` | Count definitions, scope, observation versus decision versus verification, and data-confidence rules. |
| `03-IMPLEMENTATION-PLAN.md` | Small implementation slices, migration constraints and completion gates. |
| `04-ACCEPTANCE-TESTS.md` | Production acceptance scenarios, responsive/accessibility expectations and regression cases. |
| `05-AGENT-PROMPT.md` | Copyable implementation-agent instructions. |
| `design-tokens.json` | Starting visual tokens corresponding to the prototype. |
| `QA-REPORT.md` | What was actually checked, and what has not been validated. |

The `previews` directory contains rendered screenshots of the working prototype. `test_prototype.py` and `test-results.json` document the browser interaction tests.

## Important boundaries

The prototype is a visual and interaction reference, not production architecture. It uses a deliberately small client-side fixture and simple rendering. Do not copy its storage model, sample policies, fixed time, identifiers, or synthetic exposure assertions into the real application.

No application repository was inspected or modified. The screenshots suggest an Elixir-related command interface, but the actual front-end stack and data schema have not been verified. The first implementation step is a repository and state-model audit, not a framework replacement.

The design is a proposal informed by all 17 supplied screenshots. It does not determine whether the user's real systems are safe, vulnerable or compromised.
