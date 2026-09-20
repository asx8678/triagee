# PTV Triage — approved redesign implementation package

**Prepared for Adam · 19 September 2026 · Design lock v1.0**

## The assignment

Modify the existing PTV Triage application to implement the approved interface in this package. This is an implementation and integration task, **not another design exploration**. The accepted HTML, its CSS, and the matching screenshots are the visual target. Preserve the application's real data, history, supported actions, local-workspace behavior and safeguards.

The expected result is the actual application, rebuilt around **Overview → Vulnerabilities → Review → Timeline**, with one shared scope bar, one CVE inspector, and the single-screen review workspace. A second standalone mockup is not a delivery.

## Hand this to the implementation agent

1. Put this complete directory somewhere readable next to the application repository. Do not copy demo files into public production routes.
2. Give the agent access to the existing repository and this package.
3. Paste `IMPLEMENTATION-AGENT-PROMPT.md`. It requires no framework assumption or production credentials.

The agent starts with the repository audit, then executes the gated implementation plan. Routine implementation choices do not need another design approval. A real data-loss risk, irreconcilable domain conflict, missing authorization or material departure from the accepted visuals must be recorded and resolved rather than guessed.

## Open the accepted design

- `reference/approved/ptv-triage-prototype.html` — interactive, offline, self-contained accepted reference. Open in a browser.
- `reference/approved/previews/` — the seven previews delivered with the accepted design, preserved byte for byte.
- `reference/baselines/index.html` — gallery of 32 clean reference renders, including all inspector tabs, review dialogs, timeline views and breakpoint states.
- `reference/baselines/*.json` — corresponding measured geometry and computed styles.
- `reference/source/approved-exact.css` — exact CSS extracted from the accepted HTML.
- `reference/source/approved-readable.css` — the same rules formatted for reading.
- `reference/assets/` — extracted brand and icon assets; no font binaries.

No screenshot in this package is evidence that the production application has already been changed. All new baseline renders use the accepted synthetic fixture.

## Reading order

| Order | File | Purpose |
|---|---|---|
| 1 | `AGENTS.md` | Non-negotiable instructions for every agent/subagent. |
| 2 | `IMPLEMENTATION-AGENT-PROMPT.md` | Complete execution prompt and reporting requirements. |
| 3 | `specification/01-DESIGN-LOCK.md` | Source precedence, exact-match expectations and allowed production differences. |
| 4 | `specification/02-REPOSITORY-DISCOVERY.md` | Trace the existing code/data before editing. |
| 5 | `specification/03-VISUAL-SYSTEM.md` | Exact geometry, colors, typography, scroll ownership and assets. |
| 6 | `specification/04-SCREEN-BY-SCREEN.md` | Page and component implementation specifications. |
| 7 | `specification/05-INTERACTION-CONTRACTS.md` | Every operator action and its side effects. |
| 8 | `specification/06-DOMAIN-AND-DATA.md` | Correct counts, scope, evidence, decisions and histories. |
| 9 | `specification/07-PRODUCTION-INTEGRATION.md` | Port the design into the current stack; do not ship demo architecture. |
| 10 | `specification/08-RESPONSIVE-AND-ACCESSIBILITY.md` | Boundary widths, keyboard behavior, fixed actions and readable content. |
| 11 | `specification/09-STATE-AND-ERROR-CATALOG.md` | Loading, empty, stale, failed, conflicting and partial-success states. |
| 12 | `specification/10-IMPLEMENTATION-SEQUENCE.md` | Small vertical slices, completion gates and rollback. |
| 13 | `specification/11-ACCEPTANCE-AND-VISUAL-QA.md` | Tests, visual comparisons and definition of done. |
| 14 | `specification/12-DELIVERY-AND-SIGNOFF.md` | Required final implementation evidence. |
| 15 | `specification/13-REFERENCE-LIMITATIONS.md` | Prototype shortcuts that must not become production behavior. |

`contracts/` contains machine-readable fixture, expected sets, visual cases, locator mapping and acceptance scenarios. `templates/` contains the audit, phase log, deviation register, test evidence and final report templates. `qa/README.md` explains the executable tools.

## Fast checks

From this directory:

```bash
python qa/verify_package.py
python -m venv .venv
. .venv/bin/activate
python -m pip install -r qa/requirements.txt
python -m playwright install chromium
python qa/test_reference.py
python qa/test_fixture_contract.py
python qa/capture_reference.py --output qa/results/local-reference
```

On Windows, activate the virtual environment using its `Scripts` directory instead. A locally installed Chromium can be selected with `--browser`; see tool help. Browser installation may require normal OS dependencies; the tools do not install system packages automatically.

Do not replace approved baselines to make a failing implementation comparison pass. `qa/results/` is the output directory for new evidence.

## Scope boundary

No real application repository was supplied or inspected for this package. Framework, schema, routes, authorization and integrations must be confirmed in the target repository. The design contains Elixir-related context in legacy screenshots, but this is **not** permission to assume a particular Phoenix/LiveView version, adopt React, add login, change providers, or replace the backend.

The package's QA report describes only the tools and reference checks actually run. Application tests, migration validation and production visual conformance remain the implementation agent's responsibility.
