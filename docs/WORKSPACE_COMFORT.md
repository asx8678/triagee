# Calmer workspace presentation

## Intent

Make the security workspace approachable and predictable without making it
playful or hiding evidence. Overview, Vulnerabilities, Review, and Timeline
remain in their existing locations.

## Implementation

`app/priv/static/assets/css/workspace-comfort.css` loads after `workspace.css` in
the root layout. It uses the existing `.approved-workspace` and
`.restored-timeline` scopes. The baseline stylesheet remains unchanged. No
application JavaScript, runtime dependencies, external fonts, or network assets
are added by the theme.

The layer provides a light header, clear selected navigation, neutral canvas,
12px panel corners, 8px controls, quieter separators, restrained shadows, and
more text spacing. Critical priorities and evidence warnings retain their text
and distinct colours.

Overview task items extend their existing single link across the item with a
focus-within treatment. Table checkboxes and CVE links stay separate controls.
Desktop Review keeps its queue and save footer while evidence and decision
fields share one scroll region. On phones, page scrolling keeps the table and
form reachable. The existing queue toggle remains intact.

The inspector has a lighter backdrop and inset rounded edges on desktop; it is
full-screen on phones. Timeline sections, jump links, filters, and heatmap
spacing follow the same visual language without reinterpreting event shapes,
counts, future-day hatching, or unknown coverage.

## Invariants

The theme does not change queries, routes, CVE counts, scope selection, risk
policy, persistence, confirmations, or unsaved-draft logic. Suppression and risk
acceptance are not remediation. Coverage warnings remain visible. Keyboard
focus, reduced motion, density switching, and print remain supported.

## Validation

The earlier statement that reconstructed-fixture smoke checks had passed was
not backed by saved execution evidence and has been removed. Do not treat it as
a test result.

The initial PR run compiled the app and passed its formatting gate, then stopped
at Credo complexity checks in two unchanged functions:
`WorkspaceLive.handle_params/3` and `WorkspaceRedirectController.show/2`.
That run did not reach the test suite. No Elixir/Mix runtime is installed in the
local editing environment, so `mix precommit` was not run there.

A separate `workspace-ui` workflow now prepares an isolated, demo-seeded Phoenix
app, runs `workspace_live_test.exs`, and runs
`scripts/check_workspace_ui.py` with pinned Playwright 1.57.0. It does not submit
decisions. It captures real-app screenshots and records pass/fail measurements
in the workflow artifact's `report.json`; adding the workflow is not itself a
claim that these checks have passed.

The browser checks cover four screens at six viewport sizes, live density and
queue toggles, inspector bounds and Escape, expanded task links, visible
coverage status, document overflow, focus indication, and reduced motion.
Before/after Overview screenshots use the same live data by disabling only the
new stylesheet. Test tooling is CI/development-only, not an application
runtime dependency.

Keep the PR in draft until the actual run and manual review are satisfactory.
The smoke check is not a full accessibility audit or browser compatibility
certification. Before merging, also inspect long/empty records, scope changes,
unsaved drafts, save confirmations, inspector focus return, Timeline filters,
200% browser zoom, Firefox, and Safari.
