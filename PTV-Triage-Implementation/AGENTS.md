# Instructions for implementation agents

These instructions apply to the entire PTV Triage redesign task, including work delegated to other agents.

## Objective

Implement the already accepted UI in the existing application. The target is `reference/approved/ptv-triage-prototype.html`, not a verbal approximation. Open it, exercise it, and inspect the extracted CSS before changing code. Read `START-HERE.md` and the numbered specifications.

## Design rules

- Preserve four top destinations, the compact shared scope bar, flat navy/white/blue/orange visual identity, exact panel geometry, typography hierarchy, tight tables, and the single-screen review workspace.
- Reuse the accepted CSS values and SVG geometry. Do not substitute a component library's default theme, radius, padding, shadow, typography or sidebar navigation.
- Keep 3px panel/control corners, 1px borders, the 52px desktop navigation row, 46px desktop scope row and the reference responsive breakpoints. Token exceptions are enumerated in the visual spec.
- Keep review and inspector actions structurally outside their scroll bodies. Do not make the user scroll to the end of evidence to save, close or review.
- Match on the same deterministic fixture and viewport. Real production text may differ; that is not permission to alter the layout.
- Never edit approved assets, CSS, expected screenshots or fixture assertions to excuse an implementation mismatch.

## Functional rules

- Modify the real app using its existing architecture unless a documented blocker makes that impossible. Do not ship a new demo app, iframe the reference, or route production to synthetic records.
- Complete the repository audit before adding domain mutations or migrations. Preserve data/history and the existing local/no-sign-in mode.
- CVEs, package occurrences, images and deployment scopes are different units. Shared-team counts are not additive. Metric drilldowns must return the exact contributing IDs/scopes.
- Scanner suppression is not accepted risk. Accepted risk does not remove an active vulnerability. A reported fix, closed ticket or disappearing record is not verified remediation.
- Decision targets are explicit, stable scope IDs. A production-only decision must not change staging. Draft targets never expand silently.
- Local work saves and external ticket creation are separate confirmed operations. Navigation must not fetch intelligence, create tickets, run AI or transmit service context unexpectedly.
- Bind real supported actions. An unimplemented action must not claim success or write an approximate substitute state.
- Treat self-declared operator names as self-declared; do not invent authentication or approval authority.

## Delivery rules

Work phase by phase using `specification/10-IMPLEMENTATION-SEQUENCE.md`. Each phase supplies changed files, tests, screenshots, real data mappings and rollback notes. Run browser-based visual comparisons; do not stop at a successful build or unit tests.

Do not ask for a new aesthetic direction. For a genuine blocker, state the exact affected requirement and safe options, continue independent work, and document the unresolved decision. Avoid destructive migrations, silently discarded work, framework rewrites or assumptions about external credentials.

The final delivery must demonstrate real Overview → team drilldown → CVE inspector → production-only decision → queue return → scoped history, with no lost context and no hidden primary action. Report outstanding limitations honestly.
