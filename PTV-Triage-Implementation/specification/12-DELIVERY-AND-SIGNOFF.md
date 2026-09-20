# 12 · Delivery and sign-off evidence

## What must be delivered

The actual modified application repository, not only an HTML demo. Include a concise implementation report pointing to changed code, tests, screenshots, field/query mappings, migrations, compatibility routes, feature-flag behavior and rollback. Use the provided template; keep evidence paths real and reproducible.

The completed package should show both the accepted synthetic fixture for visual comparison and representative real-shaped application data for semantic correctness. Do not expose secrets or production-sensitive data in screenshots/artifacts.

## Required demonstration

Start on Overview with the shared scope. Open a team's decision count and demonstrate that the returned advisory/target set matches. Open a CVE inspector, change sections, expand/restore and return without losing position. Enter review for that same CVE, select production only and save a local work decision. Staging remains unresolved; active exposure is unchanged. Navigate away and back with a separate draft to prove preservation. Inspect the scoped history/timeline and demonstrate that no external ticket/AI operation occurred.

Then show a temporary exception with Cancel and Confirm; unknown scanner suppression; expired exception; disappearance without verification; a save conflict; integration disconnected; partial/unknown external result through a test double; and action visibility at laptop/mobile/zoom conditions.

## Evidence inventory

Include route/component map; metric predicate and unit mapping; action-to-handler map; legacy-data migration reconciliation; tests by acceptance ID; original and actual screenshot paths; overlay/diff artifacts; geometry comparison results; supported-browser/environment details; outstanding deviations and their approval state; before/after changed file list; rollback commands/steps based on the actual repository.

Never mark an item “pass” when it was only manually inspected in the reference. “Implemented but not tested,” “blocked,” and “not supported” are valid honest statuses and must be separated from completed.

## Completion wording

Report exact counts of tests run/passed/failed/skipped and link to outputs. Distinguish reference checks from application checks. Report visual tolerance/environment and any approved deviations. State which integrations used test doubles and which operations were actually exercised in a sanctioned environment.

Do not claim a ticket was created unless there is a real test remote ID/link and operation result. Do not claim authenticated approval in a local no-sign-in app. Do not claim old data was preserved unless reconciliation/migration evidence exists. Do not use a screenshot of the reference as if it were the rebuilt app.

## Rollback

Use additive schema changes where appropriate, backward-compatible reads and a reversible route/feature flag. Keep old data and legacy IDs intact through cutover. Record exactly which new writes remain readable after rollback. A UI toggle alone is not a rollback plan for an incompatible database migration.

If a rollback cannot restore old behavior after new decisions are written, stop the migration until compatibility is designed. Avoid retaining two independently mutable decision systems that can diverge. Test rollback on an isolated copy and keep the old interface read-only where needed during cutover.
