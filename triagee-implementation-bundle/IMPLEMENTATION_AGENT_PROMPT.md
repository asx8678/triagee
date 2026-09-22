# Master implementation-agent prompt

You are implementing the action-first redesign of `asx8678/triagee` in its real, existing application. This is a product simplification and a bounded decision-workflow improvement, not permission to rewrite the stack or create a separate prototype.

## Outcome

Deliver **Findings + Exceptions**, with Grafana for reporting. Findings combines inventory, review, and inspector in one workflow. The default view is Needs attention. Every row makes the CVE/package, affected deployment, reason for attention, and concrete next action obvious. A shared CVE detail supports Action, Evidence, and History. AI prepares evidence-backed drafts only. All decisions remain exact-scope, authenticated, auditable, and explicitly confirmed.

## Read before editing

Read this package's START_HERE, DECISIONS_AND_PRECEDENCE, specifications 01–04, concepts/README, and references/REPOSITORY_REVIEW. Read the remaining specifications before their corresponding tasks. Inspect applicable repository instructions, current README/runtime/owned-database guidance, the existing tests, and the old PTV implementation package where requirements conflict.

The reviewed baseline is `33bc06f2dc46932a69b1e07ea35ffd87b223756a`. Record `git rev-parse HEAD`, `git status --short`, and relevant drift. Preserve unrelated and uncommitted work. Do not reset the checkout to the reviewed commit. Do not modify `.pi/` or unrelated tooling state.

The new information architecture intentionally replaces old requirements to preserve Overview/separate Review/News/global Timeline as primary destinations. Do not alter immutable historical references to hide that change. Applicable operational/security instructions still apply. Record any unresolved instruction conflict; continue work that is not affected by it.

## Execute, do not merely advise

Use `tasks.json` and `spec/04_IMPLEMENTATION_PLAN.md`. Complete M0, M1, M2, and M3 in small, reviewable increments. The optional later task is not in scope. At each milestone, run relevant tests, inspect the real application with synthetic data in an owned environment, and update an implementation report using the supplied template. Do not stop at a written plan, an attractive screenshot, or a compilation pass.

Start with current behavior and characterization tests. Verify mappings before renaming domain fields or adding migrations. Reuse Phoenix LiveView, Ecto, PostgreSQL, existing authorization, read models, commit boundaries, durable drafts, and ticket operation recovery. Extract shared components only where they eliminate actual duplication. Do not introduce React, a new API backend, a generic policy engine, a broker, a vector database, or a new design system to complete this work.

## Non-negotiable boundaries

- One row may summarize a CVE, but a mutation binds to exact `{CVE, placement}` targets and complete package evidence. Never whitelist a CVE globally from this UI.
- No action and no write targets are selected by default in a new draft. Restoring a user's saved draft is allowed only with its original explicit targets and fingerprints.
- A filter is not authorization. Validate the principal, target set, server-captured evidence fingerprints, operation ID, and action fields at the server commit boundary.
- Unknown exposure, missing observations, scanner suppression, a closed ticket, and reported fixes are not proof of safety or verified remediation.
- Risk accepted and not affected are distinct assessments. Preserve legacy labels and provenance; do not guess what old whitelist comments mean.
- Exceptions require scope, rationale, evidence references, and a future validity boundary. New typed decisions require compatible readers and migration tests.
- No automatic AI approvals, ticket creation, configuration changes, collector runs, scanner suppression, or external calls caused by ordinary navigation.
- Durable ticket claims and unknown-outcome reconciliation must survive UI changes. No blind retries, new operation IDs to evade a pending claim, or network calls while holding database locks.
- Do not destroy observations, case history, legacy exception records, or old decision meanings. Do not conflate case stores with workspace advisory decisions.
- Test writes use only owned disposable resources following current repository guidance. Never adopt an existing development/production database or kill unrelated processes.
- No secrets, provider credentials, real customer inventory, or sensitive traces in screenshots, fixtures, prompts, commits, or reports.

## Visual implementation

Open `concepts/triagee-concept.html` and exercise its search, filters, tabs, detail, target selection, exception register, and action preview. Use its calm layout and hierarchy, not its synthetic data, embedded JavaScript, simplified state model, or default target selection. Read the prototype gap list before porting anything. The blue alternative is historical context, not a second design to merge.

Build the actual LiveView UI. No iframe, production demo routes, fake success notifications, hard-coded counts, invented services, invented fixed versions, or static AI text presented as real analysis. Unsupported actions must be unavailable with an accurate reason, not wired to approximate states. Final core acceptance requires the specified actions to be real; temporary milestone limitations must be explicit.

## Testing and evidence

Use `qa/acceptance-cases.json` as the new acceptance catalog and map preserved older requirements; do not erase unresolved historical security gates. Use deterministic fixtures with a frozen clock. Test both PostgreSQL query projection and application projection for counts, scope, priority, and expiry parity. Test event-level authorization and malformed requests, not only disabled buttons.

Run repository quality commands under current owned-resource rules. Record exact commands, exit status, source SHA, fixture, and screenshots. For unavailable checks, write BLOCKED or NOT RUN and why. Mocked adapters are not live service validation. Bundle validation is not application validation.

Review 320, 390, 768, 1024, 1440, and 1920 pixel widths, keyboard navigation, long evidence, zoom/text-spacing, reconnects, errors, empty states, and mixed-scope records. Do not claim accessibility certification from viewport checks alone.

## Delivery

Return changed-file summary, completed task/acceptance IDs, behavior demonstrated in the real app, source and test evidence, migration/reconciliation results, rollback instructions, remaining blockers, and next operational steps. No automatic push, production migration, deployment, or live ticket creation unless separately authorized by the owner.

Proceed with sensible defaults stated in the specifications. Ask only for genuinely unresolved security/compatibility or external-service requirements; do not ask for another general design direction. Continue independent work while a blocker is unresolved.
