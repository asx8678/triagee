# Workspace UI/UX review

## Scope and evidence

Reviewed the running Overview, Vulnerabilities, Review, Timeline and News screens,
their Phoenix components and events, and the shipped workspace stylesheet.
The existing login, authorization and deployment boundaries were not changed.

### What already works

- Five clear top-level destinations, with deep links and scoped navigation.
- Real tables and explicit review actions rather than decorative dashboards.
- Server-enforced roles, durable per-user drafts, and recorded decision identity.
- A useful distinction between local deployment evidence and public advisories.
- Confirmation and reconciliation for Azure operations, and stale-evidence checks.

### Problems observed

- At an emulated 390px phone width, the document expanded to 407px. Controls were
  clipped and the account header consumed unnecessary vertical space.
- Four primary screens had no level-one heading. The inventory browser title
  also differed from its navigation label.
- Timeline repeated the global team/environment controls. Nine equally styled
  summary cards competed with the actual timeline.
- The inventory search was about 190px wide on a large screen. Its form handled
  change but did not explicitly handle Enter submission; filter clearing was not
  offered. The row-density control did not describe its state.
- The review queue exposed only CVE IDs. Generic policy and placeholder evidence
  blocks repeated information without helping identify the next item.
- Decision status was duplicated, an empty selection still offered an enabled
  action button, and “Cancel” did not clearly describe discarding a saved draft.
- Success notifications used a large centered panel, a page-dimming shadow and
  an entrance animation despite not being modal dialogs.
- “Data & settings” contained explanations, not editable settings.

## Implemented

- A bounded responsive shell, compact native account menu with Escape/outside
  dismissal, all five navigation links fitting at 320px, and visible focus on
  the dark header. No new JavaScript hooks or dependencies.
- One level-one heading per screen without adding redundant visual heading rows.
- A calm overview with a direct review action, precise metric units, side-by-side
  team/priority tables on desktop, and detailed caveats behind “About these numbers”.
  Priority rows now show their decision state as well as their severity.
- A wider search, explicit Enter handling, scope-preserving Clear filters,
  accessible active-view/density states, keyboard-scrollable tables, descriptive
  empty states, and visible result ranges. “Research a CVE” no longer implies
  adding a confirmed local vulnerability. Whitelisted rows are not remediation-green.
- Package and severity context in the queue; selecting another CVE returns from
  the mobile queue to its assessment. “Back to decision” remains available.
- Actual reported fix values in place of generic placeholders, with the warning
  that deployment is not verified. Core evidence and exact deployment selection
  remain available; policy explanation is progressively disclosed.
- Explicit Discard draft wording and zero-target guidance with disabled submission.
  Discard retains its existing safe semantics: it clears the draft and selection;
  the user must select deployments again before saving. No automatic target expansion.
- Compact, dismissible, non-modal success notifications and smaller saved-state
  banners. Existing timing, live announcements and durable result states remain.
- One shared timeline scope; hidden form values preserve it when changing the
  window/scale. Reset window no longer clears team/environment in the workspace,
  including recovery from an invalid window.
  Three concise primary totals replace nine competing cards; all other totals
  remain in Observation breakdown. Standalone timeline behavior is preserved.
- A truthful Data & help panel with short sections. Removed review styling that
  was accidentally scoped inside the timeline and therefore did not apply.

## Verification

- An initial 82-test focused run and a final 45-test timeline/recovery run passed.
- Full precommit suite: **1,167 passed, 2 skipped**. Compilation, formatting,
  strict Credo and Dialyzer passed.
- Chromium checks across **20 screen/viewport combinations**: five screens at
  320, 390, 768 and 1440px. No page-width overflow; all primary navigation fits;
  one main heading per screen; review submission remains within the viewport.
- Browser interactions verified: account popup bounds and Escape, Enter search,
  Clear filters retaining scope, density state, keyboard table scrolling,
  mobile queue selection, and timeline window/reset retaining scope.
- Browser review did not save decisions, create tickets, or alter inventory.
  Mutation behavior was exercised in disposable test databases.
- Final wrapping/focus adjustments passed the responsive browser matrix. Invalid-
  window change/reset recovery was also verified directly in Chromium after the
  final full suite. Existing unrelated `.pi/` state was not edited.

## Remaining opportunities

- Agree on consistent “whitelist” versus “accepted risk” terminology across the
  domain, timeline, imports and documentation before renaming individual controls.
- The timeline is still a dense analytical view. Keep its accessible lane table
  and recorded-observation caveats if adding simpler views later.
- Cross-browser and hands-on colleague feedback remain useful; the direct visual
  checks in this review used Chromium, not a Safari/Firefox compatibility matrix.
