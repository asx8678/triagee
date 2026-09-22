# Visual concepts — read before implementing

## Included assets

- `triagee-concept.html`: primary interactive design direction from the review. Open directly in a browser. Embedded styles, scripts, and fictional records; no service configuration required.
- `triagee-concept.png`: its supplied 1536 × 1080 screenshot.
- `earlier-blue-work-queue-preview.png`: earlier supplied 1560 × 1060 alternative, kept for context. Its five-column table, wording, and color palette are not a second requirement to combine with the primary direction.

All three are copied from the supplied conversation artifacts without altering their content. The blue preview's HTML was not available in this conversation, so only its image is included. No claim is made that it has an accompanying runnable source.

## What the primary concept demonstrates

Findings and Exceptions with a reporting utility link; a compact findings table; search and scope controls; a shared detail with Action/Evidence/History; exact-deployment selection; a scoped action preview; separate AI draft and evidence; restrained visual hierarchy.

The source examples are explicitly fictional. They are not real CVEs, actual package upgrade advice, deployed service data, provider outputs, or previously approved organizational decisions.

## Prototype shortcuts that must NOT become production behavior

| Prototype behavior | Implementation requirement |
|---|---|
| Opening a CVE selects all its demo deployments | Fresh write selection is empty. Only restore the same user's explicitly saved draft with original fingerprints. |
| One top-level team/environment/status per demo CVE | Real state/filtering is target-local and may be mixed across one CVE. Filter/summarize the exact contributing targets. |
| In-memory arrays and fixed illustrative ordering | Real bounded PostgreSQL/domain reads, a deterministic policy, consistent counts and pagination. |
| A single status field makes views disjoint | Real attention and in-progress views can overlap for overdue work; counts are not additive. |
| AI explanations are embedded strings | Explicit opt-in analysis, validated evidence-bound drafts, failure/staleness states, and manual fallback. |
| Action modal only previews; Investigate shows a demo message | Real supported authenticated domain operations. No fake success notifications. |
| Create/link ticket is one illustrative choice | Preserve existing create workflow; validate actual linking capability before exposing a real link operation. |
| Exception view reuses the four-column list | Implement the register fields in spec 01, with source identity, reviewer, validity, and status. |
| Date validation only checks presence for demo exceptions | Server-side future boundary, exact UTC semantics, scope/evidence validation, and legacy compatibility. |
| Demo snapshot has an accent dot | Production status must represent known source state, not imply complete coverage. |
| Static screenshots contain small text | Use readable production sizes and actual contrast/accessibility checks. |
| No authentication, durable drafts, locks, or service calls | Preserve and test the existing real boundaries; never port the prototype JavaScript into the app as its data layer. |
| Simplified dialog/back/focus behavior | Test keyboard, screen reader, reconnect, long evidence, browser Back, and real mobile flow. |
| Measured prototype overflow at 320 and 390 px (document width 428 px) | Fix the production responsive header/layout; do not treat the preserved prototype as a mobile acceptance baseline. |

The HTML is a design aid, not an approved immutable pixel baseline or a finished implementation. Keep the original reference intact. Put new real-application screenshots in implementation evidence, clearly labeled by commit, fixture, and viewport.
