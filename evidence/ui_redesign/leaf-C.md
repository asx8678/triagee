# Leaf C — Findings and Activity

Implemented only after reading `BASELINE_READY`; exact disjoint ownership retained.

## Implemented
- `app/lib/triage_web/live/finding_live/index.ex`: compact filters and explicit reset/result scope; all-local occurrence counts separate from matching advisories; semantic scroll-region table showing full aggregate package/image/occurrence/team counts, highest scanner severity, reported-fix fraction, first observation and reopened/suppressed flags. Representative link names its occurrence. Original SQL aggregation, whole-advisory package search and ordering are unchanged.
- `app/lib/triage_web/live/finding_live/show.ex`: current occurrence identity/scope/version/fix precede the explicit case action; current inventory distinguished from frozen case evidence; precise missing data, exact/copyable image/source values, escaped descriptions, scoped placements, readable observation history and related occurrences. Existing open-case event/server scope guards retained; native confirmation added.
- `app/lib/triage_web/live/whats_new_live.ex`: Activity heading, structured event list, recorded event facts separated from joined current metadata, placement ownership warning, meaningful timestamps, page-only counts and original record-ID pagination. Optional independently validated `activity[from/owner/environment/before]` return context survives detail/related navigation without supplying finding or saved-case scope. Existing deep links and inventory back links remain supported.

## Regressions and verification
- New `app/test/triage_web/inventory_readability_test.exs`: 7 tests covering aggregates/search/order, invalid/empty recovery, scope/deep links, exact values, escaped hostile data, disappearance semantics and browsing purity.
- `app/test/triage_web/live/whats_new_live_test.exs`: 3 additional tests covering backdated ID order, changed metadata vs recorded facts, exact timestamps/copy values, duplicate-placement deduplication, pagination/filter resets, feed-detail-feed return and read-only purity; existing heading/link expectations updated.
- Static `git diff --check` for owned paths passed. Mechanically confirmed shared layout/header APIs, stream containers, original Inventory/Activity entry points, explicit Cases action, independent return-context validation and absence of raw HTML/inline styles.
- **Tests, formatter, app, DB and browser were not run**, per coordinator ownership. Coordinator: targeted-format these five files; run the above tests plus existing dedicated finding index/input/scope tests and shared integration coverage. Browser-check confirmation cancellation, full-value copy, keyboard/320px table containment and Activity cursor return.

## Contracts / limitations
Uses guaranteed shared components and CSS primitives only; no cross-owner CSS/JS edits. Confirmed same-origin `phoenix_html.js` supplies native confirmation; coordinator must verify behavior. Scanner identity/collection-run provenance is unavailable on occurrence records and labelled as not captured; no invented metrics or freshness. Shared global safety notice replaces repeated page banners. No screenshot or accessibility-conformance claims from this leaf.
