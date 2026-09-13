# Leaf W1 — foundations, Overview, Findings, Activity

## What changed
- **#1 severity ramp** (`app.css`): each severity now has a distinct treatment — CRITICAL 2px solid + bold 700, HIGH 2px solid, MEDIUM 2px dashed, LOW 2px dotted, unknown/neutral 1px solid. Fill tints also differ. Badge text labels unchanged.
- **#2 Overview** (`page_html/home.html.heex`): counts are real links — `#overview-open-link` → `/findings`, `#overview-suppressed-link` → `/findings?suppressed=1` (param confirmed in `TriageWeb.FindingFilters`: `suppressed` truthy values `1|true|on`, canonicalised to `"1"`). Recent cases now show assessment state from existing queue data (`row.latest_review`, `row.review_status`), with a `· revalidation needed` qualifier when `:needs_revalidation`.
- **#4 Activity** (`whats_new_live.ex`): `#feed-banner` and the old `#event-time-context` merged into one `<.notice id="feed-banner">` retaining both meanings. Event rows get `event-item-appeared` (accent edge) / `event-item-resolved` (muted) classes. Record-ID ordering statement kept.
- **#5 Finding detail** (`show.ex`): breadcrumb eyebrow = `Findings / {CVE ID}`; identity strip occurrence moved into a plain block (`<p>Occurrence #N</p>`) instead of a space-between trailing span; `finding-identity-strip` keeps 1rem/1.5rem gaps.
- **#8 mobile safety** (`layouts.ex` + `app.css`): `environment-summary` collapses to the bold line under 760px; the full text (incl. "Live collection is disabled. Production coverage is unknown.") remains in `#safety-details`. Desktop visible layout unchanged.
- **#11 Findings** (`index.ex`): `#findings-summary` moved inside `#filter-form.filter-toolbar` (`.filter-toolbar > .filter-summary` flex child) instead of a separate line.
- **#14 Activity** (`whats_new_live.ex`): server-side relative time rendered next to the exact `<time>` in `#event-relative-{id}` (`05 Aug 2026, 06:00 UTC · 5 weeks ago`). No JS date libs.

## New/updated contracts
- `TriageWeb.UIComponents.technical_value/1` — new attr `variant` (`"default"` | `"compact"`). Compact renders `.technical-value-compact` + `.technical-compact`, label is `sr-only`, and keeps the same ids: `#{id}-full`, `#{id}-copy`, `#{id}-feedback`. Usage: `<.technical_value id="image" label="Image digest" value={v} variant="compact" />`. Missing value → "Not captured", no copy button.
- `TriageWeb.UIComponents.assessment_state/1` → `"No assessment recorded"` | `"Assessment recorded"`.
- `TriageWeb.UIComponents.relative_time/1,2` → `"5 weeks ago"` | `"in 10 minutes"` | `nil` (unparseable/missing). `relative_time(value, now)` is injectable for tests.
- CSS classes added: `.status-badge-neutral`, `.technical-value-compact`, `.technical-compact`, `.finding-identity-strip`, `.event-item-appeared`, `.event-item-resolved`, `.environment-summary`.

## Badge contrast (#1)
Borders are drawn in the text colour, so border↔bg = text↔bg; text↔border is 1:1 by design. All text↔background and border↔background ratios:

| Level | text | bg | text↔bg | border↔bg | border↔page white |
|---|---|---|---|---|---|
| CRITICAL | #7a1119 | #fbdde0 | 8.60 | 8.60 | 10.93 |
| HIGH | #6f2a0f | #ffe9dd | 8.91 | 8.91 | 10.43 |
| MEDIUM / warning | #5c3d00 | #fff5dc | 9.11 | 9.11 | 9.89 |
| LOW | #23406b | #eaf1fb | 9.16 | 9.16 | 10.41 |
| unknown / neutral | #3b4c62 | #edf1f6 | 7.73 | 7.73 | 8.76 |

All ≥ 4.5:1 (lowest 7.73).

## Tests
- `app/test/triage_web/ui_components_test.exs`: severity-ramp class test, compact `technical_value` contract, `relative_time/2` values, `assessment_state/1`, shell `environment-summary` + `#safety-details` text.
- `app/test/triage_web/inventory_readability_test.exs`: `#findings-summary` asserted inside `#filter-form`; new breadcrumb + occurrence-in-identity-strip test.
- New `app/test/triage_web/overview_readability_test.exs`: count links and the `suppressed=1` param; recent-case assessment state.
- New `app/test/triage_web/activity_readability_test.exs`: single merged notice, event-type classes, `#event-relative-{id}`.

## CSS requests for coordinator
None from W1 — `app/priv/static/assets/css/app.css` is W1-owned and was updated directly.
W2's requested `.assessment-actions` sticky-bar rules (`leaf-w2.md`) are left to the coordinator
per the plan's "final CSS additions requested in leaf notes" ownership.

## Limits
- "Assessment recorded" is unit-tested via `assessment_state/1`; only the "No assessment recorded" overview path is integration-tested.
- Desktop expanding Safety details now repeats the one-line collection caveat that the mobile span hides.
