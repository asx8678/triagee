# Calmer workspace presentation

## Intent

Make the existing security workspace feel approachable and predictable without
turning it into a playful dashboard or hiding uncomfortable evidence. Keep
Overview, Vulnerabilities, Review, and Timeline in their existing locations.

## Implementation

`app/priv/static/assets/css/workspace-comfort.css` loads after `workspace.css` in
the root layout. It uses the existing `.approved-workspace` and
`.restored-timeline` scopes. The approved baseline and retired styles are not
modified. No JavaScript, runtime dependencies, external fonts, or network assets
are added.

The new layer provides a light header with clearly selected navigation, a neutral
canvas, 12px panel corners, 8px controls, quieter separators, restrained shadows,
and more comfortable text spacing. Primary actions remain blue; real critical
priorities and evidence warnings retain their distinct colours and text.

Overview task items extend their existing single link across the item, including
a keyboard focus-within treatment. Table checkboxes and CVE links remain separate
controls; rows are not falsely presented as a single clickable target.

Review keeps its queue and save footer. On desktop, evidence and decision fields
share one content scroll region rather than two competing scroll regions. The
policy explanation is styled as information, not as an additional warning.
Phones use page scrolling so a fixed-height layout cannot squeeze the findings
table or decision form out of view. The existing queue toggle is preserved.

The inspector uses a lighter backdrop and rounded, inset edges on desktop; it
remains full-screen on phones. Its native dialog behaviour is unchanged. Timeline
sections, jump links, filter controls, and heatmap cell spacing follow the same
visual language; event shapes, recorded counts, and future-day hatching are not
reinterpreted.

## Invariants

No changes to queries, routes, CVE counts, scope selection, risk policy, decision
persistence, confirmation requirements, or evidence semantics. Scanner suppression
and risk acceptance are not reclassified as remediation. Coverage warnings remain
visible, including at narrow widths. Focus indicators, disabled states, reduced
motion, density switching, and print layout are preserved.

## Validation and limits

CSS parsed without syntax errors. A Chromium smoke check on representative static
fixtures passed for Overview, Vulnerabilities, Review, and Timeline at 1600x1000,
1280x800, 768x1024, 390x844, and 320x740. Checks covered outer-page overflow,
visible coverage status and footer, dialog bounds and Escape closing, focus rings,
expanded task-link targets, scope isolation, reduced motion, shared Review
scrolling, and the compact-density toggle.

Those fixtures reproduce relevant inspected markup and baseline styles; they are
not the running Phoenix application. They do not prove end-to-end compatibility,
actual LiveView focus restoration, persistence, or cross-browser behaviour.
Elixir/Mix is unavailable in the editing environment, so `mix precommit` and the
full application suite were not run there. This change should remain a draft
until the real application has been checked.

Before merging, run `mix precommit` from `app`, then check the live workspace with
real records. Exercise filtering, both table densities, queue switching, long
advisory text, long package names, empty states, scrolling to the end of the
Review form, unsaved-draft navigation, save confirmation, inspector close/focus
return, Timeline filter changes, and keyboard navigation. Include a narrow phone,
a short laptop viewport, 200% zoom, and Safari/Firefox. Confirm that critical,
accepted-risk, suppressed, missing-observation, and unknown-coverage states remain
unambiguous.
