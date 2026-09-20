# 08 · Responsive behavior, keyboard access and persistent actions

## 8.1 Responsive thresholds are locked

Use the actual CSS media queries, not framework-default breakpoints.

| Width | Layout behavior |
|---|---|
| ≥1750px | Page horizontal gutters32px; review queue310px and decision350px; wider dashboard proportions. |
| 1151–1749px | Page gutters24px; queue278px, gap14px; decision300px beside evidence. |
| ≤1150px | Page padding16px18px; queue234px; evidence and decision stack in one scroll region; compact top navigation. |
| ≤850px | Queue215px; dashboard panels stack; compact navigation/meta and reviewed footer behavior. |
| ≤640px | Two-row/wrapping navigation and scope; metrics2×2; queue OR assessment toggle; page padding14px12px. |

Boundary cases are supplied at1749/1750,1150/1151,850/851,640/641. Also test1920×1080,1600×1000,1366×768,1280×720,1024×768 and390×844. The reference's wide breakpoint is inclusive `min-width:1750px`; narrow queries are inclusive `max-width`.

Mobile is not a compressed three-column desktop. The review Queue toggle switches one primary pane; preserve the draft/selected record while switching. Inspector stays right-aligned at the accepted `min(780px,96vw)` width until expanded; the slightly visible underlying edge is intentional.

## 8.2 Scroll ownership

Desktop shell fits the dynamic viewport. Overview/inventory page content can scroll. Review page's header/tools remain in its shell allocation; review grid has `min-height:0`. Queue scrolls independently. On wide layouts evidence and decision have their own scroll containers. On stacked layouts the combined content scrolls. Footer is a sibling, never inside these bodies.

Inspector: fixed viewport-height dialog, header/tabs/body/footer grid; only body scrolls. Confirmation modal may have a bounded body with footer outside it. Do not position a transparent fixed button bar over content without adequate scroll/focus accommodation.

Charts/tables can scroll horizontally inside their region. The outer document must not gain a horizontal scrollbar at the supported widths. Long strings cannot force the shell wider. Keep the scrollbar gutter treatment from the reference so the page does not jump when opening a different view.

## 8.3 Essential actions and the prototype's narrow-footer shortcut

Save & next, inspector Close, Expand/restore and Review this CVE must remain visible and usable during content scroll. Save decision must also remain available without forcing an unwanted advance. The reference hides the secondary Save button between641px and850px; do not ship an inaccessible save-without-advance operation as a side effect of copying that selector.

Use the smallest corrective reflow within the existing footer (wrapping the existing buttons when needed, rather than changing the desktop composition). Record the narrow-screen delta with screenshot evidence. Keep all baseline-desktop sizes unchanged. Do not add a new decision wizard or large action panel to solve this.

At200% zoom, content should reflow into the appropriate narrow layout and all primary actions remain reachable. A viewport resize test is not a complete zoom test; perform actual browser zoom too. Test mobile virtual-keyboard opening and date inputs; `100dvh` alone is not evidence that every keyboard/browser combination is correct.

## 8.4 Keyboard and focus

Use native links for navigation, buttons for actions, labels for fields and semantic tables for data. Maintain logical focus order from navigation/scope to page controls and current content. Provide a visible skip link to the primary region. Tab order must not jump behind a modal or into hidden responsive panes.

When a dialog opens, place focus on a useful control or heading according to the task. Keep focus within the top modal. Escape closes only that modal; canceling an exception does not close the entire review. On close return focus to the actual opener if it remains, otherwise a stable logical replacement. Do not routinely dump focus into the top navigation after a local detail interaction.

Tab switches preserve focus and expose the selected state appropriately. Use a valid tabs keyboard pattern if implementing ARIA tabs; otherwise ordinary navigation links/buttons with unambiguous active state are preferable to incorrect ARIA. Queue selected state is available beyond color alone.

Errors link to fields and are announced without clearing the draft. Saving state is conveyed by text/progress as well as disabled styling. Success toasts use a noninterruptive status announcement; critical validation/conflict messages remain visible near the form and are not only transient toasts.

Search shortcut `/` and optional queue shortcuts must not run while typing, editing a rich text field, using a native selector or interacting with a modal. Keyboard users can reach all functionality without shortcuts. Nonvisible search at compact widths must have an accessible alternative, not a keybinding targeting a hidden input.

## 8.5 Readability and targeting

Preserve reference type sizes instead of globally shrinking text to fit. Long values may be abbreviated only with a discoverable keyboard-accessible full-value/copy interaction. Important versions, CVE IDs and dates must not split character-by-character.

Do not reduce click targets to the16px checkbox drawing. Its label/hit area remains usable. Ensure icon buttons have accessible names; decorative SVGs are hidden from assistive technology. Severity, priority, warning and event type have labels/shapes as well as color.

Verify text/control contrast against actual rendered backgrounds, including badges, muted tiny labels, focus outlines, selected rows and disabled controls. This package's tests do not constitute a full accessibility-conformance audit. Correct a measured contrast problem minimally and record it; do not assume a supplied color automatically passes every combination.

Respect reduced motion. The reference has no essential animated transition. Do not add hover-only critical actions, pulsing alarms or decorative motion. Native date/select controls vary by platform; test readability and provide proper labels rather than replacing them with an untested custom widget for superficial pixel identity.

## 8.6 Timeline access

Every plotted event must be reachable through a complete event log, with the same filters/scope/window. Markers should be keyboard-focusable or have an equivalent accessible event selection without hiding records. Tooltip-only content needs a non-pointer path. Sticky date/label layers must not obscure the focused event.

Heatmap cells expose date, count unit, coverage state and availability; not just color. Future and unknown-coverage states are distinct in text. Coverage gaps are not announced as zero findings. Document whether the chart itself is decorative with a full table alternative or semantically interactive, then implement that approach consistently.
