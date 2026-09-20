# 03 · Visual system, exact geometry and CSS port

## 3.1 Use code values, not an approximate interpretation

Authoritative: `reference/source/approved-exact.css`. Convenience: `approved-readable.css`. The JSON beside each baseline records `getBoundingClientRect()` and computed styles at that viewport. The global CSS is a design reference; scope/reorganize it safely in the real app rather than globally breaking unrelated screens.

Keep the reference's border-box sizing. Use tabular numerals for counts/age, system monospace for package versions/digests, and readable full values for long identifiers. Do not substitute default framework styles after applying the tokens.

## 3.2 Exact core palette

| Token in accepted CSS | Value | Purpose |
|---|---|---|
| `--ink` | `#17263c` | Main text |
| `--muted` | `#57677c` | Supporting text |
| `--line` | `#d5dde7` | Main borders |
| `--paper` | `#ffffff` | Panels |
| `--bg` | `#f3f5f8` | Workspace background |
| `--navy` | `#15243a` | Navigation |
| `--blue` | `#2554ce` | Primary action/focus |
| `--blue-soft` | `#edf3ff` | Selected/background accents |
| `--orange` | `#f66b29` | Brand/navigation underline |
| `--red` | `#b52832` | Urgent/critical signal |
| `--red-soft` | `#fff0f1` | Urgent background |
| `--amber` | `#8c5a0b` | Unknown/warning/exception |
| `--amber-soft` | `#fff7e7` | Warning background |
| `--green` | `#196945` | Verified-positive outcome |
| `--green-soft` | `#edf7f1` | Verified-positive background |
| `--purple` | `#7144a7` | Re-observation |

Some components use intentionally more specific values; copy their actual declarations. Examples: Critical badge foreground/background/border `#a51d2b / #ffedef / #edc4ca`; High `#954506 / #fff1e5 / #edcfb0`; Medium `#805700 / #fff7df / #e8d9a5`; Low `#3c6485 / #edf4fa / #cfdfed`. The P1 badge is filled red with white text. Severity and work priority remain separate concepts.

Do not recolor every table cell by severity. Do not use green for a newly detected vulnerability. Do not interpret red as proof of compromise. The subtle timeline grid/hatching is functional evidence encoding; retain it even though decorative gradients are not wanted.

## 3.3 Typography

Exact stack: `Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif`. Body: 14px, line-height 1.45. Page title: 24px/1.2, weight 700, letter-spacing −0.65px. Section h2: 16px, letter-spacing −0.2px. Normal h3: 14px. Selected review title: 19px, letter-spacing −0.4px. Inspector title: 22px, letter-spacing −0.5px. Metric: 31px, weight 700, line-height 1.3, letter-spacing −1px. Table body 12px, header 11px. Secondary table metadata 11px. Tiny labels 10px only where the reference uses them.

Do not assume the first family in the stack is installed. Match the renderer/font environment when comparing pixels. The package deliberately includes no font binaries and adds no network font dependency. Preserve the application's correctly licensed local font delivery if available, then compare measured line wraps.

Avoid a universal font-weight or font-size override. Reference weights include 550, 600, 650 and 750; browser fallback may resolve them differently. Measure the rendered result rather than rounding everything to a different style system.

## 3.4 Shell and page

Desktop shell: `height:100dvh; display:grid; grid-template-rows:52px 46px minmax(0,1fr) 26px; min-width:320px`. These are navigation, scope, content and status. Desktop navigation padding `0 24px`, gap 32px. The brand is 18px with 27px mark. Navigation tabs are full row height with a 3px active orange bottom border.

Scope row: white surface, bottom border, 12px gap and `0 24px` padding. Selects are 30px high/min-height with 12px type; max-width175px. Small controls here intentionally differ from standard 34px controls. Dataset indicator is separated by a vertical divider. Data-health control sits at the right on normal desktop.

Base page: `padding:20px 24px 24px; min-height:0; overflow:auto; scrollbar-gutter:stable; scroll-padding:20px`. At ≥1750px horizontal page padding is32px. The actual usable width includes the browser's reserved scrollbar gutter. Do not force the right margin to24px by removing that reservation.

Status row:26px, muted flat background `#eaf0f6`, top border, 10px text. In production replace demo claims with truthful local workspace/source information; do not remove the row or imply simulated data is live.

## 3.5 Panels, controls and states

Panels: white,1px `--line` border,3px radius, overflow hidden. Panel heading14px16px padding; body16px; footer9px16px. No default card shadow. Confirmation dialogs are a deliberate exception:4px corners and the reference modal shadow. Inspector drawer has0px radius and a left border.

Standard button:34px minimum height, `6px 11px` padding,3px radius,1px border, font-weight600, line-height1.2. Icon button:34px width. Reference icons17px with1.6 stroke and rounded stroke joins. Use the extracted SVG paths; do not use emoji as icon replacements.

Primary button:blue fill/white text; hover `#1945b7`. Quiet button:transparent border/background; hover `#e9eff8`. Disabled controls use opacity .52 and a non-action cursor; still supply an adjacent reason where the user needs to understand unavailability.

Inputs/selects/textareas:34px min-height, `7px 10px` padding, border `#b9c5d4`,3px radius. Decision form field type12px. Textarea base min-height76px; decision textarea86px. Checkbox visible mark16px; the surrounding label/target provides usable hit area.

Focus:2px solid blue outline,3px offset; checkbox offset6px. Keep focus styling visible on dark navigation and modal layers. State/badge corners2px, not rounded pills. Table selected background `#edf3ff`, hover `#f7f9fc`.

## 3.6 Overview composition

Page heading and compact actions; attention/confidence callout; four metric buttons; primary two-column panels; secondary panels. Metrics gap12px, margin-bottom18px; metric padding13px16px, min-height100px. Alert-top metric has3px top border and compensating top padding11px. Count must not jitter layout as digits change.

Base dashboard grid: `minmax(0,1.4fr) minmax(330px,.85fr)`, gap 16px. Wide ≥1750px: `minmax(0,1.65fr) minmax(400px,1fr)`. At ≤1150px: `minmax(0,1.25fr) minmax(320px,.9fr)`. At ≤850px the columns stack. At ≤640px metrics become2×2.

Team-table row height44px, padding7px vertically. Use the accepted restrained ownership mini-bars and square team initials. Do not replace them with decorative charts.

## 3.7 Review geometry and scroll contract

At1151–1749px: review grid `278px minmax(0,1fr)` with14px gap. Workspace grid rows `auto minmax(0,1fr) auto`. Inside: evidence `minmax(0,1fr)`, decision300px. Queue, evidence and decision each own their appropriate scrolling; the workspace footer is not inside them.

At≥1750px: queue310px, decision350px. At≤1150px: queue234px and decision stacks below evidence in one scrollable content region. At≤850px queue215px. At≤640px queue is hidden until explicitly selected; assessment occupies full available width.

Review heading padding14px17px12px. Evidence/decision padding16px. Decision surface `#f8fafc`,1px left border on side-by-side layouts. Queue item min-height89px, padding12px; active item3px blue left border and9px left padding to compensate. Compact queue items min-height79px and9px vertical padding.

Footer min-height58px, padding11px15px, white background, top border. Commit buttons remain reachable. The primary action must not be absolutely positioned over form content. Required structural pattern, translated into the actual stack:

```css
.review-workspace {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr) auto;
  min-height: 0;
}
.review-content { min-height: 0; overflow: hidden; }
.evidence-column, .decision-column { min-width: 0; overflow: auto; }
```

For the actual1600×1000 baseline, the review grid starts at x24/y229.1875; queue width 278; workspace x316, width1245; decision width300; footer y899, height58. These are validation anchors, not absolute coordinates to hardcode. Responsive layout must generate them naturally.

## 3.8 Inspector and timeline

Inspector default width `min(780px,96vw)` and expanded `min(1240px,100vw)`, height/max-height100dvh, right anchored. Its grid is header/tabs/minmax(0,1fr)/footer. Header padding19px20px15px, body18px20px, footer12px20px. Mobile padding changes are in the exact CSS. Background dimming is intentional; do not add blur.

Timeline labels215px; plot minimum530px; complete timeline min-width745px. The plot owns horizontal scrolling, not the outer page. Sticky labels and date header share a coherent stacking order. Heatmap max-width1100px;12 columns plus day-label column in the12-week view. Do not reintroduce the original wide empty container.

## 3.9 Component stylesheet strategy

Implement one shared definition of severity badges, priority badges, buttons, data tables, scope bar, disclosures and action rows. Map tokens into the existing styling mechanism. Replace arbitrary local overrides with these primitives; do not duplicate CSS values independently across screens.

Use `min-width:0` on shrinking grid/flex children and `min-height:0` on bounded vertical regions. Assign one clearly documented scroll owner per content region. Test long content before changing widths. Compare screenshots after each component batch, not only after the whole application is rewritten.
