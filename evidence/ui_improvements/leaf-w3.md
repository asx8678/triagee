# Worker W3 leaf note — Imports + Replay + Replay History

Owned files edited: `app/lib/triage_web/live/import_live.ex`,
`app/lib/triage_web/live/replay_live.ex`,
`app/lib/triage_web/live/replay_history_live.ex`,
`app/test/triage_web/tools_readability_test.exs`.
Round-1 redesign preserved; no backend/config/deps/routes, no passive writes.
Preview/nonce/ack/apply, run/save boundaries and all event handlers are unchanged.

## #6 file inputs (imports + replay)
Wrapped the real `<.live_file_input>` in the already-existing `.triage-upload` wrapper and
added `class="file-input"`. The actual file input stays visible and natively focusable;
label association (`for={@uploads.*.ref}`) and `aria-describedby` are intact. No upload
callbacks, `auto_upload`, size limits or consume/cancel logic touched.

## #6 step indicator (presentational)
Both indicators now emit `id={"<tool>-step-N"}`, `data-step-state`
(`complete` / `current` / `upcoming`), a `step-item step-<state>` class list and an
`aria-hidden` `✓` marker on completed steps. State comes only from the existing
`current_step/1`; `aria-current="step"` stays on the active step only. No new assigns.

## #9 First page disabled
On `/replay/history`, when `@cursor == 0 and is_nil(@error)` the control is a real
`<button id="replay-history-first" disabled aria-disabled="true">` (no patch/navigation).
When paged (`cursor > 0`) or in an error state (so First page remains the read-only
recovery action), it is the existing `<.link patch>`. No handler changes.

## #9 Inline receipt counts
Added inline `<span data-receipt-count="<label>">` entries inside each receipt `<summary>`,
projected from `row.result.counts` through an allowlist (`key_counts/1`); values already
render `Unavailable` when absent. LIMITATION: `Triage.Replay.Run.summary` persists counts
`owners`, `images`, `findings`, `suppressed`, `actionable` only — there is **no
"advisories" and no "changes" count** in the receipt data. Inline shows Owners, Images,
Findings, Suppressed findings; "Would be actionable in replay" remains in the expanded
`summary_panel`. No counts were invented.

## CSS requests for coordinator (W1 owns `app.css`)
`.triage-upload` already exists; please add the file-button + step-state polish:
```css
.triage-content input.file-input { padding: .375rem; }
.triage-content input.file-input::file-selector-button {
  margin-right: .75rem; min-height: 2.25rem; padding: .4rem .9rem;
  border: 1px solid var(--triage-accent); border-radius: var(--triage-radius);
  background: var(--triage-accent); color: #fff; font: inherit; font-weight: 600; cursor: pointer;
}
.triage-content input.file-input:hover::file-selector-button { background: #173c92; color: #fff; }
.step-list .step-complete, .step-list .step-marker { color: #1f5c3d; font-weight: 700; }
.step-list .step-upcoming { color: var(--triage-muted); }
```

## Tests (element/ID-based)
`tools_readability_test.exs`:
- `assert_step/3` now also asserts exactly one `[data-step-state='current']`, `step-1`
  `[data-step-state='complete']`, and `4-step` `[data-step-state='upcoming']`.
- New "import and replay file inputs stay labelled and keyboard operable": exactly one
  `input[type=file]` per form, class contains `file-input`, `.triage-upload` present,
  `label[for=<input id>]` matches, and the input is not `disabled`/`tabindex=-1`/`hidden`.
- New "first page control is disabled on the first page and enabled after paging" (button
  disabled at cursor 0, link after paging, disabled again after clicking First page).
- History browsing test asserts inline `[data-receipt-count='Findings']` and
  `[data-receipt-count='Suppressed findings']` inside each receipt summary.

## Verification
`mise exec -- elixir -e 'Code.string_to_quoted!(File.read!(f))'` (run from `app/`) passes
for all four edited files. No `mix`/compile, no DB, no network, no git. HEEx validity is
left to the coordinator's compile.
