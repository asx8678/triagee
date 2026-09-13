# Worker W2 leaf note — Review Queue + Review Case

Owned files edited: `app/lib/triage_web/live/case_live/show.ex`,
`app/test/triage_web/case_readability_test.exs`. `case_live/index.ex` unchanged (see #7).
Round-1 redesign preserved: every hidden binding input (`meta[case_id]`,
`meta[expected_revision]`, `meta[expected_snapshot_id]`, `meta[idempotency_token]`),
`DirtyDraft`/`FocusReturn` hooks, confirmation dialogs, stale-revision/rebind/discard
flows and `#review-form` attrs are byte-for-byte unchanged.

## #3 Evidence limitations (show.ex)
Replaced the four stacked caveat paragraphs in the evidence column with one labelled block:
- `#evidence-limitations` (`aria-labelledby="evidence-limitations-heading"`), heading
  "Evidence limitations", visible summary line "Frozen local snapshot — not live inventory,
  production freshness, verified remediation or mitigation evidence."
- Full text (frozen-evidence caveat, suppressed-in-capture note, no-longer-observed note,
  coverage warning) inside `#evidence-limitations-details` (`<details class="disclosure">`).
Still always visible: package/version, "Reported fixed version", `#case-assessment-state`,
and the `#evidence-stale` / `#source-out-of-scope` / `#source-missing` notices. No text removed.

## #10 Assessment form (show.ex)
- All four fields now carry a visible `*` in the label and a semantic `required` attr:
  "Applicability *", "Priority *", "Next action *", "Rationale *". Legend
  "All four fields are required" kept, so the semantics stay truthful.
- Save/discard cluster wrapped as `#assessment-actions.cluster.assessment-actions`,
  still holding `#save-review-btn` (and `#discard-draft-btn` when dirty).

## #7 Queue Image column — SWITCH NOTE for coordinator
`evidence/ui_improvements/leaf-w1.md` (and the whole `evidence/ui_improvements/` dir) does
not exist, and `TriageWeb.UIComponents.technical_value/1` exposes only `id`/`label`/`value`
(no `variant` attr). Per plan fallback I kept the existing `technical_value/1` call in
`case_live/index.ex` (`#queue-image-<id>`); no code change was possible without W1's compact
variant. Coordinator: once W1 lands `variant="compact"`, switch that call to it.

## CSS requests for coordinator (W1 owns `app.css`)
`app.css:44` currently states "no sticky content ... to obscure focus"; #10 intentionally
requires a desktop sticky action bar. Please add:
```css
@media (min-width: 769px) {
  .assessment-actions {
    position: sticky; bottom: 1rem; z-index: 5;
    background: #fff; border-top: 1px solid var(--triage-border);
    padding-top: .75rem;
  }
  /* keep the sticky bar from covering a focused field */
  #review-form .fieldset { scroll-margin-bottom: 6rem; }
}
@media (max-width: 768px) { .assessment-actions { position: static; } }
@media (prefers-reduced-motion: reduce) { .assessment-actions { position: static; } }
```
Optional: `.evidence-limitations` spacing already comes from `.stack` / `.disclosure`.

## Tests (element/ID-based)
Added 3 tests in `case_readability_test.exs`:
`#evidence-limitations` + `#evidence-limitations-details` visible caveats and preserved
`Package · installed version` / `Reported fixed version` / `#case-assessment-state`;
`#review_<field>[required]` for all four fields plus the `*` labels and
`#assessment-actions #save-review-btn`; queue `#queue-image-<id>` inside the row.

## Verification
`mise exec erlang elixir -- elixir -e 'Code.string_to_quoted!(...)'` passes for both edited
files. HEEx validity is left to the coordinator's compile (no `mix` run by W2).
