# Leaf A — implemented

- Read OWNERSHIP first; entire brief and app/AGENTS chunked. No source edits until BASELINE_READY was read.
- Compact navy sidebar, grouped stable routes/IDs, Overview/Activity labels, native mobile navigation disclosure + Escape/focus, skip link, light root.
- One persistent safety notice uses actual endpoint listener configuration and collection build policy. Says **Local workspace**, not unsupported “all synthetic”; preserves no authentication/authorization, display filters ≠ access control, unknown production coverage, and explicit local writes.
- Shared `UIComponents`: page_header, status_badge, technical_value, timestamp, notice, empty_state; imported through html_helpers. Exact escaped values in native disclosures, copy feedback, UTC display with exact original timestamps, explicit missing states.
- Replaced app.css foundations: 16px body/1.5 line height, 15px tables/technical text, ≥14px support, focus/control tokens, all guaranteed primitives, local table scrolling, 60/40 case summary/form/details layout with mobile DOM order. Inspected every B/C/D LiveView's actual classes and reconciled spacing/row headers/forms.
- Registered CopyValue, DirtyDraft, optional FocusReturn. Immediate dirty input/change protection, internal-link confirmation, beforeunload, cancelable Navigation API Back/Forward, explicit draft-saved clearing, no draft/evidence browser storage or form DOM ownership. `data-draft-preserving=true` reserved for B's retained-draft return link. Phoenix HTML vendor still supplies native data-confirm.
- Practical Overview: GET `/findings?q=`, queue action, existing global open/suppressed occurrence counts with units, up to five newest-opened saved cases by case ID, honest unavailable/empty states; secondary tools. Only existing pure-read contexts invoked by controller.
- Core inputs associate errors without replacing help descriptions; flashes remain in document flow; core tables have semantic headings and named keyboard scroll regions.

## Files
`app/lib/triage_web/components/{ui_components.ex,layouts.ex,layouts/root.html.heex,core_components.ex}`, `app/lib/triage_web.ex`, `app/lib/triage_web/controllers/{page_controller.ex,page_html/home.html.heex}`, `app/priv/static/assets/{css/app.css,js/app.js}`, `app/test/triage_web/ui_components_test.exs`.

## Verification / handoff
- Static source ledger: six public symbols + import present; no missing guaranteed CSS primitives; hook registrations present; q GET search correct; existing read APIs; no storage calls. Eight focused component tests written (escaping/exact copy, missing values, UTC/exact timestamps, neutral statuses, semantic patterns/shell, associated errors).
- **No tests, DB, app, browser, aliases, global or targeted format commands run by this leaf.** Coordinator must targeted-format/compile and run the new component test plus home/navigation/assets integration; validate all rendered viewports, contrast, keyboard/zoom, copy success/failure, save/cancel, native confirmations, mobile disclosure after patches, dirty link/history navigation, and no passive writes.
- Existing controller expectations for Home/title/cards/global notice need coordinator update, already reported. No backend, config, logo, dependencies, other leaf files, or .pi writes.
- Limitation: browsers lacking a cancelable Navigation API do not get a same-document Back/Forward interception; full-document unload and clicked navigation remain guarded. No history sentinel/trap was introduced. No accessibility conformance or runtime-test pass claimed.
