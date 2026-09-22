# 02 — UX, visual direction, and interaction contract

## Reference hierarchy

Use `concepts/triagee-concept.html` and its PNG for the calm action-first visual direction. The earlier blue PNG is an alternative, not a second layout to combine. Behavioral details below override the static prototype. No exact pixel-approval is claimed.

Reuse the existing asset pipeline. The concept uses system fonts; do not add remote fonts or a component library. Suggested tokens from the concept: ink `#17252e`, muted `#5e6c75`, border `#dfe5e8`, background `#f6f8f9`, accent `#146653`, caution `#805619`, attention `#aa3d31`. Use color with text, never as the only state signal. These colors are a starting point; verify contrast at the actual text sizes.

Prefer compact tables, one visual accent, restrained borders, small radii, and minimal shadow. Use readable body/table text around 13–14 px, not the prototype's smallest 10–11 px labels as a blanket production rule. Keep dense evidence behind disclosure, not unreadably small. A practical initial desktop detail width is 420–540 px; adapt to available space.

## Findings layout

Header: brand, Findings, Exceptions, configured Grafana utility link; account and data status on the right. No dashboard card wall, large decorative hero, sidebar full of modules, or persistent generic warning banner.

Main region: one heading, search, team/environment filters, the three view tabs, scoped result count, then the table. Show source failures/coverage limitations in one source-status disclosure plus precise per-finding warnings. A recent observation is not proof of complete coverage.

Four columns:

1. **CVE / package:** identifier, package and installed version; compact severity context. Multiple packages expand into package-specific rows in detail.
2. **Affected:** real service when available, otherwise image repository/deployment identifier; environment, owning team, additional matching target count. Never fabricate a service name or ownership mapping.
3. **Why now:** strongest concrete review reason and a short supporting qualifier, such as known exploitation / exposed production, review due, exposure unknown, or verification missing. Source and policy explanation are in detail.
4. **Next action:** specific upgrade/investigation/review/verification step, existing work owner, and existing ticket link. Show actual reported fixed versions by package. For incompatible or multiple version paths show “3 upgrade targets,” not one invented version arrow.

Search must submit on Enter, be clearable without losing team/environment scope, and maintain bounded server-side pagination. Do not claim search covers service names unless the data mapping and query actually do so. Use the actual searchable fields in placeholder text.

## One reusable CVE detail

Desktop: docked alongside the queue with Action, Evidence, History sections/tabs. Scrolling long evidence does not hide the close/back control or active action controls. Avoid two nested scroll areas unless their focus/scroll behavior is tested.

Action: exact affected target summary; the strongest reason for attention; proposed package-specific next step; existing owner/ticket; explicit target selection; optional AI draft; action-specific fields and confirmation.

Evidence: package occurrences, immutable artifact identity, advisory references, installed/reported fixed versions, exposure observations, provenance/timestamps, coverage limitations, and conflicting or missing information. Facts, AI suggestions, and human decisions are visually distinct.

History: append-only decision events and meaningful changes for this CVE/scope. Repeated unchanged observations may be collapsed with their count/time range. Never delete the underlying records. Legacy source IDs, labels, and broader scope remain explicit.

## Interaction flows

**Review a finding:** open a row → inspect evidence → select exact deployments → choose action → supply action-specific rationale/evidence → preview full scope → confirm → see a durable result and updated relevant rows. A normal save does not navigate to a new dashboard.

**New selection:** opening a row does not select every deployment for a mutation. A fresh draft starts with zero write targets and no action. Restoring the same authenticated user's existing draft may restore exactly its original selection and fingerprints. Display the selection count and full target names before committing.

**Filters while editing:** retain the original draft binding. Never silently add, remove, or substitute targets. Either keep the draft with a prominent different-scope warning and an explicit full-scope preview, or offer Keep draft / Discard draft before switching. Hidden targets cannot be committed through a misleading current-filter summary. Clearing search is not discarding a draft.

**Switch CVE / browser Back:** preserve or explicitly discard the draft under the existing durable-draft policy; restore list position/filter state. Do not silently change the pending operation ID. A deep-linked CVE not on the current page still loads independently with its true scope.

**Create ticket:** preview exact destination and payload → explicit Create ticket confirmation → pending state → existing ticket link or reconciliation-required state. Opening the preview sends no POST. An unknown result is not success or permission to retry.

**Exception:** choose Risk accepted or Not affected; display selected targets; require rationale, referenced evidence, and validity/review date. No default claim that infrastructure is unaffected. User identity comes from authentication, not an editable name.

**Report remediation:** require change/deployment evidence and exact targets; display Awaiting verification. Verification is a separate evidence-supported transition, not a cosmetic rename of the old fixed action.

**AI:** explicit Analyze selected scope action, clear information boundary, loading/cancel/failure states, then a draft with cited evidence IDs and gaps. A draft may populate editable proposal fields after the reviewer chooses to use it; it never submits them.

## Responsive and accessible behavior

At wide sizes keep queue and detail side by side. On narrow screens use a full-width detail with Back to findings, not a squeezed second column. Preserve filters and scroll position on return. Adapt rows or use a clearly labeled, keyboard-scrollable table container; never create document-wide horizontal overflow.

Use semantic headings, real labels, visible focus, keyboard-operable rows/actions, and accessible tabs or simpler link navigation. Escape closes transient dialogs and restores focus without discarding work. Trap focus only in actual modal dialogs, not a desktop docked detail. Announce validation errors and pending/result states without stealing focus. Respect reduced motion. Test screen-reader behavior and actual zoom/text spacing separately from viewport resizing.

Viewport matrix: 320, 390, 768, 1024, 1440, 1920 px widths; short-height laptop; long package names, digests, translated/large text, and many targets. Use browser-native zoom checks at 200% and 400%, not just CSS scaling. Check at least Chromium and a second browser when available; document unavailable checks.

## Required empty, degraded, and concurrency states

- No matching results: distinguish filtered emptiness from no imported data; Clear filters preserves deployment scope.
- Inventory/data unavailable: last-success time and actual failure; no “safe” or “all clear” success state.
- Unknown exposure or ownership: explicitly unknown; do not infer internal, unused, or low risk.
- AI not configured / timeout / invalid output: manual workflow remains usable; preserve the draft; no approval message.
- Grafana not configured: accurate utility state; no fake destination.
- Zero selected targets: action cannot commit on client or server.
- Stale evidence / changed artifact / role revoked / conflicting save: reject or require refreshed review; preserve original evidence and draft.
- Ticket outcome unknown: persistent reconciliation guidance and operation identity; no generic retry button.
- Expired/invalidated exception: visible reason and reassessment action, without deleting history.
- Long or mixed-scope CVE: show complete target/package membership; paginate visible evidence without truncating mutation evidence.

## Copy rules

Prefer “Risk accepted until …,” “Not affected — assessed scope,” “Remediation reported,” “Awaiting verification,” “Verified remediated,” and “Exposure evidence missing.” Avoid “Safe,” “AI approved,” “Fixed” for unsupported observations, generic confidence percentages, and “No vulnerabilities” when collection is unavailable. Temporary milestone features must be honestly labeled unavailable; final acceptance must not rely on placeholder success.
