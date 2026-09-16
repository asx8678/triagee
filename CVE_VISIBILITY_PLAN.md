# CVE visibility — review and plan

Date: 2026-09-15. This is a review of the current UI against one question: **is the CVE
itself the visible unit of the product?** No code was changed to produce it. Scope is
UI/UX only: no new routes, no invented data, no colour-only signalling, and no claim that
is stronger than the evidence behind it.

The baseline is the shipped round-1 redesign and round-2 improvements
(`UI_REDESIGN_REPORT.md`, `UI_IMPROVEMENTS_REPORT.md`). Everything recorded below as
already working is verified against source, not assumed from those reports.

## 1. What already works (do not redo)

- **The CVE leads the identity of four surfaces.** Findings rows (`finding_live/index.ex:373-375`),
  queue rows (`case_live/index.ex:306-317`), the case page title
  (`case_live/show.ex:617`) and the advisory page title (`cve_live/show.ex:56`) all
  begin with the advisory id, linked, with the scanner severity beside it.
- **The advisory id reaches its aggregate from every one of those surfaces** — the
  cross-link work of the previous session (`#case-cve-<id>`, `#finding-cve-action`,
  `#event-cve-<id>`, `#tl-lane-cve-<cve>`, `#tl-drawer-advisory`), each carrying the
  display scope of the view it was opened from.
- **Search already accepts a CVE id.** `Inventory.apply_group_search/2`
  (`inventory.ex:800-812`) matches `lower(f.cve) like ?` or any affected package, and the
  moduledoc states the group-level rule at `inventory.ex:186-187`.
- **The Overview leads with CVE-bearing tables** — critical advisories and newest
  advisories (`home.html.heex:135-200`) — and the recent-cases list titles each case with
  its CVE (`home.html.heex:238-247`).
- **Absence is handled honestly everywhere.** A blank captured id renders as text, never
  as a broken link; KEV language on the advisory page already says absence from the cache
  never means "not known exploited" (`cve_live/show.ex:298`); the Overview states that a
  refresh has not populated the cache rather than showing zero.

## 2. The gaps, ranked

### G1 — Exploitation status is invisible outside one page (the sharpest gap)

`known_exploited` appears in exactly one module, `cve_live/show.ex` (lines 9, 88-98, 298),
and `Intel.cached_kev/1` is called from exactly one place, `cve_live/show.ex:50`.
The KEV fields that make a CVE actionable — `required_action`, `due_date`,
`known_ransomware` (`priv/repo/migrations/20260915103805_add_kev_actionability_to_intel_advisories.exs`)
— are therefore visible only after opening `/cves/<id>`.

The consequence is concrete: an analyst reading 25 rows of the inventory, or the
Overview's "Critical advisories to review" table, or the review queue, cannot see which
advisories are known-exploited. The signal exists, is cached, and is unused at exactly
the moment the triage decision is made. This is the highest-value visibility change
available, and it is also the cheapest to reason about because the data is already local.

### G2 — The tab/window title never names the CVE (except the advisory page)

`root.html.heex:7` renders `live_title` with `default="Overview"` and suffix
`" · Triage"`; the assigns are generic: "Finding detail" (`finding_live/show.ex:19`),
"Review case" (`case_live/show.ex:41`), "Review Queue" (`case_live/index.ex:29`),
"Activity" (`whats_new_live.ex:27`), "Timeline" (`timeline_live.ex:28`). Only
`cve_live/show.ex:56` assigns the CVE, and it assigns it after loading.

The tab strip, window switcher, browser history and any bookmark are the most-seen text
about a page, and for an analyst working several advisories at once they are the only
text that is still visible for the other tabs. A CVE-first title makes parallel triage
legible at essentially zero cost.

### G3 — The activity feed buries the CVE in its second section

An event row is headed by the event kind (`whats_new_live.ex:303`) and the CVE appears
later inside "Current local metadata" (`whats_new_live.ex:~317-330`). This placement is
deliberate and honest: the event is a recorded fact, the CVE is a join to current records,
and the page is careful not to present the second as the first. Any change here must keep
that distinction, which is why it ranks below G1/G2 — the fix is a label, not a move.

### G4 — Nothing copies a CVE id

`technical_value/1` supports a compact variant with a copy affordance
(`ui_components.ex:49-54`) for long opaque values, but advisory ids are plain links. The
copy path in this product is the separator between reading a CVE and acting on it in a
ticket or a chat thread.

### G5 — The search field does not say it takes a CVE id

The findings search is labelled "Search advisory or package" (`finding_live/index.ex:278`)
and its help text (`finding_live/index.ex:313-314`) explains only the package rule. The
CVE behaviour is real (`inventory.ex:800-812`) but undocumented in the UI, so the fastest
path to a specific advisory — typing its id — is discoverable only by trying it.

### G6 — Small redundancies

The finding page prints the CVE twice in its header: eyebrow `Findings / {CVE}` and title
`{CVE}` (`finding_live/show.ex:133-134`). The breadcrumb change was a deliberate
round-2 decision, so this is polish, not a defect.

## 3. Plan

### Phase 1 — make the CVE the identity of the surface (pure UI, no context change)

| # | Change | Files | Acceptance |
|---|---|---|---|
| 1.1 | Assign the CVE to `page_title` after load, exactly as the advisory page does: finding detail and case detail. | `finding_live/show.ex`, `case_live/show.ex` | A test asserts the CVE appears in the rendered `<title>` text for both routes. |
| 1.2 | State that the search takes an advisory id: extend the findings search label/help and the Overview search helper. | `finding_live/index.ex`, `home.html.heex` | Copy names both accepted inputs; existing search tests unchanged. |
| 1.3 | Copy affordance beside the CVE on the finding and advisory headers, reusing the existing copy hook; the advisory link stays the link. | `finding_live/show.ex`, `cve_live/show.ex`, `ui_components.ex` if a small variant is needed | Copy control is keyboard-operable, has an accessible name, and copies the exact id. |

### Phase 2 — put exploitation status next to the CVE (one context function, then render)

| # | Change | Notes |
|---|---|---|
| 2.1 | `Intel.kev_index/1`: one batched read (`where source == "kev" and external_id in ^cves`) returning a map of id → `%{required_action, due_date, known_ransomware}`. | `cached_kev/1` is a per-CVE query (`intel.ex:138-144`); per-row use would be N+1. Only cached rows are returned: absence is never "not exploited". |
| 2.2 | Render a "Known exploited (cached KEV)" badge beside the CVE in: findings list rows, the Overview critical table, queue rows, case header, timeline lanes. | Badge text must name the cache as its source. Reuse the existing receipt vocabulary (`home-receipts`) so each page shows KEV cache freshness once — an empty or failed cache shows as absent/unknown, never as "clear". |
| 2.3 | On a case whose CVE is in KEV, surface `required_action`, `due_date` and the ransomware flag in the case header region. | The reviewer is deciding on that case; the advisory page already renders these (`cve_live/show.ex:327-337`). |
| 2.4 | (Needs a filter contract, so it is a separate decision) a `kev=1` findings filter plus a link from the Overview. | Touches `FindingFilters` + `Inventory`; must follow the existing rule that an unrecognised value is rejected visibly and never widens the view. |

### Phase 3 — polish

- 3.1 Activity rows: name the CVE in the row header **as current local metadata**, with the
  same explicit "joined from current local records" qualifier the section already carries,
  so the event-versus-current distinction survives.
- 3.2 Finding eyebrow: drop the duplicated id (eyebrow "Findings" or the package identity).
- 3.3 A CVE lookup entry in navigation for cross-page jumps (form → `/cves/<id>`).

## 4. Rejected

- **A risk score, or "not exploited" from an empty cache.** The product's own rule: absence
  from the cache never means unaffected. A badge may only assert what is cached.
- **Reordering the Overview critical table by exploitation.** Its documented order is "most
  affected images first" (`home.html.heex` caption); changing the order without changing
  the caption would make the caption false. A `kev=1` filter (2.4) is the honest route.
- **Colour-only severity or exploitation signalling.** Round 2 already established fill +
  border + weight differentiation; exploitation follows the same rule (text, not hue alone).

## 5. Verification

- Phase 1 and 2 changes ship with element-ID tests; `mix ci` (format, `credo --strict`,
  full suite, `dialyzer`) must stay at exit 0.
- The KEV index needs a context test for the batched read, including the empty-cache case
  (no badge anywhere) and the cache-failed case (freshness shown as failed, no badge).
- Rendered confirmation: the dev server from the previous rounds is **gone** (PID 59341 no
  longer exists; the port answers nothing). Any screenshot check must therefore run on an
  owned server and an owned database through `scripts/verify_owned_db.sh`, and be cleaned
  up afterwards. Postgres (PID 33667) is still running.
- Truthfulness review at the end: read every new string back and confirm it claims only
  cached data.

## 6. Decisions for the owner

1. Is a KEV badge wanted on the review queue and the timeline, or only where an analyst
   chooses work (Overview + findings + case)?
2. Is the `kev=1` filter wanted (2.4), which is a filter-contract change rather than UI?
3. Should the activity feed carry the CVE in the row header at all (3.1), given the
   recorded-fact/current-join distinction it currently preserves?
