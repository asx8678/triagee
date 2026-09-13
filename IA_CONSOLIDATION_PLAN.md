# Consolidating the workspace: Overview, Triage, Timeline

Status: **proposal, awaiting the operator's choice.** No navigation, route or page has been
restructured. The only code changed so far is the pair of confirmed defects in section 6.

Scored by three independent read-only reviews of this tree (`navigation-options`,
`human-triage-policy`, `overview-data-model`). Scores are advisory fit judgments against the
requested requirements, not measured usability results.

## 1. What each of the eight destinations does today

| Destination | Shows | Actual responsibility |
|---|---|---|
| `Overview` `/` | Severity tiles, occurrence counts, 10 critical CVEs, 5 newest CVEs, 5 recent cases, cached news | Posture summary + two slices of `Findings` + previews of cases and news |
| `Findings` `/findings` | Searchable CVE groups: severity, packages, images, occurrences, reported fix, first seen, teams | The full inventory browser |
| `Review Queue` `/cases` | Saved review cases, newest opened first, team/environment filter | History of cases already opened — **not** a CVE triage backlog |
| `Activity` `/whats-new` | Paginated `finding_events`: first observed / no longer observed / re-observed | The same lifecycle rows `Timeline` draws, ordered by record id |
| `Timeline` `/timeline` | Day bands, weekday grid, SVG lane chart, per-CVE drawer | The only connected, time-based view. **Keep.** |
| `Imports` `/imports` | Preview, confirm nonce, apply a historical snapshot | Operator tool |
| `Replay` `/replay` | Run a synthetic file in memory, optionally save a summary | Operator tool |
| `Replay History` `/replay/history` | Saved replay receipts | Operator tool |

Secondary detail routes (`/cves/:id`, `/findings/:id`, `/cases/:id`) are drilldowns, not tabs.

## 2. Where the pages are duplicated (verified)

1. **Overview duplicates Findings.** The critical table and the newest rail call
   `Inventory.list_groups/1` — the same query behind `/findings`, sliced to 5–10 rows
   (`page_controller.ex:10-25`).
2. **Activity duplicates Timeline.** Both read `finding_events`; Activity orders by descending
   record id, Timeline by observation time with a chart (`whats_new_live.ex:1-16`,
   `timeline.ex:23-53`). Timeline's CVE drawer also carries the case history that the Review Queue
   lists.
3. **The Review Queue is not a triage queue.** It lists only cases a human already opened, so a
   critical CVE nobody has touched yet appears nowhere.
4. **Overview's "Recently discovered new CVEs" listed saved cases**, ordered by case opening —
   not discoveries. Fixed in section 6.

## 3. Navigation options

Every option keeps Timeline, adds a dedicated Triage page, and keeps all detail URLs.

| # | Top-level tabs | Change | Score |
|---|---|---|---:|
| **A** | Overview · Triage · Timeline | Findings' browse/filter/search moves into Overview; Activity becomes an expandable ledger inside Timeline | **95** |
| **B** | Overview · CVEs · Triage · Timeline | As A, but keeps exhaustive inventory browsing as its own page | **88** |
| **C** | Overview · Triage · Timeline · Operations | As A, and promotes Imports/Replay to a first-class operations hub | **85** |
| **D** | Keep the eight tabs, fix labels only | Lowest effort; duplication stays | **45** |

Three independent reviews scored A at 94, 95 and 95.

## 4. What "critical CVEs that have impact" can mean

The application has scanner severity, operator-declared exposure evidence, cached KEV (public
exploitation only), and affected teams/packages/images. **It has no impact field.** Impact is a
human judgment, so admission has to be defined rather than discovered.

| Gate | Rule | Score |
|---|---|---:|
| **Strict evidence** | CRITICAL + unresolved + active placement + a human-recorded applicability/impact judgment. Unknowns stay visible, never "unaffected" | **95** |
| **Potential impact** | CRITICAL + local presence + fresh internet exposure or KEV, labelled "potential" | **78** |
| **Severity only** | Every CRITICAL CVE; a Findings filter by another name | **62** |

Recommendation: strict evidence.

Constraints that follow from the code:

- **Circular admission.** If strict evidence is the gate, Overview must expose a *critical,
  impact-unconfirmed* lane, otherwise nothing can ever qualify — the evidence required for
  admission is only recorded inside Triage.
- **Do not substitute proxies for impact.** Review priority (`Risk.classify/1`) promotes HIGH to
  critical on KEV or internet exposure, so it must never define the Triage population.
- **Scope is `(finding_id, owner, environment)`**, which can span namespaces, so a CVE row must
  expand into scoped work items, and a CVE must never read "handled" because one scope was
  reviewed.
- **"Handled" means an assessment was saved**, not fixed or approved. Timeline "judgments" are
  assessments. Only remediation verification could support "fixed", and there is no such state.
- **Retention.** A human-assessed CVE stays visible after retirement or disappearance, showing why
  it qualified then and its status now.

Within Triage: **Unreviewed → In review → Assessment recorded**, with applicability, remediation
and evidence-freshness kept as separate axes.

## 5. Target page contents

**Overview** — one dense surface, three labelled clocks kept apart:
latest active local CVEs; newest locally observed (by `first_seen`, never publication date);
critical/impact-unconfirmed (the Triage intake lane); cached public advisories with cache freshness;
and visible access to the full inventory.

**Triage** — one row per CVE, expandable to scoped cases, with three filters rather than new tabs:
Active · Handled by a human · All.

**Timeline** — unchanged, absorbing Activity as an expandable paginated ledger.

**Data tools** — Imports, Replay, Replay History, unchanged.

## 6. Defects found in this change

Fixed here, each with a regression:

1. **Severity tiles double-counted a mixed-severity CVE.** `Inventory.cve_summary_counts/0` summed
   the four severity bands, so a CVE recorded at two severities was counted twice in `:total`.
   Measured on this machine's development estate: bands sum to **29**, distinct CVEs are **28**
   (a freshly seeded test database shows the same one-CVE overlap: 4 band memberships over 3 CVEs);
   `CVE-2024-4004` is recorded at HIGH and MEDIUM. `:total` is now its own distinct count over a
   single shared relation, and the bands' overlap is stated in the visible caption, the
   screen-reader intro and the severity bar's accessible name.
2. **"Recently discovered new CVEs" was mislabelled** — the section lists saved review cases. It is
   now "Recently opened review cases".

Disclosed, not changed:

3. **CVE detail can let an inactive placement drive the headline priority.** `fetch_cve/2` loads all
   placements for its images with no `active == true` filter (`inventory.ex:474-502`), while the CVE
   list, the review queue and case opening all require an active placement. The development estate
   has **0** inactive placements on live findings, so the path is latent rather than biting today;
   it becomes reachable as soon as placements retire through import or replay.

## 7. Data limits behind these designs

- **No impact field.** Exposure is operator-declared evidence with a source and time; expired
  evidence becomes `unknown`. KEV means publicly exploited, not exploited or applicable here.
- **No reviewer identity.** Every review is the server-owned literal `local-operator`.
- **Snapshot hashing excludes exposure, Intel and the risk-policy version**, so a "current" review
  does not prove those inputs are still fresh.
- **Import arrival is not persisted**, so "newly imported today" cannot be reconstructed from
  `first_seen`; local observation, import arrival and publication are three different clocks.
- **The cached Intel feed is not a global discovery feed.** The CLI refreshes advisories, not news;
  NVD is fetched per CVE; KEV takes the first 50 entries and stores the KEV addition date in
  `published_at`.
- **Production coverage is unknown**, `local-operator` is unauthenticated, and absence of a row is
  not evidence of a clean estate.

## 8. Acceptance checks for any implemented design

Mixed-severity deduplication; backdated and reopened discovery ordering; active and retired
reviewed cases shown together; stale-review rejection after evidence changes; unchanged audit
history; honest empty/stale-cache labelling; scope and pagination preserved across all three pages;
no critical function (case opening, evidence refresh, manual assessment, aggregate CVE impact)
unreachable after consolidation.

## 9. Open decisions

1. Tab set — A, B, C or D.
2. Triage gate — strict evidence, potential impact or severity-only.
3. Overview — keep the public news feed.
4. Activity — fold into Timeline or keep its own tab.
5. Data tools — leave as-is or promote to Operations.
6. Defects — fixed here for items 1 and 2; item 3 awaits the redesign.
