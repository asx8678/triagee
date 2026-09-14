# Which pages should this app have?

Decision sheet. Five independent read-only reviews of this tree plus direct measurement of
`triage_dev`. **Nothing is implemented from this document yet** — it is a menu, one line per
decision, so the operator can pick per line.

## 1. What every page actually does today

| Page | Route | What it shows | What it is really for |
|---|---|---|---|
| **Overview** | `/` | Severity tiles, occurrence counts, 10 critical CVEs, 5 newest CVEs, 5 recent cases, cached news | Posture summary **plus** two slices of Findings plus previews of cases and news |
| **Findings** | `/findings` | Searchable/filterable CVE groups: severity, packages, images, occurrences, reported fix, first seen, teams | The complete inventory browser — the only search, and the only place a case can be opened |
| **Review Queue** | `/cases` | Saved review cases, newest opened first, team/environment filter | History of cases a human already opened — **not** a triage backlog, and not a list of what needs review |
| **Activity** | `/whats-new` | Paged `finding_events`: first observed / no longer observed / observed again | The same lifecycle rows Timeline draws, ordered by record id instead of observation time |
| **Timeline** | `/timeline` | Day bands, weekday grid, connected SVG lane chart, per-CVE drawer | The only connected time-based view |
| **Imports** | `/imports` | Preview, confirm nonce, apply a historical snapshot | Operator tool |
| **Replay** | `/replay` | Runs a synthetic file in memory, optionally saves a summary | Operator tool |
| **Replay History** | `/replay/history` | Saved replay receipts | Operator tool |

Detail routes `/cves/:id`, `/findings/:id`, `/cases/:id` are drilldowns, not tabs.

**Why there are so many:** the app grew by addition. The moduledocs name the slices
(`CaseLive.Index` — "Read-only Review Queue (PR 3)"), and each page is a deliberately narrow,
audit-grade surface with its own filter parsing, error state and honesty notices. The navigation is a
flat ordered list (`layouts.ex:105-121`) grouped "Workspace" (5) + "Data tools" (3). Nothing ever
merged; two of the eight are near-duplicates.

## 2. Are they doubled? Yes — three verified duplications

1. **Overview duplicates Findings.** `page_controller.ex:14-24` calls the same
   `Inventory.list_groups/1` behind `/findings`, sliced to 5-10 rows, and adds a cases preview already
   on `/cases`.
2. **Activity duplicates Timeline.** Both read `finding_events`; Activity orders by descending record
   id, Timeline by observation time with a chart. Timeline's drawer carries the same case history the
   Review Queue lists.
3. **Review Queue is a history, not a queue.** It lists only cases already opened, so a critical CVE
   nobody has touched appears nowhere.

Measured estate (`triage_dev`, this machine): 44 finding rows, 8 resolved, **28 distinct CVEs** under
the app's own active predicate (5 critical, 11 high, 7 medium, 6 low), 10 placements (0 inactive),
**9 saved cases covering 8 CVEs, but only 1 saved assessment**, 3 exposure evidences, **0 cached intel
advisories** (so any KEV signal is currently false everywhere), 64 lifecycle events.

## 3. What the words can actually mean (measured, not assumed)

| Word | Reality in the code |
|---|---|
| **Active** | Derived: `resolved_at IS NULL` + unsuppressed + an active placement (`inventory.ex:255-269`). Not a stored status. |
| **Latest active** | `last_seen` exists and is already selected as `max(f.last_seen)` (`inventory.ex:227-228`); what is missing is only a sort option — `@group_sorts` is `~w(severity newest occurrences cve)` (`inventory.ex:163`). |
| **Latest discovered** | `first_seen` = first local observation, already exposed as `newest_cve_groups/1` (`inventory.ex:451`). Publication date is **unsupported**: `intel_advisories` is empty. |
| **Handled by a human** | A `review_reviews` row exists (`cases.ex:236`, `cases.ex:990-1000`). `resolved_at`, `suppressed` and opening a case are **not** handling. Today: 1 CVE (`CVE-2026-87637`, HIGH, applicability `affected`, actor `local-operator`). |
| **Impact** | **No impact or criticality field exists anywhere** — `information_schema` returns 0 matching columns and grep finds no source reference. Closest data: operator-declared `exposure_evidences` (but it has **no product writer**; only seeds/tests write it), the empty KEV cache, and the human `review_reviews.applicability` field. |

## 4. The decisions — pick one line each

Scores are 1-100 fit judgments against the stated requirements, not usability measurements. Each
navigation option was scored twice, independently (`ia2-options-operator`, `ia2-options-risk`); the
reconciled figure is the average rounded.

### D1 — How many tabs?

| Option | Tabs | Score | What it means |
|---|---|---:|---|
| **B** | **Overview · Triage · Findings · Timeline** | **83** | Fold Review Queue into Triage, Activity into Timeline, Replay History into Replay; keep Findings as the searchable all-CVE browser; Imports/Replay under "Data tools". Both reviews recommended this. |
| C | + Review Queue kept separate | 79 | Same, but handled CVEs keep a second home. |
| A | Overview · Triage · Timeline only | 76 | Fewest tabs, but hides search and the only "open case" entry point behind a menu. |
| D | 6 tabs, relabel only | 74 | Cheapest, keeps the duplication. |

*Build cost for B:* delete one `live` line (`/cases` folds into Triage), one nav entry pair, fold the
`whats-new` body into Timeline, and rewrite `navigation_test.exs:38` (currently asserts `== 8`) and
`navigation_test.exs:6-15`. **Unchanged:** every `/findings/:id`, `/cves/:id` and `/cases/:id` URL keeps working.

### D2 — What Overview contains

| Option | Score | Contents |
|---|---:|---|
| **O1** | **92** | KPI band (severity + occurrences) + **"Active now"** 5 rows ordered by `last_seen` desc + **"Newest discovered"** 5 rows ordered by `first_seen` desc + "Top 5 of N" + a link into `/findings`. Dense row: severity, package, image, teams, occurrences, fixable, first/last seen. |
| O2 | 76 | O1 without the KPI band — posture summary lost. |
| O3 | 68 | O1 plus the public news block (third clock on one page). |
| O4 | 45 | Today's Overview: 10 critical + 5 newest + 5 cases + news + tiles. |

*Cost:* one new sort (`last_seen`) + a thin wrapper reusing `list_groups/1`. Delete the critical table
(it becomes Triage's job) and the cases preview (Triage/Findings already cover it).

### D3 — What earns a place in Triage ("critical CVEs that have impact")

| Option | Score | Predicate | Rows today |
|---|---:|---|---:|
| **G1 (recommended now)** | **86** | CRITICAL + active + **human applicability = `affected`** (no migration; honest label is *applicability*, not impact) | **0** |
| G2 (the real answer) | 90 | CRITICAL + active + **a human-recorded impact judgement** — needs a small migration (`placement_impact_evidences` mirroring `exposure_evidences`) plus a recording form in the case review | 0 |
| G3 | 58 | CRITICAL + active + (internet exposure or KEV) | **1** |
| G4 | 52 | Every CRITICAL (a Findings filter with a new name) | **5** |

**The circular-admission problem:** the only place a human records judgement is inside a case review,
and cases can only be opened from `/findings/:id`. So a Triage page showing only *already-impacted*
CVEs can never receive its first row — it is empty today either way (G1/G2 = 0). Any such page must
also carry an **intake lane: critical, unassessed**. G3/G2 also depend on data nobody is writing.
Recommendation: G1 + intake lane, then G2 as the definition of impact once the operator wants to record it.

### D4 — Triage list structure

| Option | Score | Structure |
|---|---:|---|
| **T1** | **92** | One row per CVE + three filters **Active · Handled by a human · All** (default Active), row expands into the per-scope `(finding, owner, environment)` work items |
| T2 | 80 | Two tabs, Active / Handled |
| T3 | 70 | One list with a status badge per row |
| T4 | 55 | Keep Review Queue as the "handled" home (the duplication the operator is trying to remove) |

A CVE-level *single* "handled" badge across scopes would be dishonest — status is per scope
(`review_case.ex:16-18`); show `1 of 3 scopes assessed`, never one green tick.

### D5 — Activity · D6 — Data tools · D7 — News feed

| # | Option | Score | Notes |
|---|---|---:|---|
| D5 | **Fold into Timeline** as an expandable paged ledger | **90** | Same rows, one home; keep the per-event "current metadata, not captured facts" honesty note |
| D5 | Keep the Activity tab | 60 | Duplication stays |
| D6 | **Single "Data tools" menu** (Imports, Replay, Replay History) | **85** | No capability lost; three nav slots freed |
| D6 | Keep three separate tabs | 55 | — |
| D7 | **Move the news feed to Data tools · Intel** | **78** | `intel_advisories` is empty today; the feed is the app's only external-cache surface |
| D7 | Keep it on Overview | 60 | Adds a third clock to a page the operator wants compact |
| D7 | Drop the feed | 70 | Loses the only public-advisory context |

### D8 — Fix the data gap that makes "impact" meaningless

| Option | Score | What it is |
|---|---:|---|
| **Add a recording surface** | **85** | Give `exposure_evidences` a product writer (it has none) and add placement-scoped impact evidence + a form in the case review, so impact becomes operator-declared and reviewable |
| Leave read-only | 55 | "Impact" stays a proxy forever; G3 keeps returning 1 row and G1/G2 return 0 |

## 5. Guardrails for whatever you pick

- **Never** present exposure, KEV or applicability as "impact" without saying which one it is.
- **Never** delete `/findings` or `/cases/:id` routes: case opening exists only in `FindingLive.Show`
  (`finding_live/show.ex:393-410`) and evidence refresh / manual assessment only in `CaseLive.Show`
  (`cases.ex:262`, `cases.ex:236`).
- **Never** treat `resolved_at` or `suppressed` as resolved or handled (`inventory.ex:12,201`).
- Overview's per-block `:unavailable` degradation (`page_controller.ex:98-103`) must survive — it is why a
  broken read never invents a number.
- Foreign keys: cases link to `findings.finding_id`; exposure links `placement_id → image_placements.image_id → findings.image_id`.

## 6. Reply with one line per decision

Example: `D1 B · D2 O1 · D3 G1+intake · D4 T1 · D5 fold · D6 menu · D7 move · D8 yes`.
