# Findings list paging — execution record

Date: 2026-09-13. Scope: the bounded, sortable advisory list — the one open
implementation item from `OVERVIEW_INTELLIGENCE_PLAN.md` step 2 ("add severity,
sort, pagination") and its pending ledger box *"Newness ordering and stable
pagination tested"*.

No commit, stage, push, or deployment was performed. HEAD remains
`dc4843141b94aa8f9a040eec6aa0ea61978784cc`; `app/` is still untracked, so the
hashes below are the only stable identifiers for this change.

## What changed

`Triage.Inventory.list_groups/1` applied scope, severity and suppression filters
and a fixed order but had **no limit or pagination**, and `FindingLive.Index`
rendered every matching group (`advisory_count = length(groups)`). The overview's
critical table (`PageController.home/2`) read *every* critical group and took ten
in the template. Both are now bounded, and every order is a strict total order.

| File | Lines | SHA-256 |
|---|---:|---|
| `app/lib/triage/inventory.ex` | 808 | `199d760f3b593cd909059e88ad1a9fc93f41db7ad001b7f913a4c143c571f229` |
| `app/lib/triage_web/finding_filters.ex` | — | `6abd3197d3244e1f5a5b6d80c37ffa407593a2b60ffbbd877cd47a8bfca07bfe` |
| `app/lib/triage_web/live/finding_live/index.ex` | 427 | `df40e8d025b8cafef05a1a796e428908004f003670d226d3256017c391747e93` |
| `app/lib/triage_web/live/finding_live/show.ex` | — | `3bc81b5fd3a665d389df03839c580c5f3af0c7110af074b551a2c39a86d204cc` |
| `app/lib/triage_web/controllers/page_controller.ex` | — | `6a75a874457112213e4d02a1956d8d39fbf99acca382c7617d8cabd89a6520b9` |
| `app/lib/triage_web/controllers/page_html.ex` | — | `5fb743cb3d3b2a51287befb85df08469c36e99882b462b8bb189ee670b890d4b` |
| `app/lib/triage_web/controllers/page_html/home.html.heex` | — | `9075a6c20bdc7f2e9e1541a6ffebe275c6466da4d9db07f510f11527e66b6b04` |
| `app/test/triage/inventory_paging_test.exs` (new) | 163 | `8296cbc32779caea6d56d93da55afbfada2f12104a491e420f2ac66d3221bffe` |
| `app/test/triage_web/live/finding_live_paging_test.exs` (new) | 223 | `11d8fe9a6dc2c7cede4dbeadbeac8440c9acc0d6503d032a9db389f3f33750ef` |
| `app/test/triage_web/finding_filters_test.exs` | — | `98ed67e61361ef316f6b528b7ab3433c385b6c8e738550cd3c1235f79898c506` |
| `app/test/triage_web/overview_readability_test.exs` | — | `9f13a1794786e6b6b882ece9f48099f3ae3924258331f29c9bd7711454e0210d` |

### Design decisions

- **One predicate pipeline.** `filtered_findings/1` is the single definition of
  the group predicates; `list_groups/1` and the new `count_groups/1` both use it,
  so a page total cannot disagree with its rows.
- **Strict total orders.** Every published sort ends in `cve` (the group key), so
  two groups can never compare equal and paging can neither duplicate nor skip.
- **Page size vs offset.** `:limit` is bounded at 200 per request; `:offset` is
  *not* bounded, because a later page of a large inventory is a legitimate cursor
  position. The list clamps the requested page against the real total first.
- **Canonical URLs.** The default order (`severity`) and page 1 stay out of page
  links; a non-default order is explicit. A filter event that leaves the order at
  its default patches the same canonical URL as before this change.
- **One ordering for the newest rail.** `newest_cve_groups/1` is now
  `list_groups(sort: "newest", limit: limit)`, so the overview rail and the list's
  newest order cannot drift.
- **Honest captions.** The rail and the critical table label their withheld rows
  against the *real* total (`count_groups/1`), not the size of the slice read.
- **One allowlist.** Accepted orders and the default order live with the query
  that implements them (`Inventory.group_sorts/0`, `Inventory.default_group_sort/0`).
  The filter contract and the list view read them instead of restating them, and
  a test asserts `FindingFilters.sorts/0 == Inventory.group_sorts/0`.

## Acceptance ledger

All commands run from `app/` with `mise x --` and `PATH=/opt/homebrew/bin:$PATH`.

| Check | Command | Result |
|---|---|---|
| Full gate (compile `--warnings-as-errors`, `deps.unlock`, `format`, `assets.setup`, full suite) | `mix precommit` | **exit 0 — 601 passed, 2 skipped** (was 574 before this slice; +27) |
| Findings web suite | `mix test test/triage_web` | 288 passed |
| Inventory paging suite | `mix test test/triage/inventory_paging_test.exs` | 10 passed |
| Findings paging suite | `mix test test/triage_web/live/finding_live_paging_test.exs` | 8 passed |
| Formatter | `mix format --check-formatted` (inside precommit) | exit 0 |
| Count agrees with rows | `count_groups/1 == length(list_groups/1)` for 11 filter sets | pass |
| Paging partitions the list | offsets 0,5,10,… reassemble the unpaged order exactly | pass |
| Sorts are total and repeatable | all four `group_sorts/0` values | pass |
| Page past the end | renders the last page, not an empty table | pass |
| Invalid page | `0`, `-3`, `2.5`, `abc`, `1000000` → visible invalid state, no rows | pass |
| Deep offset reachable | `limit: 2, offset: 10_000` is accepted, not rejected by the page-size cap | pass |

### Live browser evidence

Headless Chrome against the running dev server (`127.0.0.1:4000`, 1440×900),
read-only, no writes:

```
findings-page1:  rows=25 status="Page 1 of 2 · showing 1–25 of 28" prev=false
                 next="/findings?page=2" sortOptions=[severity,newest,occurrences,cve]
                 summary="28 matching advisories · Page 1 of 2 · All teams · All environments · Suppressed excluded"
findings-page2:  rows=3  status="Page 2 of 2 · showing 26–28 of 28" prev=true next=null
findings-newest: selectedSort="newest" order="Sorted by first local observation, newest first…"
                 firstRow="CVE-2026-87637" next="/findings?sort=newest&page=2"
findings-past-end (page=9999): clamped to "Page 2 of 2", rows=3
findings-invalid-page (page=0): "Invalid filter value for page — no findings were loaded…"
overview:        criticalCaption="All 5 open critical CVEs" criticalRows=5
                 newestTrunc="Showing 5 of 28 by first observation · See all findings"
no page-level horizontal overflow at 1440px on any probed state
```

Screenshots: `app/tmp/overview-redesign/verify-findings-{page1,page2,newest,past-end,invalid-page}.png`,
`verify-overview.png`.

## Defects found and fixed during this slice

1. **`count_groups/1` was invalid SQL.** The group-search predicate is an
   aggregate (`bool_or`), so counting required a grouped subquery — found by the
   new suite before any browser check.
2. **Blank `page` was rejected as invalid** instead of meaning page 1, which
   broke the blank-form-field contract. Caught by the extended defaults test.
3. **Filter events pinned `sort=severity` into the URL** on every change; three
   existing URL tests caught it. Fixed by canonicalizing the default order, not
   by relaxing the assertions.
4. **The sort select made wrapper events "ambiguous".** The shipped form
   serializes its order control on every event, so a flat value equal to the
   default must not count as conflicting intent next to a `filters` wrapper. A
   non-default value there is still rejected.
5. **`offset` was wrongly capped by the page-size limit**, which would have
   crashed a legitimate deep page. Caught while writing the validation test.

## Limits

- No shared-deployment, auth, or live-collection change; the app is still
  unauthenticated and must stay on loopback.
- Browser checks are Chrome-only at 1440×900 plus the earlier 320/375/1024 reflow
  pass; not a WCAG certification.
- The pagination controls are links (patch), not keyboard-trapped; they inherit
  the existing shell focus behaviour but were not re-tested with a real keyboard
  matrix in this slice.
- `OVERVIEW_INTELLIGENCE_PLAN.md` still reads "not implemented" with all twelve
  boxes unticked. That status is stale: the exposure/priority/intel/CVE-detail
  work exists in the tree with tests (see `lib/triage/risk.ex`,
  `lib/triage/exposure.ex`, `lib/triage/intel*.ex`, `lib/triage_web/live/cve_live/show.ex`).
  It was left untouched here rather than rewritten without review.
- The checkpoint commit remains pending and explicitly unapproved; the modified
  `.pi/fabric.json`, `.pi/fabric/mcp-cache.json` and `.gitignore` are harness
  state and were not part of this change.
