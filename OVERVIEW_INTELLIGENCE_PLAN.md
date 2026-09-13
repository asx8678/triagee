# Overview and vulnerability intelligence — implementation preparation

Status: **partially implemented, reconciled below**. Originally a reviewed proposal whose
verdict read "not implemented"; that historical wording is left in the sequence section.
See "Reconciled implementation evidence" for exactly what is backed by tests now and what
is not. Scores are engineering judgments, not measured accuracy. Application remains local-only. No commit, deployment, production access, or DB mutation is authorized by this plan.

## Review

Overall previous proposal: 82/100. Strong UI decomposition and reuse, but its exposure-based automatic downgrade, missing live-inventory dependency, and manual-only refresh are material gaps.

| Idea | Score / 100 | Decision |
|---|---:|---|
| New cluster CVEs above public news | 97 | Keep; label observation time separately from publication time |
| CVE-centric detail with occurrence drill-down | 96 | Keep; preserve scoped review-case workflow |
| Reuse Findings for full filtering | 95 | Keep; add severity, sort, pagination |
| Cached public enrichment separate from inventory | 96 | Keep; source provenance and freshness mandatory |
| Deterministic explainable prioritization | 93 | Keep; policy-versioned, not a probability or final disposition |
| Single exposure enum on placement | 70 | Improve with workload-level evidence, source, time, expiry |
| Automatically downgrade internal services | 35 | Reject; internal-only alone does not prove reduced exploitability |
| Manual-only internet refresh | 65 | Useful first milestone, incomplete company product |
| Many news/advisory sources immediately | 60 | Start small; validate source contracts before expanding |
| Preserve loopback until SSO/authorization | 99 | Required for company rollout |

## Corrections to previous analysis

- Existing list_groups returns a team COUNT, not the affected team names. A bounded team-name query is needed.
- Existing summary_counts counts occurrences without the active-placement join used by list_groups. Do not reuse it for distinct-CVE metrics or silently change its existing contract.
- first_seen is local observation time, not publication time or most recent spread into a new team. last_seen is not newness either.
- Public feeds cannot establish internal teams, images, or deployment reachability. Those come exclusively from local inventory and approved internal evidence.
- The current collection adapter does not populate live inventory. Real cluster freshness requires the separately gated collection and observation-ingestion work in NEXT_STEPS_PLAN.md (D/F).
- Existing advisory identifiers are not restricted to CVE/GHSA. Preserve bounded opaque local advisory navigation; validate CVE format only for provider-specific lookup. Never silently merge aliases by title/package similarity.
- Fix availability is remediation information, not reduced danger. KEV absence is not evidence of no exploitation. Missing enrichment is unknown, not zero risk.
- NVD commonly documents limits of 5 requests/30 seconds without a key and 50 with one. Verify current official limits and feed availability before adapter implementation; neither was checked live in this review.
- A checkpoint is advisable, but committing requires separate permission and is not a prerequisite for safe local preparation.

## Product contract

Overview order:
1. New to local inventory: top 10 advisory groups, sorted first-observed descending with stable ID tie-break. Show severity, named teams (bounded plus more link), image count, observation time and priority reason. Distinguish a new advisory from newly affected teams in the later observation-ingestion milestone.
2. Current inventory: distinct advisory/CVE counts by severity, affected images and occurrences separately labelled; top critical groups; links to filtered Findings. Default excludes suppressed and no-longer-observed occurrences, requires an active placement. Suppressed items remain explicitly accessible. Non-CVE advisory counts are labelled separately.
3. Public security updates: top 10 sourced notices, source publication and fetch times, and optional exact-CVE inventory-match links. No match means not found in current local inventory, not unaffected. News and authoritative advisory/KEV notices are labelled separately.

Keep /findings as the full filterable list and /findings/:id as occurrence detail. Add /cves/:id for validated CVE IDs, retaining an advisory-detail path for other supported identifiers rather than excluding existing findings. Preserve team/environment/suppression scope and back-navigation. No second competing all-CVE list.

Detail: advisory description with provenance; packages and installed versions; scanner-reported fix separately from vendor enrichment; team -> workload/placement -> image digest -> package occurrence; per-placement exposure and priority explanations; active/inactive and suppressed states clearly distinguished. Bounded paginated sections prevent unbounded group rendering. Public affected-version ranges do not replace scanner observations or prove runtime reachability.

## Risk and exposure contract

Display four independent facts: scanner severity, exploitation intelligence, exposure evidence, and remediation availability. Add a separate policy-derived review priority with reasons, missing evidence, and policy version. Never present it as an exploitation probability.

Compute priority per occurrence/placement before aggregating maximum priority at CVE level. Do not combine severity from one occurrence with exposure from an unrelated occurrence to fabricate a risk assessment. Unknown/stale exposure triggers verification and does not downgrade baseline severity priority. Internal exposure alone and available fixes never downgrade severity priority. Known exploitation and evidenced internet reachability can escalate review priority under an explicit tested policy. No automatic suppression, approval, or remediation.

Prefer separate exposure-evidence records attached to the narrowest known workload/placement identity: exposure enum, source type/reference, observed_at, expires_at, and optional workload identity. Current placements can cover multiple workloads; mixed or incomplete evidence must not become internal-only. MVP uses explicit operator-declared evidence via a bounded local ingestion contract; no production-data inference from repository names, namespace names, or environment. Missing evidence remains unknown. Preserve import v1 unchanged; add a separate exposure ingestion path and tests, not invented fields in old snapshots. Existing frozen review evidence is never rewritten.

## Public intelligence architecture

Triage.Intel: source adapters -> validation/normalization -> durable source-specific cache -> read-only UI. Retain each provider's values, version, timestamps and references; show conflicts rather than overwriting scanner facts. Candidate initial sources: CISA KEV and NVD, plus one verified official RSS/Atom security feed. KEV additions are updates, not newly published CVEs. OSV, EPSS and broader media feeds are follow-ups.

Tables: source-specific advisory records keyed by source + external identifier; news items keyed by source + stable item identifier; refresh receipts with attempts, last success and safe error status; exposure evidence separate from scanner inventory. Explicit retention/item limits and indexes. Additive migrations only.

No request-time downloads. Default-disabled manual mix triage.intel refresh entry first, writing only intel cache/receipts. Subsequent explicitly enabled scheduled refresh is needed for an unattended company aggregator; use a single-flight job/lock, bounded retries, jitter, per-provider rate limits and conditional requests. Scheduling public intel does not enable cluster collection. CLI starts only required persistence/HTTP services, never Endpoint. Failure preserves last good cache and displays stale/partial status. Validate a refresh before replacing that source's cache; never erase good data on empty/malformed/error responses.

Proposed configuration namespace: :triage, :intel with enabled: false, named allowlisted sources, scheduling disabled, request/response/run/item limits, freshness and retention thresholds. Freeze numeric defaults and exact provider URLs against current official documentation before coding transports. No arbitrary URL parameters, browser credentials or internal inventory uploads. Public CVE-only lookups still disclose identifiers: use an approved egress policy or public bulk feeds where required.

Use existing Req, verified HTTPS, redirects off, bounded streaming and decompression, deadlines and provider backoff. SSRF/egress restrictions cover DNS/proxy behavior, not merely a URL regex. Do not copy test-only Collection gates into an externally enabled adapter or weaken Collection. RSS XML: DTD/external entities disabled, depth/size limits, no external resource resolution. Escape all display text; no raw HTML or remote images. Validate outbound link schemes separately from fetch allowlists. Review feed reuse terms. No network in ordinary tests.

## Sequence and acceptance ledger

1. Freeze query/data contracts and source choices; record source-only baseline without staging user changes.
2. Implement bounded overview/advisory read models, severity/group filters and scoped navigation; preserve existing summary_counts.
3. Add exposure evidence ingestion plus pure versioned priority module and synthetic fixtures.
4. Implement overview and CVE/advisory detail UI against cached fixtures, including errors/empty/stale states.
5. Implement public intel cache, tested adapters and explicit CLI; bounded public-source smoke check only after endpoint/egress configuration is approved.
6. Add scheduled public refresh for unattended use with operational tests/runbook.
7. Separately integrate authorized live cluster observations and verified workload exposure; SSO/context authorization before any shared company deployment.

### Reconciled implementation evidence (2026-09-13)

The twelve boxes below are left exactly as written. This block records, item by item,
what the tree and its tests actually support now. Nothing is ticked without evidence,
and unresolved parts are named.

| Ledger item | Status | Evidence |
|---:|---|---|
| 1 Counts and group rows reconcile on the same predicates | Partial | `Inventory.filtered_findings/1` is the single predicate pipeline behind `list_groups/1` and `count_groups/1`; equality is asserted across 11 filter sets in `test/triage/inventory_paging_test.exs`. Placement-level duplicate inflation is **not applicable** yet, because no placement aggregation exists. |
| 2 Newness ordering and stable pagination | Verified | All four orders are strict total orders ending in the group key; paged offsets reassemble the unpaged order; `newest` orders by first observation, never `last_seen`. `test/triage/inventory_paging_test.exs`, `test/triage_web/live/finding_live_paging_test.exs`, live probe in [FINDINGS_PAGING_EXECUTION.md](FINDINGS_PAGING_EXECUTION.md). |
| 3 Group filtering retains other packages; navigation retains scope; malformed clears rows | Partial | `test/triage_web/inventory_readability_test.exs` covers whole-advisory count preservation under package search, an error instead of empty-success counts for invalid filters with reset recovery, and scope retention. Row-level "other packages stay listed" is asserted only as help text. |
| 4 Non-CVE advisories navigable; aliases from provider evidence | **Not implemented** | No non-CVE advisory identifier (for example GHSA) appears anywhere in `lib/`, `test/`, or `priv/repo/`; group keys are CVEs. |
| 5 Per-placement priority matrix | Partial | `test/triage/risk_test.exs` covers internet-exposed, known-exploited-but-internal, internal-never-downgrades, fix-available-is-not-danger-reduction, unknown exposure, unknown KEV, missing severity, stable policy version, and aggregate-max. `test/triage/exposure_test.exs` covers expired evidence falling back to unknown. The matrix is now wired end to end: `test/triage_web/live/cve_live_test.exs` asserts mixed-exposure placements and proves a cached KEV entry raises priority. The remaining gap is closed by `test/triage_web/live/cve_live_test.exs`, which asserts that a conflicting NVD severity claim is displayed as a claim and moves no priority while a KEV row does raise it. |
| 6 Exposure ingestion validates identity, source and timestamps without changing history | Partial | `test/triage/exposure_test.exs` covers a valid record with preserved history, expiry fallback, placements with no evidence, and rejection of invalid exposure and placement. No end-to-end operator ingestion path is tested. |
| 7 Refresh idempotency, failure retention, duplicate jobs, rate limiting, malformed XML/JSON, XSS, size/deadline, disabled-zero-network | Partial | `test/triage/intel_cache_test.exs` covers default-disabled with an HTTPS allowlist, cached reads with no network effect, per-source replacement, bounded news, receipts, and hostile-text sanitization. **Not covered: idempotency over a real payload, failure retention, duplicate-job locking, rate limiting, malformed XML, size and deadline limits.** |
| 8 Read-only overview/detail requests perform no network and no inventory writes | Partial | Cached intel reads assert no network effect (`test/triage/intel_cache_test.exs`) and read paths call no refresh entry point. DB-effect fingerprints for read states are recorded in `evidence/ui_redesign/INDEPENDENT_REVIEW.md`. With the default config the client transport itself is `{:error, :intel_disabled}`, so a request-time fetch is impossible while disabled (asserted by the default-off test). **Verified per route**: `test/triage_web/read_only_requests_test.exs` fingerprints every table before and after `/`, the list routes and the findings/cases/CVE detail routes, and asserts the default transport cannot reach the network. |
| 9 Public routes, context APIs, Mix task and configuration mechanically checked | Verified | `mix phx.routes` lists `/`, `/findings`, `/findings/:id`, `/cves/:id`; `mix help triage.intel` documents a cache-only refresh; `config :triage, :intel, enabled: false, sources: []`. The task itself was then executed for real, which is how it was found to crash on every invocation: it now starts `:ecto_sql`/`:postgrex` before the Repo, refuses a source the `sources:` allowlist does not name, exempts read-only `--receipts` from the disabled guard, and uses one canonical `nvd:` source key for success and failure. See [INTEL_WIRING_EXECUTION.md](INTEL_WIRING_EXECUTION.md). **Not exercised: an actual refresh** (needs `enabled: true`, a named source, and network approval). |
| 10 Targeted tests plus probes in an absent-before owned disposable DB | Verified | `app/OWNED_DB_VERIFICATION.md`, plus this session's full and targeted suites against owned databases, dropped afterwards. |
| 11 Responsive browser checks, keyboard navigation, real filters, detail drill-down | Partial | Reflow evidence at 320/390/768/1024/1366/1920 (`evidence/ui_redesign/reflow-results.json`) and keyboard/draft/zoom probes with 320px detail screenshots (`evidence/ui_redesign/INDEPENDENT_REVIEW.md`). **Gap: physical-keyboard horizontal scrolling of the table is unconfirmed** and retained as an explicit gap. |
| 12 One final precommit plus owned-DB migration rehearsal, evidence and cleanup documented | Verified | `mix precommit` 605 passed / 2 skipped, exit 0 (2026-09-13); migration rehearsal and owned-DB cleanup in `app/OWNED_DB_VERIFICATION.md`. |

Items 2 and 12 were closed by the paging slice, and three wiring defects behind
item 5 were fixed during reconciliation. Records:
[FINDINGS_PAGING_EXECUTION.md](FINDINGS_PAGING_EXECUTION.md) and
[INTEL_WIRING_EXECUTION.md](INTEL_WIRING_EXECUTION.md).

All checks below are pending:
- [ ] Counts and group rows reconcile on the same active/suppression/scope predicates; no duplicate inflation across placements.
- [ ] Newness ordering and stable pagination tested; no last_seen-as-new inference.
- [ ] Group filtering retains other affected packages; all navigation retains scope; malformed queries clear stale rows.
- [ ] Non-CVE advisories remain navigable; aliases only from explicit provider evidence.
- [ ] Per-placement priority matrix covers internal/local attacks, unknown/stale/mixed exposure, KEV absence, missing enrichment, fix availability and conflicting sources.
- [ ] Exposure ingestion validates identity, source and timestamps without changing old import/review history.
- [ ] Refresh idempotency, failure retention, duplicate jobs, rate limiting, malformed XML/JSON, XSS/unsafe links, size/deadline and disabled-zero-network probes pass.
- [ ] Read-only overview/detail requests perform no network and no inventory writes.
- [ ] Public routes, context APIs, Mix task and configuration entries mechanically checked after implementation.
- [ ] Targeted tests plus direct probes in an absent-before owned disposable DB; never migrate/reset dev/shared DBs.
- [ ] Responsive browser checks at desktop and 320/375px, keyboard navigation, real filters and detail drill-down.
- [ ] One final mix precommit with inspected failures/side effects, plus migration rehearsal in owned DB; evidence and cleanup documented.

Current evidence: reread app/AGENTS.md, inventory group/count fields, FindingFilters and git status; earlier route/controller/detail tracing informs this plan. This turn changes this document only. No application tests, public-source checks or implementation correctness claims are made.
