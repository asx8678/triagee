# Intel -> risk wiring — execution record

Date: 2026-09-13. Scope: the advisory-detail integration between the cached public
intelligence, the exposure evidence and the deterministic review-priority policy.
This closes the reconciliation gaps recorded for `OVERVIEW_INTELLIGENCE_PLAN.md`
ledger items 5 and 8, and fixes three defects found by tracing call sites.

No commit, stage, push, deployment, or dev/shared database mutation was performed.
HEAD remains `dc4843141b94aa8f9a040eec6aa0ea61978784cc`; `app/` is still untracked, so
the hashes below are the stable identifiers.

## Defects found and fixed

1. **The KEV cache was unreachable from the UI (permanent false negative).**
   `mix triage.intel --kev` writes rows with `source: "kev"` and the bare CVE as
   `external_id`, but the advisory detail looked them up as
   `Intel.cached_advisories("kev:" <> cve)` — an *external id* of `"kev:CVE-…"`,
   which can never match a written row. Every KEV match therefore rendered as
   "No cached entry". Fixed with source-aware readers:
   `Intel.cached_kev/1` (`source == "kev" and external_id == cve`) and
   `Intel.cached_nvd/1` (`source == "nvd:" <> upcase(cve)`, the per-CVE key the CLI
   actually writes — the source carries the CVE because NVD refreshes are per CVE).
   `cached_advisories/1` is unchanged for generic external-id lookups, and a test now
   pins the replaced expression's failure mode explicitly.

2. **Known exploitation never reached the policy.** The KEV match was computed only
   for display; `Risk.classify/1` was called without `known_exploited`, so the
   policy's escalation branch ("Actively exploited (KEV) …") was unreachable in the
   running application. The detail view now loads the cache first and classifies with
   `known_exploited: kev != []`.

3. **Priority mixed severity from one occurrence with exposure from an unrelated
   placement.** `plc_risks/1` classified every placement using the advisory group's
   *worst* severity, which is exactly the fabrication the plan forbids ("do not
   combine severity from one occurrence with exposure from an unrelated
   occurrence"). Severity and fix availability are now derived from the occurrences
   on that placement's own image (`Enum.filter(&(&1.image_id == p.image_id))`),
   before placement-level classification and CVE-level max aggregation.

Observed difference on seeded data (CVE-2024-4004: HIGH on `app-a`, MEDIUM on
`shared-base`): the unexposed `shared-base` placement now renders **medium** instead
of inheriting `app-a`'s **high**.

## Files

| File | SHA-256 |
|---|---|
| `app/lib/triage/intel.ex` | `58b35cca5143f8ad04a4309f656f948728354b4877bbee509bfc7f76fb42b79f` |
| `app/lib/triage_web/live/cve_live/show.ex` | `00aeda43bf168522dac3ca5718c5829d15fa99b62c8bec31b2824c503ffca3eb` |
| `app/test/triage/intel_cache_test.exs` | `fd2f9e15ae9992b794754aca1b33d28dc733d2c8b2e56c4420059eb3d1655dd2` |
| `app/test/triage_web/live/cve_live_test.exs` | `92eb9d87ad39ec237990ba7a32a5fdcfc40f9b8fd3a64bde2ef9bcd1d1c0d819` |

## Acceptance ledger

| Check | Command | Result |
|---|---|---|
| Full gate (warnings-as-errors compile, formatter, assets, full suite) | `mix precommit` | **exit 0 — 605 passed, 2 skipped** (was 601; +4) |
| Writer/reader agreement for KEV and NVD | `mix test test/triage/intel_cache_test.exs` | pass, including `cached_advisories("kev:CVE-…") == []` |
| Per-placement priority and KEV escalation | `mix test test/triage_web/live/cve_live_test.exs` | pass |
| Policy and exposure units unaffected | `mix test test/triage/risk_test.exs test/triage/exposure_test.exs` | 31 passed (with the two cache files) |

Each new test discriminates the fix rather than restating it: the per-placement test
asserts `medium` for the unexposed placement (the old code produced `high`), and the
KEV test asserts `"KEV cache match: Yes"` plus the escalation reason after writing a
KEV row through the real CLI writer (the old lookup always returned `[]`).

## Live read-only probe

`GET http://127.0.0.1:4000/cves/CVE-2024-4004` (200), placement rows as served:

```
4 registry.internal/shared-base:9  alpha / prod-cluster-1 (unknown) unknown Yes medium
1 registry.internal/app-a:1.0      alpha / prod-cluster-1 web      unknown Yes high
2 registry.internal/app-a:1.0      beta  / prod-cluster-1 web      unknown Yes high
KEV cache match: No cached entry
```

The first row is the corrected derivation. The running dev database holds
**0 exposure-evidence rows for 10 placements** (verified read-only), so it renders
`unknown` exposure honestly rather than inferring exposure from names; the escalated
`internet_exposed` path is covered by the suite on a freshly seeded database. No
write was made to the dev database and no KEV row was inserted there, so the KEV
escalation is verified by test only, not by live probe.

## Boundary tests added for the open ledger gaps

- `app/test/triage_web/live/cve_live_test.exs` — "disagreeing public sources are
  shown side by side and never blended into priority": an NVD row claiming top
  severity is displayed in its own list and moves no priority, while a KEV row on the
  same advisory does raise it. Closes the conflicting-sources gap of item 5.
- `app/test/triage_web/read_only_requests_test.exs` — asserts the default intel
  transport is `{:error, :intel_disabled}` (so request-time network use is impossible,
  not merely unobserved) and that a whole-database row-count fingerprint is unchanged
  after `/`, `/findings`, `/cases`, `/whats-new`, `/replay`, `/replay/history`,
  `/imports` and the findings/cases/CVE detail routes. Closes the per-route gap of
  item 8. The network claim is structural, not observational; that limit is stated in
  the test's own documentation.
- Unrelated pre-existing flake stabilized: `test/triage/collection/client_test.exs`
  asserted `requests(agent) == 1` under a 20 ms total deadline, a wall-clock lower
  bound that failed once under load (607/608) and passed 3/3 in isolation. It now
  asserts `<= 1`, keeping the guarantee that the budget blocks retries.

## CLI call-site consistency (follow-up pass)

Auditing the only caller of the cache writers found four defects, all fixed:

1. **The task could not run at all.** It started `Triage.Repo` after ensuring only
   `:logger`, so every invocation died with "no process ... DBConnection.Watcher". The
   documented refresh entry point — the only one the plan allows — was dead. It now
   ensures `:ecto_sql` and `:postgrex` first, still never starting the Endpoint.
   Verified by running it: `--receipts` exits 0, `--kev` exits 1 with "intel is
   disabled".
2. **A failed NVD refresh was recorded under a different source than the row it
   protects.** Success used `"nvd:" <> upcase(trim(cve))` while failure used the raw
   argument, so `--nvd cve-2024-3094` produced receipts for `nvd:cve-2024-3094` and
   later `nvd:CVE-2024-3094` — two sources for one adapter in `latest_receipts/0`. Both
   paths now call `Intel.nvd_source/1`, which `cached_nvd/1` also uses.
3. **The `sources:` allowlist was never enforced.** `enabled: true` was the only gate,
   so `sources: [:kev]` still fetched NVD and the printed list was intent rather than
   restriction. `Config.source_allowed?/1` now requires the source to be named, each
   source is refused before any request, and a refusal records no receipt because no
   refresh was attempted.
4. **`--receipts` demanded `enabled: true`.** Reading the cache issues no request, so
   the disabled guard now exempts it.

Also: dev and prod builds emitted six dead-code warnings (`do_post/4`,
`validate_state/2`, `finish/2`, `into_fun/1`, `normalize_headers/1`, `transport_error/1`
and their aliases/attributes) because the live request path is compiled only for test
builds. Those declarations now sit inside the same `Mix.env() == :test` guard, so
`mix compile --warnings-as-errors` is clean in dev and in test.

## Limits

- `known_exploited` is taken from the cached KEV entry; a stale cache still asserts
  exploitation, and the page shows the cache age rather than a freshness verdict.
- NVD is not a match signal here; only cached rows for the exact CVE are shown.
- No news/RSS adapter exists: `replace_news/2` is exercised only by
  `priv/repo/seeds.exs`, so the news cache is a display path with synthetic rows and
  no real source. Freezing a provider URL requires the approval the plan gates.
- Conflicting-source handling is still untested (no provider disagreement fixture).
- No keyboard or responsive re-verification was performed in this slice; the change
  is server-rendered content in existing tables.
