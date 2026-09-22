# 06 — Shared reporting and Grafana boundary

## Responsibility split

Triagee owns current scoped findings, evidence-backed assessments, work ownership/ticket references, exceptions, and per-CVE audit history. Grafana owns time trends, estate/team/environment summaries, aging, overdue work, remediation outcomes, and collection-status reporting. Do not duplicate charts in both applications.

No Grafana deployment or working integration was validated when preparing this package. Discover the real integration in M0. Reuse it where suitable; do not invent a backend, datasource URL, or deployed dashboard. The target is a shared projection with accurate semantics and a configured link, not a promise of live Grafana availability.

## Proposed snapshot projection

`contracts/reporting-target.schema.json` specifies a proposed row shape for one `{CVE, placement}` at one captured snapshot. It is a contract proposal, not an existing public API. Map it through a domain projection rather than adding columns named after every UI label.

Essential dimensions: snapshot/policy version, CVE, placement/image identity, environment/team (nullable), observation state, typed effective assessment and validity/source, workflow, verified outcome/evidence references, attention reasons/priority, package-specific installed/fixed information, and collection/freshness limitations.

Use a separate snapshot envelope for captured time, source status, completeness, and applied filters. Page and aggregate within the same logical snapshot. The sample contract does not mandate a new HTTP endpoint; a read-only SQL view or current API may be better after repository discovery. Do not expose raw writable tables or trust a dashboard filter as authorization.

## Counting definitions

| Measure | Meaning |
|---|---|
| Recorded-present CVEs | Distinct CVEs with at least one operational target whose current recorded observation is present. Not a claim of full live coverage. |
| Attention CVEs | Distinct CVEs with at least one qualifying target under the same predicate as Needs attention. |
| In-progress CVEs | Distinct CVEs with at least one current work target; may overlap attention. |
| Accepted-risk targets | Exact currently valid risk-accepted targets; not remediated and not removed from recorded-present totals. |
| Not-affected targets | Exact valid assessed targets; separate from accepted risk and observed scanner matches. |
| Verified-remediated targets | Targets with qualifying explicit verification evidence; not old fixed flags or merely closed tickets. |
| Exception review due | Exact exception records/targets due within the policy window; state/counting unit explicitly labeled. |
| Exposure unknown | Target count, not automatically distinct CVEs. |
| Source completeness | Known collection/coverage state with timestamps and failures; unknown is a valid output. |

A CVE can span teams, so per-team distinct CVE counts are not additive. Target counts and CVE counts cannot be substituted. Zero returned rows after a source failure is not zero vulnerabilities. Graph risk acceptance and remediation separately. A scan result disappearing or being suppressed must not appear as a verified-remediation event.

## Time series

A current snapshot cannot reconstruct historical truth. Use recorded observation/decision events or intentionally captured snapshots with documented semantics. Do not infer daily remediation counts from today's effective state. If historical coverage is incomplete, state the covered range and limitation. Preserve the old Timeline's recorded-observation caveats during migration.

## Drilldowns and links

Each actionable record links back to the same CVE and exact placement context, with a view/filter that includes it. The server validates the link, resolves authorized data, and does not auto-select write targets. Prefer existing internal route helpers and encoded parameters; do not build an open redirect from arbitrary dashboard input.

For large scope sets, use a server-resolved authorized selection reference rather than stuffing hundreds of IDs into a URL. Do not include credentials or sensitive evidence in query strings. Opening a Grafana link may contact that configured service; ordinary Findings navigation must not call Grafana in the background.

## Implementation acceptance

Test the same deterministic snapshot through the domain projection, SQL query, UI counts/drilldowns, and reporting adapter. Assert IDs and targets, not just aggregate totals. Test cross-team CVEs, mixed states, expired/invalidated exceptions, legacy fixed/global records, reference-only records, and unavailable sources. Document retention, cache/freshness, and access policy. An example adapter or mock does not certify a live dashboard.
