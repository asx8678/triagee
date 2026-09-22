# 07 — Compatibility, migrations, rollout, rollback

## Default strategy

Do presentation consolidation before broad domain additions. Keep existing runtime and storage. Add new semantics only through compatible readers and additive migrations. Never run setup/import/migration against an operator's working database without explicit authorization and a recovery plan.

## Routes and saved work

Keep `/` and `/workspace` resolving to the new Findings default. Prefer extending existing route helpers/query parameters rather than inventing a parallel router. The following are semantic mappings; inspect actual parameter names during M0.

| Old destination | New behavior |
|---|---|
| Overview | Findings / Needs attention, retaining team/environment and meaningful filter context. |
| Vulnerabilities/inventory | Findings with an equivalent operational active/all/history filter; do not silently broaden old filtered links. |
| Review with item/selection | Shared CVE detail in Findings; retain durable draft, original IDs/fingerprints, operation identity, and relevant filters. |
| Inspector with CVE/scope | Same shared detail, read context only; no automatic write selection. |
| Accepted/whitelist list | Exceptions or equivalent filtered register, preserving the source/scope. |
| Fixed/progress/history modes | Equivalent new filters and honest labels, not a redirect that loses records. |
| `/timeline` and old timeline windows | Read-only compatibility during transition. Preserve time window/scope and access to historical data until reporting/export replacement is proven. |
| News | No primary nav/fetch. A legacy route can explain relocation/retirement without fetching a public feed. |
| Older case/import/replay links | Preserve existing safe routing/backend behavior; do not re-enable retired mutation screens merely to retain a URL. |

Inventory/reference lookups must not become findings. Dirty-state guards must work across route aliases, browser Back, reconnect/reload, and scope changes. URL redirects never discard a pending ticket operation or silently change the target set.

## Legacy data treatment

Keep original IDs, decided_at/expiry metadata, action labels, authenticated/self-declared provenance, frozen snapshots, hashes, revisions, and ticket operation records. Add interpretation metadata only where justified. No speculative backfill that classifies every old whitelist as not affected or every old fixed as verified.

Workspace advisory decisions and case exceptions retain separate source identities. A union register uses `(source_kind, source_record_id)` as an unambiguous record key. Editing routes to the right domain or explicitly starts a new scoped assessment; it never overwrites legacy evidence.

Mixed old/global/scoped/new records must preserve chronological precedence and legacy expiry boundary behavior. New enum/action labels require all validation, SQL CASE expressions, serializers, readers, fixtures, and reports to be updated before writes are enabled.

## Rehearsal

Use an owned copy containing representative legacy cases, workspace decisions, global and scoped records, past/future/expired boundaries, new work rows, multiple reviewers, and durable ticket operations in pending/unknown/remote-created/completed states. Empty-database migration success is not sufficient.

Record pre/post counts and exact identities, parent-child/evidence links, immutable snapshot/hash content, chronological effective results, source labels, and valid operation recovery. Also test concurrent writes and rollback behavior. Do not claim whole-machine invariance from application row hashes; the scope of the comparison must be explicit.

Prefer reversible presentation switches. Once new labels/metadata are written, rolling back the UI must retain readers/schema that understand them. Do not drop columns, truncate new records, reset operation state, or deploy an older binary that silently ignores new labels.

## Release gates

1. Core acceptance IDs pass or remain explicitly blocked with owner-visible impact. Preserve unresolved older security requirements; general tests cannot substitute for missing original findings.
2. Representative migration/reconciliation and safe UI rollback are demonstrated on owned data.
3. Real application flows and responsive/error/reconnect states are captured, not just the static concept.
4. Source access controls, data redaction, opt-in integration boundaries, and no-automatic-write properties hold.
5. Query/memory observations cover realistic CVE and target fanout. State measured environment and remaining limits; no invented performance threshold claimed as achieved.
6. Deployment owner separately validates live Azure/AI/Grafana configuration as applicable. Mocked tests remain labeled mocked.

## Operational changes not authorized by this package

Production database migrations, live provider calls with real inventory, real ticket creation, secrets provisioning, external scanner suppression, public exposure changes, deployment, and remote pushes. The implementation can prepare and test these boundaries but must not execute them without the owner's separate authorization.

## Final report

Use `templates/IMPLEMENTATION_REPORT.md`. Include exact source SHA, changed files/tasks, acceptance outcomes, commands and exit status, fixture and time, screenshots, migration checks, source/reporting mappings, unresolved old gates, live-service limits, rollback steps, and outstanding decisions. Keep copied credentials and personal/customer data out of the report.
