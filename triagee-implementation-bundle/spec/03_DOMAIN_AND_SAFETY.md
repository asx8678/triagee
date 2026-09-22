# 03 — Domain semantics and safety invariants

## Reuse, do not replace

The source baseline already has a scoped workspace read model, SQL filtering/pagination, authenticated commit overloads, durable draft/operation concepts, evidence hashes, and distinct historical case/exception stores. The source map identifies entry points. Verify exact current APIs before implementing; proposed schemas in this bundle are not current Ecto structures.

A finding is a package occurrence for a CVE in an image. A placement is an image's deployment context. A writable workspace target is `{CVE, placement_id}` and includes the complete relevant package evidence for that target. One CVE table row is not a permission boundary.

## Separate facts from conclusions

Expose the following as read-model dimensions, not necessarily four new database tables:

| Dimension | Examples |
|---|---|
| Observation | Present in a recorded artifact; no longer observed; source unavailable; scanner suppressed. |
| Assessment | Unassessed; risk accepted; not affected; legacy/unknown classification. |
| Workflow | None; investigating; remediation requested; ticketed; awaiting verification. |
| Verified outcome | None; evidence-supported remediation or mitigation verified. |

Do not combine obsolete records to resurrect a prior acceptance. The current chronological supersession policy remains authoritative: future decisions cover nothing, a newer decision can supersede an older global record, and expiry of a newer record must not revive an older acceptance. Read-model dimensions are not permission to change those rules implicitly.

## Required invariants

I01. New UI writes require explicit stable target IDs; no implicit all-placements or null/global target fallback. Preserve labeled legacy global records read-only under their original semantics.

I02. Filters and team names do not authorize access. Server-side role checks remain mandatory; do not represent the current application as tenant-isolated merely because it has team filters.

I03. Web mutations derive actor/user ID from the authenticated principal. Never expose the trusted legacy self-declared API as an authenticated web action. Preserve controlled development-only login behavior; do not create a production bypass.

I04. Complete server-captured evidence and selected target membership are revalidated on commit. Never trust browser-supplied hashes, model-proposed target expansion, or a page-sized subset of a large target as full evidence.

I05. New drafts have no action, conclusion, or automatically selected write targets. Saved drafts retain original IDs/fingerprints/operation identity across navigation and reconnects.

I06. Decisions append history; they do not mutate scanner observations into safety or remove findings. Do not delete evidence to reduce noise.

I07. Risk acceptance and not-affected are distinct. A not-affected assessment requires explicit applicability justification for every selected target. A package match plus unknown exposure does not establish it.

I08. An exception requires exact scope, nonempty rationale, valid evidence references, authenticated reviewer, and a validity/review boundary. Renewal is a new decision, never silent extension.

I09. Material evidence changes invalidate affected conclusions or require reassessment. A mere repeated timestamp on otherwise identical evidence should not cause a new human task. Define materiality in code with tests, not free-text AI judgment alone.

I10. A reported remediation, absent scanner finding, closed ticket, or scanner suppression is not verified remediation. Verification needs trusted post-change evidence bound to the deployed artifact/mitigation and reviewed scope.

I11. Ticket preview/confirmation, operation deduplication, durable remote-success recovery, and unknown-outcome reconciliation survive. Do not create an operation with a new ID to evade an existing pending claim. No external POST inside database locks.

I12. No unexpected network calls from list navigation, sorting, filter changes, render, or reconnect. Research, intelligence refresh, AI, and ticket writes retain explicit boundaries. No automatic scanner suppressions are included.

I13. Preserve each case/assessment/exception store's revision and evidence semantics. A unified register may project multiple sources but must not edit a case record through an approximate advisory-decision API.

I14. Old readers, migrations, and reporting must understand new labels before they are written. A UI rollback retains compatible readers and additive schema; no destructive downgrade after new records exist.

## Decision lifecycle

Risk accepted / not affected: draft → previewed → explicitly recorded → valid → review due → expired, invalidated, revoked, or replaced. “Review due” within the lead window does not mean already expired. Pending future decisions do not cover scope. Archived history remains visible.

Use the currently supported accepted-risk action as the migration starting point, not as a stand-in for not affected. Add a typed not-affected path only after mapping existing case APIs and the current advisory-decision validation/readers. If none matches the exact workspace scope, extend the domain additively. Do not implement a not-affected button that writes accepted_risk.

Remediation: local plan/investigation/ticket → remediation reported → awaiting verification → verified outcome. A verification request should use the existing compatible work mechanism where appropriate. Add a true verified-outcome representation only with evidence requirements and compatible readers. Failed or inconclusive verification retains work/attention; it is not automatically a new exception.

Old `fixed` records remain historically labeled as such but display as reported remediation/legacy unverified unless specific preserved verification evidence supports more. Do not mass-rewrite them as verified or silently delete their prior meaning. Active targets without a supported verification conclusion may receive a verification-needed attention reason; deduplicate that work once a current verification task exists.

## Validity boundaries

For new workspace decisions, the date picker means valid through the selected UTC date; store the exclusive boundary at 00:00 UTC on the next day with explicit boundary metadata. At the exact boundary, the exception is expired. This matches the newer workspace convention described by current source, but older records may use inclusive timestamp semantics. Preserve their metadata and reader behavior; never normalize legacy timestamps by guessing.

Use a frozen clock in tests. Validate empty/past dates server-side. Review-due defaults to the seven days before expiry; keep this as a small versioned policy constant initially. SQL and Elixir must use the same captured `now` for a page/read.

## Evidence changes and requeue

Material examples: artifact identity or package/version membership change; changed exposure or required configuration; new affected placement; changed relevant applicability/advisory evidence; new exploitation intelligence; expiry; meaningful policy change. Reassess only the affected targets. A changed sibling must not silently broaden or invalidate unrelated decisions unless a shared evidence dependency actually changed.

Inventory-derived hashes already exist; audit which values they include. Do not claim existing effective decisions bind to newly introduced AI/policy/context fields unless readers verify those fields. Preserve previous evidence even when a new assessment becomes necessary.

Identical scans can update observation history without creating repeated decisions, tickets, or AI calls. UI history may collapse repetitions while maintaining count/time range and access to raw records.

## Proposed deterministic action priority

This is a local product policy, not an external security standard. Implement one versioned policy and keep database/application projections equivalent. Determine reasons only from known, relevant, authorized evidence; missing data never becomes a positive safety fact.

For active targets with an attention/work reason, initial context bands are:

| Rank (smaller first) | Rule |
|---|---|
| 0 | Known exploitation signal AND confirmed internet exposure AND production scope. |
| 1 | Known exploitation in another scope, or critical severity with confirmed internet exposure. |
| 2 | Exception due/expired/materially invalidated, overdue work, production exposure unknown, or an unresolved operation requiring reconciliation. |
| 3 | Other actionable/in-progress targets; include patching, investigation, and verification needs. |
| 4 | No current action: valid coverage/historical records retained in All tracked. |

Within a band: applicable due timestamp ascending, then scanner severity descending, then stable CVE identifier and target ID. Null due dates sort last. Use the most urgent contributing target in the current filter scope to order a CVE row; do not use urgency from a filtered-out deployment. Display the strongest actual reason and allow inspection of all reasons. Unknown environment does not equal production, and unknown exposure does not equal internet exposure.

A high-severity exploited/public production target must be able to precede an unexposed critical target. Do not merely rename the current severity-first order. Priority determines ordering, not exception validity, authorization, or proof of compromise.

Keep the first implementation small. Do not add a generic rule builder, composite numerical risk score, ML ranking, or EPSS dependency. Policy changes require parity tests, versioning, and documented requeue effects.

## Bounded reads and concurrency

Preserve SQL-side filtering/counts and bounded CVE hydration. Current source uses a 50-CVE page and OFFSET; do not describe it as keyset pagination. Evidence for a selected CVE may still be large. Page the presentation without truncating the target membership/evidence used for a decision. Record query-plan and memory behavior against a representative synthetic volume before making performance claims.

Test simultaneous import/decision/expiry and multiple reviewer sessions. Counts, IDs, and hydrated rows must be internally consistent at the chosen snapshot. Keep operation conflicts visible; do not retry source-lock failures in an unbounded loop. Existing lock strategy may deserve later optimization, but removing it is not a UI simplification.
