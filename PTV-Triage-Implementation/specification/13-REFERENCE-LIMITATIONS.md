# 13 · Reference limitations and mandatory production distinctions

The accepted reference is deliberately a small offline interaction prototype. Its **appearance** is locked; its simplified business logic is not a production specification. The following points were identified by inspecting the supplied source, not inferred from a production repository.

| Reference shortcut | Production requirement | Visual impact |
|---|---|---|
|20 synthetic advisory records and a fixed sample clock | Real scoped data; fixed fixture only in isolated QA | Replace content, preserve geometry. |
| One supplied priority per advisory | Versioned scope-local priority; no higher out-of-scope priority leakage | Same badges/Why interface, truthful inputs. |
| Global client record array and event switch | Existing framework/query/mutation architecture | No aesthetic change. |
| Browser localStorage/session draft fallback | Existing authorized server/session draft model or explicitly approved storage policy | Truthful footer draft status. |
| `getDraft` intersects stored targets with current visible scopes | Preserve draft target identity; explicitly reconcile hidden/changed targets | Small contextual message when needed, not silent loss. |
| Inspector can fall back to all targets when no visible scopes remain | Explicit out-of-scope state and deliberate scope-broadening action | Empty-state variant only. |
| Inspector History displays advisory-level event array | Filter by target context and preserve legacy/global/unknown-scope distinctions | Same history rows, accurate content. |
| Sample coverage lanes and evidence/freshness text | Actual source/run completeness and observed/ingested times | Same coverage strip and qualifiers. |
| Sample intelligence/installed/fix assertions | Real source attribution; unknown/not fetched remains unknown | Same fact components. |
| Some “Available · not deployed” wording | “Available · not verified deployed” unless absence is actually evidenced | Minimal truthful copy correction. |
| Fixed due-date minimum/default and string-based sample validation | Real clock/timezone validation, inclusive expiry as next-day boundary | Same date field and confirmation. |
| Sample decision mutation directly changes client records | Atomic scoped server commit, history, concurrency and retry controls | Pending/error/conflict states within same layout. |
| No real expiry scheduler/multi-user versioning | Actual expiry/queue reconciliation and stale-form handling | Accurate current states, no silent renewal. |
| Simplified `navigate` clears some local search state | Preserve read context/Back semantics according to interaction contract | Same visible toolbar/layout. |
| Sample daily counts use the sample event model | Explicit distinct-CVE/target units and deduplication | Same heatmap and summary. |
| No real backend pagination | Complete matching set with explicit pagination/accessible virtualization | Keep table/track anatomy; add compact controls as needed. |
| Secondary Save hidden at intermediate compact widths | Keep save-without-advance accessible, using minimal footer reflow | Document narrow-screen correction; desktop unchanged. |
| Native dialog/basic fallback focus handling | Actual opener restoration and complete keyboard/assistive testing | Same drawer/modal visuals. |
| Ticket/AI unavailable | Real existing integration with explicit preview/confirmation, or honest unavailable state | Do not expose fake enabled controls. |
| Reset synthetic data | Demo/test only, never mislabeled production deletion | Omit in normal production settings. |
| Synthetic footer/dataset badges | Real workspace/source state in production; sample labels in QA | Preserve status-row dimensions. |

These are not authorization to redesign the app. Most require backend/state correctness with no visual change. Where a minimal state-specific UI correction is necessary, use the accepted primitives and record evidence. Do not copy prototype-only CSS/JS shortcuts blindly in pursuit of a screenshot while breaking the user's real workflow.

## What has not been inspected

No real repository schema, route names, package versions, APIs, migration history, integration configuration, authorization, persisted data or production runtime was provided. This package therefore includes detailed audit instructions and integration contracts rather than fabricated file patches against an unknown codebase.

## What the reference does establish

Exact accepted layout, spacing, font hierarchy, colors, controls, destinations, single-screen review composition, inspector dimensions/action placement, timeline arrangement, sample state interactions and responsive thresholds. These are concrete and testable inputs; do not treat them as optional mood-board suggestions.
