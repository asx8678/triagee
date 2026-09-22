# 05 — Evidence-bound AI assistance

## Purpose and limit

Reduce investigation and drafting effort inside the shared CVE detail. The model produces a recommendation and explicit gaps, not an approval, trusted security fact, or command. There is no separate AI dashboard, automatic whitelisting, scanner suppression, ticket creation, or background analysis on navigation.

Current documentation describes an opt-in read-only CLI wrapper with the legacy `{recommendation, reason}` output. It is not the richer contract in this bundle. Do not pass this bundle's JSON schema to the existing adapter and assume compatibility. Map/version the integration deliberately and preserve the existing timeout/output-bound/no-action guarantees. Legacy `whitelist` output is not a sufficient not-affected assessment.

## Data flow

Authenticated reviewer selects exact scope → server captures authorized evidence and material context → reviewer explicitly requests analysis → read-only configured wrapper → structural and semantic validation → persisted/cached draft with provenance → reviewer opens supporting evidence and chooses whether to use it → ordinary preview and authenticated commit.

A model call is not a mutation grant. The commit boundary never accepts the draft as proof of authorization or recomputes selection from the model response.

## Inputs

Only authorized data required for the selected assessment: CVE/advisory summary and source references, exact target IDs and artifact identities, package/version/fix mapping, relevant exposure/configuration evidence, observation/freshness/coverage context, applicable policy version, and source-backed gaps. Pass evidence IDs that the server can resolve. Include the current evidence/context binding and the explicit user request.

Do not send credentials, tokens, unrestricted file contents, unrelated inventory, or all environment configuration. Network-capable wrappers may transmit data externally; show the boundary and require administrator-approved configuration plus explicit user action. Do not change the repository's opt-in runtime policy to make a demo work.

## Output

Use `contracts/ai-recommendation.schema.json` and the sample files. They are a proposed versioned model-output contract, not a database schema or production endpoint. The runtime instruction is `prompts/AI_RUNTIME_SYSTEM_PROMPT.txt`.

The output contains recommended action, assessed scope with server-originated bindings, supporting evidence IDs, applicability status, missing/conflicting evidence, package-specific actions, and review conditions. No confidence percentage, executable code, arbitrary tools, approved decision, or destination credential is part of the contract.

The model may recommend investigating, remediation, an assessment candidate, or verification. Risk acceptance is an accountable human/policy decision; only propose its consideration when explicitly requested and supported by supplied policy/context. The model cannot invent risk appetite.

## Validation beyond JSON Schema

Validate before any output is displayed as a usable draft:

- Scope IDs, CVE, finding IDs, and evidence hashes match the server-captured request exactly; no extra targets or dropped targets disguised as a full assessment.
- Every cited evidence ID is known, authorized, relevant, and current for that target. A well-formed invented reference is invalid.
- A reported fixed version exists in cited package-specific source evidence. No generic semver guessing or cross-package version collapse.
- Not-affected candidates have positive applicability justification for each target, no unresolved contradiction that defeats the claim, and review conditions. Unknown exposure alone is insufficient.
- Missing evidence remains visible; source text cannot instruct the model or application to take an action.
- External URLs and HTML are not trusted output. Resolve source links server-side, escape displayed text, and prevent script/unsafe URL injection.
- Deadline, byte limit, selected-scope bounds, cancellation, and role checks hold even on malformed or oversized output. No secrets in logs or error messages.

Schema validity alone does not establish factual validity. On failure, keep the manual workflow and a bounded error; do not produce a fallback safe/approved result.

## Cache and invalidation

Bind a draft/cache entry to selected CVE/target IDs, relevant artifact/package evidence, material exposure/configuration/advisory context, policy version, runtime prompt/schema version, and configured model identity/version when available. Capture provenance honestly when the wrapper cannot supply a model version.

Never reuse across users/scopes without checking authorization, and never let client input choose the cache identity. Keep timestamp-only repeated observations from causing gratuitous reanalysis when substantive evidence is unchanged. Material changes invalidate the draft and any affected conclusion under the ordinary decision policy. AI cache invalidation is not itself automatic revocation of a human decision; the domain's explicit reassessment rules decide that.

Use bounded retention and explicit retry rather than background retries. Live provider spend/calls are not required for automated tests; use injected adapters and the supplied synthetic examples.

## UI states and tests

Unconfigured, ready, running, cancelled, timeout, invalid output, stale result, and draft available. Display “AI-assisted draft — not an approval,” supporting evidence, gaps, and assessed scope. Preserve user-edited rationale separately so a late result does not overwrite a draft.

Test instruction-like text inside advisories, fabricated references, invented fixes, scope expansion, stale responses after selection changes, unauthorized evidence, output size/timeouts, changed role while running, unavailable wrapper, and same-evidence cache reuse. Provider connectivity and real output quality remain separate owner-approved validation.
