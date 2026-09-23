# Kiro classification in Review

## What changed

Classification is part of **Review**, not a separate screen or approval form.
Select a CVE and click **Classify now**. A durable Oban job invokes Kiro in headless
mode; Phoenix validates the response and displays its scores and reasoning in the
CVE's Review panel. The job continues if you navigate away or disconnect. Reopening
the same scoped CVE restores its saved result.

This implementation chooses **headless mode**, not a persistent ACP session. It
uses the installed CLI's documented noninteractive contract:

```text
kiro-cli chat --no-interactive --trust-tools= --agent triage-classifier --wrap never --effort low [--model MODEL] PROMPT
```

The CLI is launched directly with argv, not through a shell. Kiro handles model
inference. Phoenix does not call an OpenAI-compatible model endpoint.

## Setup

Apply migrations, authenticate Kiro under the service user's account, then start:

```sh
cd app
mise x -- mix ecto.migrate
TRIAGE_ANALYSIS_ENABLED=true \
TRIAGE_KIRO_CLI=/absolute/path/to/kiro-cli \
mise x -- mix phx.server
```

`TRIAGE_KIRO_MODEL` optionally selects/pins a model. When omitted, Kiro chooses its
configured default; a default model is not a reproducible pinned model identity.
The app uses Kiro's existing login, not an application-provided model API key.
Restart Phoenix after changing runner/model configuration. For releases, supply
these variables through your normal service configuration.

Analysis remains **off by default**. An installed binary alone does not enable it.
Only authenticated reviewers/admins may request classification. The development
local-user account can use it when the server administrator has enabled Kiro.
Opening a page, importing data or reconnecting never starts a model call.

The previous `TRIAGE_CLASSIFIER_ENABLED` / `TRIAGE_CLASSIFIER_AUTOMATIC` flags must
be unset or false. Enabling them now fails with migration guidance rather than
silently running the old HTTP classifier. Its stored experiment records remain in
the database; its standalone UI and automatic schedule are no longer public.
`/classifier?cve=...&team=...&environment=...` redirects into the matching Review.

## What Phoenix passes to Kiro

A server-captured JSON snapshot for **all deployments of the selected CVE in the
current team/environment scope**, not just the decision checkboxes:

- All finding descriptions (not truncated), packages/versions, severities, URLs,
  scanner fixes, first/last observation, suppression/resolution/reopen information.
- Placement identity, owner/environment/namespace, active state and image identity.
- Exposure evidence, provenance, freshness/trust and deterministic risk reasons.
- KEV facts and generation currency, current decisions and coverage state.
- Exact packet/fingerprint identities and known missing register/scan provenance.

The full input and accepted response are retained in `review_classifications`.
Reviewer drafts, session tokens and application credentials are excluded. Missing
upstream data remains explicitly missing; this does not add live Grafana/register
collection. Oversized input is rejected, not silently summarized or truncated.
The reviewer can narrow the team/environment scope and try again.

## Scores and decisions

- **Risk score (1–100):** Kiro's assessment of operational danger. Higher is riskier.
- **Whitelist suitability (0–100):** Kiro's assessment of support for scoped
  non-applicability. Higher means stronger support, not an exploitation probability.
- **Reasoning and recommendation:** investigate, remediate, request verification,
  or a proposed risk-acceptance candidate.

Scores are model-generated guidance, not calibrated probabilities or approvals.
Missing evidence is not evidence of safety. A high suitability score (70+) or a
risk-acceptance recommendation is blocked pending independently verified scoped
non-applicability; its raw score/recommendation remain stored for audit. The UI
shows a blocked state rather than inventing a replacement numeric score. KEV
whitelist attempts receive an additional explicit blocker.

Classification never changes a draft, decision, whitelist/tag, finding, repository,
Azure work item or fix status. Use the existing manual decision/confirmation flow.
Different deployments are supplied individually; the model is told not to average
away a dangerous scope. The overall scores still require human judgment.

## Execution and persistence boundaries

`priv/kiro/triage-classifier.json` has no tools, allowed tools, resources, hooks or
MCP servers; loading external MCP configuration is disabled. Each run starts in a
fresh private temporary directory containing only this agent configuration. No
repository is mounted as its working directory. The child environment excludes
application secrets; only basic OS/login-location variables are retained. Kiro can
access its own login/session storage. This is capability-restricted inference,
**not an OS/container sandbox certification** or a provider data-retention guarantee.

Input is bounded to 128 KiB; output to 64 KiB; execution to 120 seconds. The process
owner also monitors the job, tears down the process tree on timeout/cancellation,
and cleans its temporary directory. Only a strict four-field JSON result with
integer scores and bounded rationale is accepted. No tool requests are executed.

Run intent and Oban job insertion are transactional. Concurrent clicks for the same
current input share one pending run. Completed or failed runs may be explicitly
classified again. There are no automatic retries or auto-discovery jobs. An
interrupted pending run is shown as interrupted after three minutes and can be
replaced by an explicit click; an uncertain call is never silently repeated.

The exact stored input determines its signature. Changes to evidence, URLs,
exposure trust/currency, KEV generation/currency, prior decisions, scope, model or
agent profile invalidate scores. Results expire after 24 hours at the latest.
Publication checks the evidence and requester again; reads also recheck currency.
Draft-preserving workspace refreshes invalidate scores without overwriting drafts.

## Acceptance ledger / verification

- K01: Installed Kiro agent config validated with `kiro-cli agent validate`.
  A real headless call with synthetic evidence returned valid scored JSON.
  Synthetic CLI tests cover headless arguments, no tools/MCP/resources, sanitized
  environment, private working directory cleanup, deadline and output cap.
- K02: Context tests cover full descriptions and all deployments in the selected
  scope, unknown provenance, credential exclusion and explicit oversized rejection.
- K03: Tests cover pending-job deduplication, repeat execution, result persistence,
  reconnect, changed evidence/URLs/model, revoked requester and interrupted runs.
- K04: LiveView tests cover Classify now, both scores, honest disabled/error states,
  guards, result delivery after navigation and preservation of manual drafts.
- K05: Route/config tests verify redirect-only legacy links, no separate navigation,
  default-off Kiro configuration and rejected retired HTTP-classifier flags.
- K06: Full owned-database precommit: 1296/1297 passed, 2 skipped. The only failure
  was missing artwork for a new icon; replaced it with a registered icon. The
  affected UI/asset suites (including the added reconnect/stale-draft test) then
  passed all 29 tests. Earlier focused workflow/configuration suite: 34 passed.
  Final durable-job suite after the pending-expiry guard: 11 passed.

Real-provider checks used synthetic data only. In a clean Chrome session, the
Review button classified the explicitly fictional `CVE-2099-9005` presentation
fixture through the real background worker and Kiro. Both scores appeared and
survived a full page reload. At 390px viewport width, page/card widths showed no
horizontal overflow, the enabled button retained readable contrast, and lengthy
reasoning was collapsed with the complete explanation still available.

No operational decision, SCM action or Azure request was made. Compilation,
formatting and diff integrity passed. Strict Credo retains only the unrelated
pre-existing nesting warning in `lib/triage/seeds/timeline_samples.ex:23`.
Contour does not cover these Elixir changes; its empty findings are not used as
correctness evidence.
