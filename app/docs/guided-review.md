# Guided action review

This documents the retained legacy guided-review backend and former UI procedure.
`/triage` and `/triage/:cve` now redirect to the workspace rather than mounting
these screens. See [README](../README.md) for current routes and
[Review actions](REVIEW_ACTIONS.md) for the separate workspace `ADO_*` integration.
The `TRIAGE_AZURE_*` and AI contracts below still describe the legacy adapters.


`/triage` is an action-required queue across all severities, with one card per CVE. `/triage/:cve` guides the operator through description/libraries, teams and exposure, explainable local risk, and a final human action. Historical assessment tools remain at `/triage/history`. Fixed and scanner-suppressed occurrences, inactive placements, actively covered whitelist scopes and scopes with confirmed remediation tickets are excluded. A partial whitelist never hides uncovered teams. Ticketing is not a deployed fix. Queue priority is local policy, not a fabricated CVSS score.

Run migrations before use: `cd app && mise exec -- mix ecto.migrate`.

## Azure DevOps

Set server environment variables and restart:

- `TRIAGE_AZURE_ORGANIZATION`: organization name (not a URL).
- `TRIAGE_AZURE_PAT`: secret PAT with Work Items read/write permission for the intended projects. Never commit it.
- `TRIAGE_AZURE_TEAMS_JSON`: JSON keyed by exact inventory owner, for example `{"Zuzia":{"project":"Infrastructure","area_path":"Infrastructure\\Zuzia","work_item_type":"Task"}}`.

No team/destination is guessed. Unknown or unmapped teams block confirmation. The final step shows ticket content and every destination before an explicit **Confirm: create N team tickets** click. There is one request per CVE/team/current affected-scope fingerprint. Multiple libraries/environments for the same team are combined in its ticket. A newly observed scope or reopened finding creates new work rather than being silently covered by an old ticket.

`Mark to be fixed` persists a local plan without contacting Azure. Confirm sends HTTPS JSON Patch to Azure DevOps API 7.1, using the configured area path for team routing. The application does not guess an individual AssignedTo identity. The queue is read-only until a user explicitly chooses an action.

Each request is durably claimed before the external write; successful ticket IDs and URLs are retained. A definitive rejection may be retried after configuration is corrected. Timeout, unexpected response, process interruption (`sending`), or ambiguous result (`unknown`) never auto-retries: an administrator must reconcile it against Azure first. This release intentionally has no blind force-retry button. Partial successes are retained and excluded from the next preview. Scope/destination/content changes invalidate the confirmation fingerprint.

This application uses the existing `local-operator` identity and loopback-only listener; this is not an authenticated enterprise approval service. Keep credentials and machine access appropriately restricted.

## Internal AI (Kiro / Keiro)

The organization's CLI contract was not supplied. `TRIAGE_AI_EXECUTABLE` therefore names an **absolute path to an administrator-maintained, read-only adapter executable**, not a shell expression or an assumed vendor CLI command. Adapt this wrapper to your actual internal CLI. It receives one JSON argument containing CVE descriptions and affected-team/service/exposure evidence, and must return only:

```json
{"recommendation":"investigate","reason":"Explain the evidence and uncertainty."}
```

Allowed recommendations: `whitelist`, `fix`, `investigate`. Exit status must be zero. The application enforces a 30-second deadline, 64-KiB output limit and 8-KiB reason limit. Disable tool execution and external side effects in the wrapper; the app cannot sandbox arbitrary administrator-installed executables. Treat CVE descriptions as untrusted data, never instructions. The operator explicitly runs the assessment and sees what context is shared. No credentials are included in the input. Output is escaped and advisory only: AI never whitelists or creates tickets.

When configuration is missing, the UI explicitly says unavailable; it does not fabricate advice or ticket success. Actual internal-CLI connectivity and live Azure writes must be validated by the deployment owner after providing these settings. Automated tests use a fake Azure adapter and do not create real tickets.
