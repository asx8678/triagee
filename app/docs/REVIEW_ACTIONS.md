# Review actions

Review offers three next actions for the selected deployment scopes:

- `fixed`: saves today's UTC decision timestamp and `metadata.fixed_at`, no comment/owner/date needed. Appears in Fixed. Scanner findings remain unchanged.
- `accepted_risk`: temporary whitelist. Defaults to today plus three calendar months (clamped to the last valid day of the target month). The date may be overridden. Comment defaults to `Reviewed for this environment: this CVE does not currently affect our infrastructure. Reassess at the whitelist expiry date.` and can be replaced or cleared. Coverage ends at midnight UTC after the chosen date; on the next read/refresh, expired scopes return to Needs decision.
- `create_ticket`: creates one Azure DevOps work item for the CVE and selected scopes, then saves its URL in decision metadata. Appears in In progress. The ticket link is in Full evidence / decision history. Existing decisions remain readable.

No owner or self-declared identity input is required. Local decisions use `Local workspace` as the internal actor; this is not authenticated identity.

## Azure DevOps configuration

Set these in the server environment and restart the server. For a least-privilege token setup and a verification checklist, see [Azure credentials](AZURE_CREDENTIALS.md).

- `ADO_ORG_URL`, e.g. `https://dev.azure.com/your-org` (HTTPS required)
- `ADO_PROJECT`
- `ADO_PAT` (secret, work-item write permission; never enter it into a CVE comment)
- `ADO_WORK_ITEM_TYPE`, e.g. `Task` or `Bug`, valid for your project

The JSON Patch work item contains the CVE ID, NVD link, selected deployments, image digests, exposure, package names/versions, severities, fix information, descriptions and observation timestamps. No extra user fields are required. An unconfigured server or rejected request shows an error without recording a successful decision.

Clicking Create Azure DevOps ticket opens a preview; only its Create ticket confirmation sends a POST. Cancel sends nothing. Configuration or API errors remain visible inside the preview.

- `ADO_BACKLOG`: display label, defaults to `1 backlog` (no PTV prefix).
- `ADO_TEAM`: display name of the receiving team.
- `ADO_AREA_PATH`: actual Azure DevOps area path owned by that team; when provided, submitted as `System.AreaPath`. Without it Azure uses the project's default area. Configure this to route to the intended team's backlog. A display label does not create or select an Azure backlog.

Azure assigns work items to individual identities, not teams: team routing is through the configured area path, not `System.AssignedTo`. Title: `<CVE-ID> needs to be fixed`. The preview uses the same escaped description payload as creation: a risk-reduction rationale followed by the full CVE/deployment evidence and NVD link. No claim of confirmed exploitability is made. POST retries and redirects are disabled. A replay of a successfully saved operation returns its existing decision without creating another ticket. Azure DevOps and the local database are not a distributed transaction: on a timeout or a local persistence failure after remote success, check Azure DevOps before retrying (the operation ID is included in the description). Automatic exactly-once recovery across such failures is not implemented.

## Human-readable description

The preview and Azure work item share formatted headings, paragraphs and bullet lists, not a JSON evidence dump. Missing fields are omitted and all source text is HTML-escaped.

Example (rendered text):

> **Summary**
> CVE-2024-1234 was reported in the selected deployment scopes.
>
> **Why this needs to be fixed**
> Remediate the reported vulnerable components to reduce security risk. Review severity, exposure and available fixes in the evidence below; scanner detection alone does not prove exploitability.
>
> **Affected components and details**
> - Environment: production
> - Package: example-library
> - Package version: 1.0
> - Severity: high
>
> The vulnerability description appears here as a paragraph.

Fixed and whitelist actions work without Azure DevOps access. Real Azure DevOps creation requires credentials; automated tests use Req.Test, not a real organization.
