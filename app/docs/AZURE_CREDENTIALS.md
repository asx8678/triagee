# Azure DevOps credentials: setup and verification

This guide connects a ticket-creation token to the workspace review actions and
then verifies that the token can **create** work items but never **delete**
them. It documents exactly what the application can do with the token, the
least-privilege token and account setup in Azure DevOps, and a checklist that
proves the resulting configuration — because a leaked or misused credential
must not be able to destroy your tracker's data.

## What the application does with your token

The application contacts Azure DevOps for exactly one purpose: creating one
work item per explicitly confirmed ticket operation, and finding it again
during reconciliation. The complete request surface is:

| Request | Purpose | When |
|---|---|---|
| `POST {org}/{project}/_apis/wit/workitems/${type}?api-version=7.1` | Create the work item | After the operator confirms the preview |
| `POST {org}/{project}/_apis/wit/wiql?api-version=7.1` | Search by the operation's unique tag | Operator reconciliation after an uncertain outcome |
| `GET {org}/{project}/_apis/wit/workitems/{id}?api-version=7.1` | Verify the tag before trusting a search hit | Immediately after the WIQL search |

There is no code path that updates or deletes a work item: the transport has
no `PATCH` or `DELETE` call sites, and a regression test pins the request
surface so a future change cannot add one silently
(`test/triage/workspace_ticket_operations_test.exs` — "the ticket lifecycle
issues only create and read requests"). Every created ticket carries a unique
`triage-operation-<uuid>` tag and the request reference in its description,
so each item is traceable to the local durable operation that created it.

The retained legacy guided-review adapter (`TRIAGE_AZURE_*`, not used by the
workspace UI) also only creates work items; it has no update or delete path.

## Step 1 — Create a dedicated service account

Do not issue the token from a personal account.

1. Ask your Azure DevOps administrator to invite a dedicated user (for example
   `triage-tickets@yourcompany.example`) to the organization.
2. Give the account **Basic** access (Stakeholder access is not sufficient for
   all work item operations).
3. Do **not** add the account to any project group beyond what Step 3 grants.
   It needs no repository, pipeline, release, or test permissions — the token
   scope in Step 2 refuses them anyway.

## Step 2 — Create the personal access token

Sign in **as the service account**:

1. Open <https://dev.azure.com/{your-org}> → user settings → **Personal access
   tokens** → **+ New Token**.
2. **Name**: `triage-ticket-creation` (anything recognizable).
3. **Organization**: select your organization — *not* "All accessible
   organizations".
4. **Expiration**: the shortest practical lifetime (30 days is a good default);
   calendar a rotation reminder.
5. **Scopes**: choose **Custom defined**, then set exactly:
   * **Work Items → Read & write** (REST identifier `vso.work_write`)

   Nothing else. This is the narrowest scope that can create a work item —
   the token is refused by Git, Pipelines, Boards administration, and every
   other product API.
6. Create the token and copy it once. Treat it like a password: store it only
   in the server environment file (below), never in the repository, tickets,
   logs, or chat.

## Step 3 — Restrict the account's project permissions

The token scope cannot distinguish create from modify or delete — that split is
enforced with account permissions in the project. Using an explicit **Deny**
(which overrides any inherited Allow from group membership):

**Project-level permissions** (Project Settings → Permissions → select the
service account → Work item tracking):

| Permission | Set to | Effect |
|---|---|---|
| **Delete and restore work items** | **Deny** | The token cannot delete a work item, even to the Recycle Bin, and cannot restore one |
| **Permanently delete work items** | **Deny** | The token cannot destroy work items or their history |
| **Move work items out of this project** | **Deny** | The token cannot smuggle work items to another project |

**Area path security** (Project Settings → Boards → Project configuration →
Areas → the ticket area → … → Security): create one dedicated area path for
triage tickets, for example `Security\Triage`, and for the service account set:

| Permission | Set to | Effect |
|---|---|---|
| **View work items in this node** | Allow | WIQL search and work item GET during reconciliation |
| **Edit work items in this node** | Allow | Work item **creation** (this is the permission Azure DevOps checks for create) |

Set the same two permissions to **Deny** on every other area path, or simply
grant nothing anywhere else. Creating and reading then work inside
`Security\Triage` and nowhere else.

Finally configure `ADO_AREA_PATH=Security\Triage` in the server environment so
the application routes every ticket into that restricted area; without it the
creation lands on the project's default area path, where the account has no
permission and the preview will show an error.

## What the token can and cannot do (resulting capability matrix)

| Operation | Possible? | Enforced by |
|---|---|---|
| Create work items in `Security\Triage` | Yes — intended | Area path: Edit work items in this node |
| Read/search work items | Yes — required for reconciliation | Token scope + View work items in this node |
| **Delete** (Recycle Bin, restore, permanent destroy) | **No** | Project-level Deny: Delete and restore work items / Permanently delete work items |
| Move work items out of the project | No | Project-level Deny |
| Modify an existing work item | Not by the application (no code path, regression-tested); at the raw-token level an attacker holding the PAT could edit items *inside the restricted area* | Azure DevOps ties create to "Edit work items in this node", so edit cannot be denied while allowing create. Contained by: single-area restriction, Basic account with no other permissions, short token lifetime, and the organization audit log |
| Repositories, pipelines, releases, boards admin, tests, … | No | Token scope refuses (`401` for other products) |

The honest residual: **creation cannot be separated from editing in Azure
DevOps' permission model.** The enforcement goal "create but never delete" is
fully achieved; "never modify" is achieved by the application by construction
and limited at the credential level to the one restricted area path, where
any change is attributable in the audit log.

## Step 4 — Verification checklist

Run these with the finished token. Use a disposable work item in the restricted
area; deleting it afterward is fine because an administrator can restore it
from the Recycle Bin. Replace `ORG`, `PROJECT` and the token reference with
your values and always pass the PAT via `-u ":$ADO_PAT"` so it never lands in
shell history.

**4.1 Token scope is narrow** (expect a refusal, not 200):

```sh
curl -s -o /dev/null -w '%{http_code}\n' \
  -u ":$ADO_PAT" \
  "https://dev.azure.com/ORG/PROJECT/_apis/git/repositories?api-version=7.1"
# Expect: 401 — the Work Items scope cannot read repositories.
# If this returns 200, the token is broader than this guide: recreate it.
```

**4.2 Creation works** (expect 200 and a positive integer `id` in the response):

```sh
curl -s -u ":$ADO_PAT" \
  -H 'Content-Type: application/json-patch+json' \
  -d '[{"op":"add","path":"/fields/System.Title","value":"triage permission check"},{"op":"add","path":"/fields/System.Tags","value":"triage-permission-check"}]' \
  "https://dev.azure.com/ORG/PROJECT/_apis/wit/workitems/Task?api-version=7.1"
```

**4.3 Deletion is refused** (expect 403 for both, using the id from 4.2):

```sh
ID=<the id from 4.2>
curl -s -o /dev/null -w '%{http_code}\n' -X DELETE \
  -u ":$ADO_PAT" \
  "https://dev.azure.com/ORG/PROJECT/_apis/wit/workitems/$ID?api-version=7.1"
# Expect: 403 — Delete and restore work items is denied.

curl -s -o /dev/null -w '%{http_code}\n' -X DELETE \
  -u ":$ADO_PAT" \
  "https://dev.azure.com/ORG/PROJECT/_apis/wit/workitems/$ID?api-version=7.1&\$destroy=true"
# Expect: 403 — Permanently delete work items is denied.
```

**4.4 Application request surface** (no network needed):

```sh
cd app && mise x -- mix test test/triage/workspace_ticket_operations_test.exs
```

The "ticket lifecycle issues only create and read requests" test records every
request across a full create-and-reconcile lifecycle and requires exactly the
three documented calls — creation POST, WIQL search, work item GET — and no
others. Any modification or deletion route fails the suite.

**4.5 End-to-end through the application**: set the environment (below), start
the server, open a review, choose *Create Azure DevOps ticket*, and confirm.
The preview shows configuration errors before anything is sent. The created
ticket must appear in `Security\Triage` with the `triage-operation-…` tag.

## Step 5 — Wire the credentials into the application

The application reads these on each request; restart the release after
changing them. Never pass the PAT as a CLI argument or leave it in the checkout:

```sh
# /etc/triage/triage.env  (mode 0600, owned by the service user, outside the checkout)
ADO_ORG_URL=https://dev.azure.com/ORG
ADO_PROJECT=PROJECT
ADO_PAT=<the token>
ADO_WORK_ITEM_TYPE=Task
ADO_AREA_PATH=Security\Triage
# Optional display/routing labels:
ADO_BACKLOG="1 backlog"
ADO_TEAM="Receiving team name"
```

Then restart the service (`systemctl restart triage`) and confirm with the
preview dialog in the workspace. See [DEPLOYMENT](DEPLOYMENT.md) for the
environment file placement, file mode, and migration/restart ordering.

## Rotation and revocation

* Rotate before expiry: create the replacement token (Step 2), update
  `/etc/triage/triage.env`, restart the service, confirm with 4.2/4.5, then
  revoke the old token.
* Revoke immediately on any suspicion: user settings → Personal access tokens
  → Revoke. The application's durable operations keep their markers, so an
  interrupted creation can still be reconciled later by a reviewer with a
  working token.
* Review **Organization Settings → Auditing** for work item changes made by the
  service account; every triage ticket is identifiable by its
  `triage-operation-<uuid>` tag and the "Request reference" in its
description.
* If an unknown ticket is found during reconciliation, the application shows
  the marker and asks you to check Azure DevOps — it never deletes or modifies
  anything to "clean up".
