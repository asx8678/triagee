# Presentation demo

## Ready-to-present defaults

Development starts with `TRIAGE_DEMO_MODE=true` by default. Fresh Review pages
preselect **Whitelist temporarily**, a three-month expiry and all active
placements of that CVE **inside the current team/environment scope**. The
**Whitelist now** button is enabled immediately. You can deselect placements
or choose either of the other two actions.

Opening a page does not save a decision, fabricate a reason, run Kiro or create
an Azure ticket. Whitelisting still requires your reason and an explicit
confirmation. Existing saved drafts—including a deliberate empty selection—are
preserved. Use **Discard draft** to start over with the new demo defaults.
Viewers remain read-only. `TRIAGE_DEMO_MODE=false` restores neutral defaults;
test and production default to false. Restart Phoenix after changing the flag.

## Expanded fictional estate

The additive seed contains **30 fictional CVEs** (`CVE-2099-9101`–`9130`),
**18 workload images**, **54 placements**, **seven teams**, and **prod / staging /
dev** environments. The infrastructure is represented through the existing image
and placement model, not a live cloud inventory integration:

| Team | Workloads |
| --- | --- |
| demo-payments | Checkout API, payment worker, billing scheduler |
| demo-commerce | Customer portal, catalogue API, order events |
| demo-identity | Identity provider, API gateway |
| demo-data | PostgreSQL, Redis, Kafka, OpenSearch |
| demo-observability | Grafana, OpenTelemetry collector |
| demo-platform | Linux CI runner, artifact registry, Windows batch pool |
| demo-edge | Retail edge agents |

Namespaces describe AKS West Europe, EKS US East, VM pools and EU edge locations.
Examples include public, internal and unknown network exposure, shared base
libraries affecting multiple services, and different decisions per environment.

The CVE identifiers, vulnerable versions and impact narratives are **invented**,
not vendor advisory claims. Every finding is explicitly labeled SIMULATED DEMO;
images use `demo.invalid`, and fictional advisories have no public URL. Exposure
is declared simulated evidence, never described as a verified cloud scan.

Install/re-run on the local development database:

```sh
cd app
mise x -- mix triage.demo --database triage_dev
```

The task requires the exact configured local database name. It adds missing cases
in a single transaction, serializes concurrent seed runs, and never resets
existing findings, decisions, drafts, timestamps or retired placements. Re-running
it is safe but intentionally does **not** undo presenter actions or renew expired
examples. Dates are relative to the first installation, so a later presentation
can naturally have different expiry states. No network requests or provider jobs
are started. Existing sample and user data are retained.

## Five-minute walkthrough

1. **Start here:** `/?page=review&team=demo-payments&item=CVE-2099-9101`.
   Show the public checkout API and three preselected environments. Narrow to
   `environment=prod` before typing a reason to demonstrate precise scope.
2. **Classify now:** run real Kiro on this explicitly fictional case. Scores and
   reasoning come from Kiro, not canned seed output. The normal analysis setup
   still applies; demo mode does not enable external providers.
3. **Whitelist:** enter a presentation reason and use **Whitelist now**. Review
   the affected deployments in the confirmation dialog before applying it.
4. **Compare all four queues:** Needs decision, In progress, Whitelisted and
   Reported fixed all contain examples. `CVE-2099-9108` has an open production
   deployment, a staging work item and a whitelisted development deployment.
5. **Tell a lifecycle story:** `CVE-2099-9113` has an expired exception;
   `CVE-2099-9106` has an exception expiring in two days;
   `CVE-2099-9124` reappeared after an older image was redeployed.
   `CVE-2099-9105` is only reported fixed; `CVE-2099-9112` additionally has a later
   simulated scan-clearance event. Use Timeline to show the differences.

The seeded In progress entries explicitly say **No Azure ticket was created**.
They have no fabricated external URL. Creating a real ticket still requires the
normal Azure configuration and manual confirmation. Existing review/coverage
warnings are not hidden for presentation.

## Acceptance checks

- Demo defaults are scoped, active-only, reversible and read-only for viewers.
- Manual deselection and edited drafts survive reload and scope changes.
- Whitelist reason/confirmation and the three-action limit remain enforced.
- Seed tests cover quantity, labeling, queue coverage, lifecycle variety,
  unchanged presenter edits and unrelated-data preservation.
- Runtime tests prove dev-on, test/prod-off defaults and strict boolean parsing.
- Verified locally: 21 focused checks and the full owned-database precommit
  suite (1,311 passed, 2 skipped). The real browser showed the enabled whitelist
  button, three selected deployments, seven demo teams and no automatically
  saved draft or decision.
