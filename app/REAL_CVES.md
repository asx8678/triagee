# Real CVEs in local triage

The development seed is a checked-in download of **95 unique real NVD CVEs**:
**30 critical, 40 high, 20 medium, 5 low**.

`priv/reference/nvd-cves.json` contains raw NVD receipts and SHA-256 hashes,
normalized descriptions, source URLs, metric author, CVSS version/score/vector,
publication/modification dates and affected-product CPE/range evidence. The sample
uses NVD publication dates **2025-01-01 through 2025-03-31**; IDs may have earlier
years. It is not a latest-threat feed or a complete vulnerability database.
Initial fetch: **2026-09-16T17:00:31Z**. Source:
https://services.nvd.nist.gov/rest/json/cves/2.0 and https://nvd.nist.gov/.
This product uses NVD data but is not endorsed or certified by NVD/NIST.

## Install or replace fake development data

Fresh development setup (`mix setup` or `mix ecto.seed`) loads this file **offline**.
For an existing local database, in `app/` with the intended database configuration:

```sh
mise x -- mix triage.reference --check
mise x -- mix triage.reference --preview
mise x -- mix triage.reference --apply --database triage_dev
```

Use the exact intended configured database name. Apply verifies configured and
actual identity and requires loopback database configuration. It never starts
Phoenix or runs migrations, database resets or credential changes. Take your
normal backup and inspect the preview first. Apply any pending migrations from
earlier work separately before using the application.

The read-only probe of `127.0.0.1:5432 / triage_dev` was rejected with
`fe_sendauth: no password supplied`. The running database was **not** replaced
in this session. Configure its authorized PostgreSQL access before preview/apply;
do not put credentials in command output or commits.

## Safety and scope

- Only exact known synthetic fixture images and expected package/scope tuples
  are retired. Additional data on those images causes refusal, not broad deletion.
  Unrelated imports are preserved, even with the same CVE ID.
- Retirement makes demo placements inactive, not findings remediated. Old findings,
  snapshots, reviews, case events and exception histories remain readable. Their
  source becomes out of scope; no disappearance is invented.
- New advisories use **public-reference / not-a-deployment**. The digest identifies
  the catalogue, not a deployed image. Installed version is “Not assessed (public
  reference)”, fix is unknown, and no exposure is invented. Load times and labelled
  load events are not scanner detections.
- Severity is the disclosed public CVSS metric. CVE/finding pages show source links
  and persistent provenance; cases use `nvd_public_reference` and
  `public_reference_only`, not fake production evidence.
- Validation re-derives every row from hash-checked receipts and requires exact
  counts. Invalid input cannot partially replace the database or download file.
  Hashes establish local integrity, not a digital signature from NVD.
- Reapplying the same catalogue is a no-op: no duplicates, changed timestamps or
  extra history. Refresh creates a new reference identity and retires old reference
  placements without rewriting their history. Modified reference rows cause refusal.
- Assessment and local exceptions remain available for this reference scope; they
  are not organizational production risk approvals.

## Explicit refresh

```sh
mise x -- mix triage.reference --download
mise x -- mix triage.reference --check
# Then preview/apply intentionally, as above.
```

Download uses Req/HTTPS, fixed NVD endpoints, no redirects, request/response limits
and rate spacing. Failures preserve the last good file. The publication window is
fixed for this bounded sample. `--file PATH` selects another catalogue/output.
No page, application startup or offline seed fetches data. Synthetic fixtures remain
for automated tests, not the development seed entry point.
