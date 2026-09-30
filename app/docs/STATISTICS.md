# Statistics

The **Statistics** page (`/?page=statistics`; the old `/statistics` bookmark opens
it) shows how long CVEs took to handle and how each deployment was handled, for
the team and environment chosen in the filter bar. **Download CSV**
(`/statistics/export.csv?team=…&environment=…&period=…`) exports the same
selection with one row per CVE and deployment. Any signed-in user can view and
export; nothing here changes data.

The numbers come from `Triage.Statistics.report/3` and `export_rows/3`, over the
same deployments as Triage (`Workspace.targets/2`, reference data excluded).

## Definitions

- **First observed**: when the scanner first recorded the CVE on the deployment's
  image, the earlier of the finding's `first_seen` and its first `appeared`
  event. This is the Timeline's "First detected"; the two agree for every CVE.
- **First action**: the first decision for the deployment (or for every
  deployment of the CVE) made at or after First observed: Whitelisted, Marked
  fixed or Ticket created, with the reviewer. Older records can show other
  decision kinds, such as Remediation requested.
- **No longer observed**: when the scanner stopped reporting it, the latest
  `resolved_at` once every occurrence on the image is resolved, or the
  deployment's `last_seen` once the deployment is retired.
- **Handled**: the earlier of First action and No longer observed. A CVE is
  handled once every deployment is (its date is the last of them). It is open
  while any deployment still needs a decision.
- **How it was handled**: the First action, or **Disappeared on its own** when
  the CVE stopped being observed before any decision (a vendor update, a new
  image, a removed package). **Fixed, confirmed by scan** is a fix the scanner
  then stopped reporting; **Fixed, not yet confirmed** is a fix it still reports.
  A whitelist stays "Whitelisted" even if the CVE later disappears; the No longer
  observed date shows that separately.
- **Days**: whole days, rounded down, medians included. The page shows 0 as
  "same day".

## Period

The period (30 days, 90 days, 12 months, all time) selects CVEs **handled** in
it, which is what response-time reporting needs. CVEs open now are always listed
and counted, whatever the period; a CVE handled in the period that needs a
decision again (for example an expired whitelist) appears in both lists. "How
deployments were handled" counts deployments whose handled date falls in the
period. The CSV holds every deployment of the CVEs the page lists, open ones
included, with their Handled date so the rows can be filtered in Excel.

## CSV for Excel

UTF-8 with a byte-order mark, CRLF line ends, comma separators with RFC 4180
quoting, ISO dates (`YYYY-MM-DD`, UTC) and whole-number days. A cell that Excel
would run as a formula (starting with `=`, `+`, `-` or `@`) gets a leading
apostrophe; reasons are free text.

If Excel shows everything in one column (some European Excel versions expect `;`
between columns), open the file with **Data → From Text/CSV** and choose comma.

Columns: CVE, Severity, Packages, Team, Environment, Namespace, Image, First
observed, First action, First action date, First action by, Days to first action,
No longer observed, Days until no longer observed, Handled, How it was handled,
Current state, Whitelisted until, Days open, Ticket, Reason.

## Limits

These are recorded observations. "No longer observed" means the scanner stopped
reporting the CVE in the imported data; it is not verified remediation, and the
numbers are only as complete as that data. Imports add history but never mark a
missing finding as resolved on their own, so "Disappeared on its own" appears
only where an import recorded the resolution.
