# Independent implementation review and QA prompt

Review the actual implementation diff and running owned test application against this handoff. Read source instead of trusting the implementing agent's report. Do not grade only the screenshot or close old security findings from generic new tests.

Inspect exact-target/complete-evidence validation, authenticated actor flow, chronological decision precedence, old/global/new record handling, expiry boundaries, not-affected versus risk-accepted semantics, reported versus verified remediation, material changes, SQL/application priority/count parity, and persistent draft/ticket operations.

Try malformed direct events, zero/hidden/cross-scope targets, forged hashes/actors, revoked roles, stale evidence, simultaneous saves/imports, operation replay/mismatched reuse, timeout after remote success, and missing/ambiguous reconciliation. Confirm that ordinary navigation causes no external call and that UI success corresponds to an actual committed operation.

Exercise real Findings/Exceptions/history flows at required widths, keyboard/focus, zoom/text spacing, browser Back, reconnect, empty/source-unavailable states, long strings, and high target fanout. Compare the new visual hierarchy with the primary concept while applying the gap corrections, not its mock logic. Validate AI injection/reference/scope/fix cases and reporting snapshot/target parity.

Run relevant current quality commands under owned-resource rules. Use qa/acceptance-cases.json and map old retained acceptance requirements. Report findings with severity, file/line, reproduction, expected/actual, evidence and suggested correction. Write PASS only for directly supported checks, BLOCKED for unavailable prerequisites, and NOT RUN otherwise. Final approval cannot be based on bundle validation or mocked live-service claims.
