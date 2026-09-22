# Workspace language and CVE lifecycle timeline

The navigation should describe what the reviewer can do and the information on
each page. Existing routes and stored decision semantics stay compatible.

1. Rename Findings to **Review**, Exceptions to **Risk decisions**, and Daily to
   **Timeline** in navigation and page titles. Make the active Review indicator
   work for both existing review URLs.
2. Explain Risk decisions as saved whitelist and not-affected decisions. Replace
   Advisory, Scope, Type, Rationale, Reviewer, and Review / expiry with **CVE**,
   **Applies to**, **Action taken**, **Reason**, **Decided by**, and **Expires at
   (UTC)**. Call placements deployments, while retaining their recorded IDs.
3. Explain that expiry ends a decision's effect and may require another review;
   it does not resolve the vulnerability. Keep the actual expiry timestamp and
   older records' timing semantics. Label the time check **Expiry status** and
   **Not expired**, since an unexpired historical record may have been replaced.
   Explain the inclusive date choice beside the whitelist form as well.
4. Combine recorded detections, whitelist decisions, other review actions, and
   scanner observation changes in Timeline. Show each CVE once, with its full
   history in chronological order, its first detection, first action, and time
   to first action. Sort CVEs by latest activity, grouped by that UTC date. Show
   action timestamps, deployment scope, reviewer, reason, expiry, and elapsed
   time since detection. Show a waiting duration without a saved action. Keep
   response timing distinct from verified remediation and whole-CVE coverage.
   Group one saved operation across deployments into one step with its scopes;
   keep later reviews separate and label repeat whitelists as updates. Exclude
   future decisions from completed activity and paginate whole CVE histories
   so detection always stays with the actions. Both history pages query all teams and
   environments, so show that coverage explicitly.
5. Provide three repeatable fictional local samples: detection then whitelist
   after 2 or 5 hours, and detection then a marked fix followed by a scan without
   the finding. Preserve existing review history when adding these samples.
6. Put **Continue as local user** above the credential fields on the development
   login page. Reuse the existing ordinary reviewer session, local-only access
   checks, CSRF protection, and production exclusion.
7. Check the three destinations in the running browser, confirm the original
   review links and draft navigation still work, and run the required precommit
   checks. Update existing navigation expectations to the new names.

No migrations, new decision types, or changes to risk acceptance duration are
needed for this change. The full observation chart retains its existing URLs.

The isolated commit passed `mix precommit` on 2026-09-22: 1,215 tests passed
and 2 skipped. Coverage includes dated actions, response timing, future and
pre-detection decisions, scanner observations, missing event logs, grouped
operations, complete-history pagination, sample idempotence, and local login.
Browser checks confirmed credential-free sign-in and the chronological sample
histories. An existing subprocess timeout test now allows 1.5 seconds for its
shell and children to start before asserting cancellation under full-suite load.
