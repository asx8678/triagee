# Prototype QA report

## Result

**61 / 61 automated browser checks passed.** JavaScript syntax validation also passed with `node --check` after extracting the inline script.

The tests ran against the actual standalone HTML using Playwright and the installed Chromium browser. The browser document was populated with `page.set_content`. This test context does not provide an ordinary persistent origin, so the prototype correctly used its session-only fallback.

## Checked

- Initial metric values derive from the synthetic fixture: 18 active CVEs, 12 requiring a decision, 3 immediate-priority CVEs and 10 unknown-exposure scopes.
- Team/environment filters, exact P1 drilldown, case-insensitive search and filtered-empty state.
- CVE inspector Summary, Affected assets, History and Evidence; expansion, Escape dismissal and visible review action.
- Multi-selection and an exact selected-only review queue.
- Required-field validation, explicitly selected scope counts and commitment affecting only the intended scope.
- A production-only work decision does not modify staging or change the active CVE count.
- Risk acceptance requires confirmation; cancel does nothing; confirmed acceptance remains an active vulnerability and retains precise scope IDs in its audit record.
- All 20 sample CVE lanes are available through scrolling, timeline window filtering, event-to-history drilldown, future versus unknown heatmap cells, daily drilldown and event-log reconciliation.
- Saved-view restoration in the current browser session.
- Review and inspector action-bar bounds at 1920×1080, 1600×900, 1440×900, 1366×768, 1280×720, 1024×768, 768×1024, 640×900 and 390×844.
- No document-wide horizontal overflow in the tested review layouts.
- No JavaScript runtime errors and no network requests during the exercised prototype workflows.

`test-results.json` contains the individual results. `test_prototype.py` provides the executable checks. Screenshots in `previews` were captured from the rendered HTML with synthetic state reset for clean reference images.

## Not validated by this prototype

No production repository, backend API, importer, database migration, real CVE intelligence, authentication/authorization, actual Azure DevOps submission, AI provider, multi-user concurrency, durable storage across reload on a normal origin, or server-side audit integrity was tested.

The prototype's clock and data are frozen. Its sample priorities are explicitly supplied fixtures, not a validated security-prioritization engine. Its local work statuses and draft storage are simplified for interaction testing. It does not implement a production scheduler for exception expiry, real remediation verification, real-time scanner reconciliation or enterprise-scale pagination/virtualization.

Browser viewport checks are not a complete accessibility audit. Actual browser zoom, mobile virtual-keyboard behavior, contrast measurements, multiple assistive technologies, all keyboard interactions and cross-browser compatibility still need production testing. Native dialog behavior and visible controls are a starting point, not a conformance claim.

The standalone file should be treated as a design reference, not a hardened application for storing production evidence or credentials.
