# M3 — Optional AI assistance and reporting prompt

Implement T10–T11 after the required core dependencies. Read specs 05–06, domain safeguards, proposed schemas, examples, and the current wrapper/reporting integrations. These JSON contracts are proposals, not existing APIs.

Add an explicit Analyze selected scope operation that uses authorized server-captured evidence, a configured read-only adapter, strict structural and semantic validation, honest failure/staleness states, and bounded caching. Treat advisory text and model output as untrusted. Never auto-approve, invent fixed versions, broaden targets, create tickets, or transmit unrelated inventory. Manual review must work without AI configuration.

Implement one shared reporting projection with correct CVE/target counting units, typed decisions, verification distinction, snapshot/freshness semantics, and authorized exact-scope drilldowns. Reuse an actual existing integration when present; otherwise build the smallest read-only adapter. Do not duplicate Grafana charts in Triagee or claim a live dashboard was validated without running it.

Use mock adapters and deterministic schema examples for automated tests. No live credentials or inventory transmission are authorized. Record which API/schema compatibility choices were made and what still needs deployment-owner validation. Update the report with actual results, not provider assumptions.
