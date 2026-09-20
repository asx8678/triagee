# QA tools — reference and implementation verification

These tools are optional companions to the repository's own tests. They do not implement the real app, seed production, or establish a security verdict. All paths are relative to this package; run from any working directory.

## Installation

Use Python 3.10+ (tested here with 3.13.5), the pinned `requirements.txt`, and Chromium. The pins describe the supplied harness environment, not dependencies to add to the application.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r qa/requirements.txt
python -m playwright install chromium
```

On Windows activate `.venv\Scripts\activate`. The environment must have the browser's normal OS dependencies. A local executable can be passed to reference tools with `--browser`; the application runner accepts `browser_path` in its config. No font binaries are included. Do not add fonts to the ZIP.

## Commands

`verify_package.py` checks every shipped file against `MANIFEST.json`. New output files are allowed; changing a shipped baseline is reported. `test_reference.py` runs the supplied 61 browser checks in a temporary directory and copies only results/logs to its output. It does not overwrite accepted files. `test_fixture_contract.py` independently checks the18 scope combinations, stable IDs, fixed totals and sample scoped-state invariants.

`capture_reference.py` renders all 32 cases from the frozen HTML in separate clean browser contexts, writes native-size PNGs and computed-style/geometry JSON, and records browser/environment/source hashes. It makes no external requests. Default output is `qa/results/reference-capture`; keep rerenders outside `reference/approved` and never alter its HTML.

`compare_visuals.py` compares actual screenshots to `reference/baselines`, without resizing. It writes overlays, changed-pixel heatmaps, JSON and an HTML gallery. Default color-difference threshold 16/255; maximum changed pixels 0.5%; geometry checks include2px anchor/width tolerance and 1px key-height tolerance. No broad masks. Run `--help` for isolated single-case investigations; skipping geometry is not a complete acceptance result.

```bash
python qa/verify_package.py
python qa/test_harness.py
python qa/test_reference.py --output qa/results/my-reference-tests
python qa/test_fixture_contract.py --output qa/results/my-fixture-tests.json
python qa/capture_reference.py --output qa/results/my-reference-renders
python qa/compare_visuals.py --actual qa/results/my-reference-renders --output qa/results/my-reference-diff
```

## Application capture configuration

`contracts/application-capture.example.json` is **intentionally not runnable** until mapped to the target application. Copy it to your local/test config. Fill:

- `configured:true`, actual isolated `base_url`, and actual routes for all 32 case IDs.
- Test-only fixture readiness selector that exists only when the synthetic fixture is loaded.
- `steps` needed to reach each screenshot through actual controls.
- `selector_map` when production geometry nodes use different selectors from the reference.

Example step syntax (illustrative selectors, not a claim about your repository):

```json
{
  "id": "inspector-history-1600",
  "width": 1600,
  "height": 1000,
  "route": "/actual-test-inventory-route",
  "steps": [
    {"action": "click", "selector": "[data-testid='cve-open'][data-cve-id='DEMO-2026-001']"},
    {"action": "click", "selector": "[data-testid='inspector-tab-history']"},
    {"action": "wait_for", "selector": "[data-testid='inspector-body']"}
  ]
}
```

Supported actions: `click`, `fill` with `value`, `select_option` with `value`, `check`, `uncheck`, `press` with `key`, `wait_for` with optional `state`, and `scroll` with pixel `top`/`left`. They are ordinary Playwright locator operations; none runs the reference's synthetic business functions against your app. A selector matching multiple elements uses the first, so prefer unique locators.

`selector_map` maps reference CSS selector strings to actual application selectors for geometry collection. Preserve the reference classes where reasonable to simplify the port; stable test IDs still help with actions. Do not hide missing elements from the comparison by mapping to unrelated nodes.

The runner requires `--acknowledge-test-environment`, permits localhost by default, and needs `--allow-remote` for an explicitly chosen remote test origin. It rejects unmapped routes and wrong fixture IDs. It blocks requests outside `base_url`'s origin unless explicitly listed in `allowed_origins`. Those browser request checks do not detect server-side outbound calls; instrument backend integration spies as part of application tests.

```bash
python qa/capture_application.py \
  --config path/to/your-application-capture.json \
  --output qa/results/application \
  --acknowledge-test-environment
python qa/compare_visuals.py --actual qa/results/application --output qa/results/application-diff
```

Fixture seeding/reset and server clock freezing remain framework-native test setup. The runner never guesses seed commands or mutates a database. Include synthetic footer/labels only in test mode for comparable screenshots. Normal production content is truthful real data with the same visual geometry.

## Reports shipped in this package

`PACKAGE-QA-REPORT.md` is the authoritative summary of checks actually run during packaging. `qa/results/reference-interactions/` contains the fresh 61-check reference run; `fixture-contract.json` contains82 independent synthetic checks. Reproducibility/comparator reports are separate from production acceptance.

No real target application, production backend, migration, external ticket system, AI provider, browser authentication or multi-user workload was tested here. Do not re-label these reports as application passes.
