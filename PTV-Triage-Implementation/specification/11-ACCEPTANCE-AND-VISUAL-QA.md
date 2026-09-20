# 11 · Acceptance and visual QA

## 11.1 Two independent acceptance tracks

**Behavior/data:** real application queries, scope, mutations, drafts, history, failure paths and outbound controls. **Visual fidelity:** exact accepted composition, geometry, styling and responsive behavior on the deterministic fixture. Passing one does not waive the other.

`contracts/acceptance-cases.json` is the executable-team checklist with stable requirement IDs, conditions, expected behavior and evidence. The JSON is a catalog, not a claim that every production test already exists. Map each case into the repository's actual tests and report pass/fail/not run honestly.

## 11.2 Reference verification

```bash
python qa/verify_package.py
python qa/test_reference.py
python qa/test_fixture_contract.py
python qa/capture_reference.py --output qa/results/local-reference
python qa/compare_visuals.py --actual qa/results/local-reference --output qa/results/reference-comparison
```

These commands test the frozen reference and fixture, not the target application. The wrapper runs the supplied 61-check interaction suite in a temporary copy so accepted files cannot be overwritten. New capture output is isolated. Results from this package's own run are in `qa/results/` and summarized in `PACKAGE-QA-REPORT.md`.

## 11.3 Preparing application captures

Complete the real fixture adapter from `07-PRODUCTION-INTEGRATION.md`. Set the fixed clock to 19 September 2026 at 10:00 UTC, use the provided IDs/data/text and disabled integrations, and expose the test-only readiness marker. Add stable locators or map existing classnames using `contracts/locators.json`.

Copy `contracts/application-capture.example.json` to a local config and fill **actual** routes/steps. The example intentionally refuses to run until configured. Use only an isolated test environment with synthetic data. A user-supplied arbitrary application URL is not sufficient evidence that a destructive test environment is safe.

```bash
python qa/capture_application.py \
  --config path/to/application-capture.json \
  --output qa/results/application \
  --acknowledge-test-environment
python qa/compare_visuals.py \
  --actual qa/results/application \
  --output qa/results/application-comparison
```

No live production mutation is required for screenshots. The reference setup JavaScript runs only against the reference. The application capture runner uses configured routes and normal control actions instead of calling reference functions inside the production app.

## 11.4 Visual comparison rules

Match viewport in CSS pixels, DPR 1, Chromium version where possible, locale en-US, timezone UTC, color scheme light, reduced motion, font environment, fixture content and form state. The accepted original previews are1600×1000 except laptop1366×768 and mobile390×844. Do not compare a scaled preview to a native-size render.

The provided comparator uses per-channel difference tolerance16/255 and a default changed-pixel ratio limit0.005 (0.5%). This is a triage threshold for antialiasing/renderer noise, not permission to alter visible layout. Critical local drift can be unacceptable even if most of a page is white and the aggregate ratio passes.

Required geometry: main anchor positions/column widths within2CSSpx; key shell/action/input heights within1px; exact intended radii, colors and border widths. Font metrics/line wrapping should match in the controlled environment. Material font/environment differences must be fixed or documented; do not blur images to force a match.

Inspect side-by-side renders,50% overlays and changed-pixel heatmaps. Focus on navigation height, metrics baseline, table density, queue/evidence/decision widths, footer placement, inspector dimensions, section order and breakpoint behavior. Compare hover/selected/focus/validation/pending states in addition to base screenshots.

No broad masking is supplied. Dynamic production text is not a valid excuse because captures use a fixed fixture. A genuinely unavoidable nondeterministic region needs a narrow documented mask and separate content assertion; never mask whole tables, panels or action bars.

## 11.5 Required browser interactions

Test every navigation entrypoint, filter/search/sort, saved view, selected-only review, inspector tab/expand/close/return, exact scope selection, all decision types, validation, save/next, cancellation, exception expiry, request verification and history. Test source freshness and empty/conflict/error states from the catalog.

For action visibility: scroll queue, evidence, decision and inspector bodies to their maximum; check control bounds against the visible viewport and hit-test/focus to ensure they are not covered by another element. A positive `is_visible()` result alone does not prove an action is unobscured. Test actual click/keyboard activation where safe.

Run responsive boundary cases supplied in visual-cases. Perform real 200% zoom, mobile keyboard/date-input checks and keyboard-only review. Test Chromium and at least the additional browsers actually supported by the application; do not claim cross-browser pass from Chromium-only evidence.

## 11.6 Data assertions

Compare contributing **sets**, not only totals. On the supplied visual fixture, default totals are18 active CVEs,12 decision CVEs,3 immediate-priority CVEs and10 unknown-exposure scopes. These are sample expectations only. Team/environment expected ID sets are in `fixture-expectations.json`.

Add real domain fixtures for per-scope priority, aliases, expired exceptions, partial scans, out-of-order events, unknown dates, global legacy decisions, concurrent edits and result-unknown ticket submission. The prototype's simplified model does not validate these production paths.

## 11.7 Final gate

Build/lint/unit/integration/e2e tests pass or pre-existing failures are distinctly reported. All must-pass acceptance cases have evidence.32 required visual states are captured or explicit supported-state deviations approved. No hidden primary actions, no false Fixed/Safe/approved labels, no lost drafts, no out-of-scope mutation, no surprise outbound calls. Migration/deep-link parity and rollback evidence are attached.

Do not claim the app is fully accessible, secure or production-ready solely from the provided harness. Describe exactly what was verified and what remains.
