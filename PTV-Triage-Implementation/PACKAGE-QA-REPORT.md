# Package QA report

Prepared 19 September 2026. This report describes verification of the implementation handoff, accepted reference and QA tools—not a production-app implementation.

## Actually executed

| Check | Result | Evidence |
|---|---|---|
| Original approved HTML and seven previews | All eight byte-identical to the previously delivered ZIP | `qa/results/approved-preservation.json` |
| Fresh reference interaction/layout suite | **61 / 61 passed** | `qa/results/reference-interactions/test-results.json` and logs |
| Independent synthetic fixture/count checks | **82 / 82 passed** | `qa/results/fixture-contract.json` |
| Clean reference captures | **32 / 32 rendered**, no runtime errors, external requests or document-wide horizontal overflow in these states | `reference/baselines/capture-report.json` |
| Independent second capture and comparison | **32 / 32 matched**, zero changed pixels in the same controlled environment; 1,036 visible-element geometry entries compared | `qa/results/reproducibility/comparison-report.json` |
| QA-harness positive/negative controls | **7 / 7 passed** | `qa/results/harness-self-tests.json` |

Harness negative controls confirmed that image differences, dimension mismatches and geometry drift are rejected; unconfigured/unacknowledged application capture is blocked; and altered files fail the integrity check. The comparator does not automatically approve design changes or overwrite baselines.

## Rendering environment

Python 3.13.5; Playwright 1.57.0; Chromium 144.0.7559.96; Linux; locale en-US; timezone UTC; DPR 1; light color scheme; reduced motion. Reference content is the synthetic `ptv-approved-v1` fixture with a fixed clock at 19 September 2026, 10:00 UTC. Full metadata and reference hash are in the capture reports. No font binaries are distributed.

The accepted HTML and original previews are unchanged. New canonical screenshots and measurements were generated from that HTML. The reference source, exact CSS, formatted CSS, source index, synthetic fixture, 45 click-action mappings, 16 form-input mappings, 90 production acceptance requirements and 32 visual-case definitions are included. The original 17 before-state screenshots are separately indexed.

## Not tested or completed here

No actual application repository was supplied, inspected or changed for this handoff. Production queries, state mutations, backend APIs, authorization, draft persistence, exception expiry, scan completeness, database migrations, rollback, real Azure DevOps operations, real AI operations, concurrency, actual browser zoom/mobile keyboard behavior and cross-browser/assistive-technology compatibility remain implementation work and must be tested in the target repository.

The 90-scenario acceptance catalog is a set of requirements, not 90 executed production tests. `capture_application.py` was syntax/configuration-guard checked, but was not validated against the unknown real application's routes or DOM. Its example config intentionally refuses to run until the agent maps the actual isolated test application and fixture.

Pixel identity was confirmed for repeat renders in the same environment, not guaranteed across arbitrary operating systems, fonts or native form controls. The design lock requires controlled-environment comparison plus manual review and documented minimal safety/accessibility corrections.

## Integrity and reproducibility

`MANIFEST.json` and `SHA256SUMS.txt` enumerate shipped payload hashes. Run `python qa/verify_package.py` after extraction. New test outputs belong outside protected reference files. Run the commands in `qa/README.md` to regenerate independent evidence. Do not update an expected screenshot merely because the application fails its comparison.
