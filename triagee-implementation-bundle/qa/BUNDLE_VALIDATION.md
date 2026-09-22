# Package preparation and validation

Prepared on 22 September 2026. This record concerns the handoff package and the supplied static prototype, not the repository application.

## Checked during preparation

- JSON syntax, both proposed JSON Schema definitions, and all three synthetic examples were validated. Format validation was enabled for the schema checks.
- Inline JavaScript extracted from the preserved HTML passed `node --check`.
- The preserved primary HTML has no external script, stylesheet, image, or font asset dependencies in its markup.
- Supplied PNGs were opened and visually inspected. They remain conversation-supplied reference assets, not screenshots of an application run in this session.
- A static prototype smoke check in system Chromium 144.0.7559.96 exercised list rendering (five initial rows), search (one matched row), Exceptions navigation, and the action preview. The preview was disabled before choosing an action. No JavaScript errors or HTTP(S) requests were recorded during those interactions.
- Prototype layout measurements were taken at 320, 390, 768, 1024, 1440, and 1920 px. **The preserved prototype overflows at 320 and 390 px: document width 428 px.** No document-width overflow was measured at the four wider widths. This is a known reference defect, not a passed mobile acceptance gate.

The prototype was loaded through Playwright `set_content`, because file navigation is blocked by this environment's browser policy and the default Playwright browser binary was unavailable. A system Chromium executable was used. This does not validate opening the file in every browser or establish accessibility conformance. Raw observations are in `prototype-smoke-results.json`.

## Reproducible package check

```sh
python3 tools/validate_bundle.py --require-jsonschema
```

This checks exact file-manifest coverage and SHA-256 values, parseable JSON, task dependency acyclicity, reciprocal task/acceptance references, local Markdown links, synthetic fixture arithmetic/example evidence references, and JSON Schema example validity. `jsonschema` must already be installed for the flag above. Without the flag, the validator explicitly reports skipped schema validation when that optional dependency is absent.

Manifest and checksum checks detect accidental changes; they are not a cryptographic signature or an independent trust guarantee. Synthetic fixture arithmetic verifies the declared sample expectations, not the implementation's algorithms.

## Not performed or claimed

No repository application build, test suite, migration, live browser workflow, database access, accessibility certification, security certification, real provider output evaluation, Grafana validation, Azure ticket creation, scanner suppression, deployment, repository change, or remote push.

All 58 application acceptance records deliberately start as **NOT_RUN**. The implementing agent must supply actual evidence. Existing historical security/acceptance obligations remain open unless individually verified; the bundle cannot close them.
