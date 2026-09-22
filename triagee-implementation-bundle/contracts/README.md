# Proposed contracts

These schemas are handoff proposals, not current repository APIs, Ecto schemas, established Grafana interfaces, or certified vulnerability-reporting formats. Implement a versioned adapter/read projection after discovery. Keep service credentials and implementation internals out of outputs.

`ai-recommendation.schema.json` validates model-output structure. The server must additionally validate exact captured scope, known evidence IDs, factual package-to-fix mapping, authorization, material freshness, and applicability justification. Evidence hash strings are opaque server bindings, not a model-generated proof. The example hashes are synthetic placeholders; actual fixture loaders must use the repository's canonical evidence implementation.

`reporting-target.schema.json` describes one authorized target at one snapshot. Validate cross-field semantics in code: verified outcomes need verification evidence and time; an exception needs an appropriate source record/boundary; unknown ticket operation state never implies successful ticket creation; source completeness needs actual declared-scope evidence. The schema alone cannot enforce all of these facts.

The example `detail_path` is illustrative. Use the implemented route helper/parameter contract rather than assuming the sample query parameters already work. `placement_ids` must never automatically become selected mutation targets.

All example CVEs, evidence, services, hashes, and package details are fictional and must not be sent to live intelligence/provider services. Schema-valid examples demonstrate shape only, not deployable security advice.
