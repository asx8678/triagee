# Policy exceptions are scoped to the existing boundary modules, not future code.
# File lists are explicit (no directory globs); new files retain default checks.
%{
  configs: [
    %{
      name: "default",
      strict: true,
      checks: %{
        # `enabled` replaces Credo's defaults; `extra` merges these overrides.
        extra: [
          # Forged atomics-reference validation needs dynamic dispatch to preserve
          # runtime rejection without making Dialyzer infer the client is dead.
          {Credo.Check.Refactor.Apply, files: [excluded: ["lib/triage/collection/client.ex"]]},
          # Existing nested validation/transaction/event dispatch. Keep its explicit
          # rejection paths together, while enforcing defaults everywhere else.
          {Credo.Check.Refactor.Nesting,
           files: [
             excluded: [
               "lib/mix/tasks/triage.intel.ex",
               "lib/mix/tasks/triage.reference.ex",
               "lib/triage/activity.ex",
               "lib/triage/collection.ex",
               "lib/triage/collection/client.ex",
               "lib/triage/collection/config.ex",
               "lib/triage/collection/crawl.ex",
               "lib/triage/collection/preview.ex",
               "lib/triage/cve_catalog.ex",
               "lib/triage/exceptions/decision.ex",
               "lib/triage/import.ex",
               "lib/triage/import/parse.ex",
               "lib/triage/import/reconcile.ex",
               "lib/triage/import/write.ex",
               "lib/triage/import_flow.ex",
               "lib/triage/inventory/group_cursor.ex",
               "lib/triage/reference_catalog.ex",
               "lib/triage/reference_data.ex",
               "lib/triage/replay.ex",
               "lib/triage/replay/runs.ex",
               "lib/triage/seeds.ex",
               "lib/triage_web/finding_filters.ex",
               "lib/triage_web/live/case_live/show.ex",
               "lib/triage_web/live/exception_live.ex",
               "lib/triage_web/live/finding_live/show.ex",
               "lib/triage_web/live/import_live.ex",
               "lib/triage_web/live/replay_live.ex",
               "test/triage/import_concurrency_test.exs"
             ]
           ]},
          # Existing contract enumeration, risk policy and CLI dispatch. No global
          # threshold increase: unrelated and newly added code is still checked.
          {Credo.Check.Refactor.CyclomaticComplexity,
           files: [
             excluded: [
               "lib/mix/tasks/triage.import.ex",
               "lib/mix/tasks/triage.intel.ex",
               "lib/mix/tasks/triage.reference.ex",
               "lib/triage/collection/config.ex",
               "lib/triage/collection/normalize.ex",
               "lib/triage/collection/transport.ex",
               "lib/triage/import.ex",
               "lib/triage/inventory.ex",
               "lib/triage/replay.ex",
               "lib/triage/risk.ex",
               "lib/triage_web/live/case_live/show.ex",
               "lib/triage_web/live/replay_live.ex",
               "test/support/fake_source.ex"
             ]
           ]}
        ],
        disabled: [
          # Fully qualified nested names avoid shadowing the Req HTTP dependency
          # and Errors aliases, and match the names in the public documentation.
          {Credo.Check.Design.AliasUsage, []}
        ]
      }
    }
  ]
}
