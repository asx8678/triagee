defmodule Triage.Import.Contract do
  @moduledoc """
  The snapshot import contract: accepted format and version, the severity and
  event vocabularies, the record key sets and the explicit budgets.

  A module that needs any of them declares `use Triage.Import.Contract`, which
  injects them as module attributes. The parser, the writer, the reconciler and
  the public import API therefore share one definition of the contract rather
  than one copy each, and the values stay usable in patterns because they arrive
  as attributes rather than as function calls.
  """

  @format "triage.snapshot"
  @version 1
  @events ~w(appeared resolved reopened)
  @severities ~w(CRITICAL HIGH MEDIUM LOW)
  @unsafe_text ~r/[\x00-\x1F\x7F]/

  # Text and scope budgets.
  @max_text 1024
  @max_text_bytes 4096
  @scope_max 120
  @max_scope_bytes 480

  # Document and collection budgets.
  @max_document_bytes 5_000_000
  @max_images 1_000
  @max_placements_per_image 500
  @max_findings_per_image 500
  @max_events_per_finding 200
  @max_total_records 10_000

  # A fixed 64-bit key for the transaction-scoped import advisory lock. Any
  # constant works as long as every import writer uses the same one.
  @import_lock_key 7_433_921_021_337

  @image_root_keys ~w(format version source generated_at images)
  @image_keys ~w(digest repository tag description placements findings)
  @placement_keys ~w(namespace owner environment active first_seen last_seen)
  @finding_keys ~w(cve package_name package_version severity fix url description suppressed first_seen last_seen resolved_at events)
  @event_keys ~w(event occurred_at note)

  @doc false
  defmacro __using__(_opts) do
    quote do
      @format unquote(Macro.escape(@format))
      @version unquote(Macro.escape(@version))
      @events unquote(Macro.escape(@events))
      @severities unquote(Macro.escape(@severities))
      @unsafe_text unquote(Macro.escape(@unsafe_text))
      @max_text unquote(Macro.escape(@max_text))
      @max_text_bytes unquote(Macro.escape(@max_text_bytes))
      @scope_max unquote(Macro.escape(@scope_max))
      @max_scope_bytes unquote(Macro.escape(@max_scope_bytes))
      @max_document_bytes unquote(Macro.escape(@max_document_bytes))
      @max_images unquote(Macro.escape(@max_images))
      @max_placements_per_image unquote(Macro.escape(@max_placements_per_image))
      @max_findings_per_image unquote(Macro.escape(@max_findings_per_image))
      @max_events_per_finding unquote(Macro.escape(@max_events_per_finding))
      @max_total_records unquote(Macro.escape(@max_total_records))
      @import_lock_key unquote(Macro.escape(@import_lock_key))
      @image_root_keys unquote(Macro.escape(@image_root_keys))
      @image_keys unquote(Macro.escape(@image_keys))
      @placement_keys unquote(Macro.escape(@placement_keys))
      @finding_keys unquote(Macro.escape(@finding_keys))
      @event_keys unquote(Macro.escape(@event_keys))
    end
  end
end
