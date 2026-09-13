defmodule Mix.Tasks.Triage.Import do
  @shortdoc "Dry-runs or applies an approved triage snapshot JSON file"

  @moduledoc """
  Reconciles an approved snapshot export against the local inventory, and only
  writes when `--apply` is passed explicitly.

      mix triage.import --file priv/snapshots/legacy-2026-09-09.json
      mix triage.import --file priv/snapshots/legacy-2026-09-09.json --apply

  The default is a **dry run**: it parses and validates the document, then
  reports, per image/placement/finding/event, whether the record is `create`,
  `update`, `unchanged` or already `existing` (events). Nothing is written and
  no schema is changed.

  `--apply` runs the same reconciliation inside one database transaction. Any
  failure rolls the entire import back and leaves the local inventory exactly
  as it was. Reimporting the same snapshot only rewrites rows whose metadata
  actually differs, so a second run reports `unchanged`/`existing`. This task
  never updates or deletes review cases, evidence snapshots, reviews or case
  events, and it never infers resolution from a missing field.

  Validation failures are reported with a JSON path per problem and exit
  non-zero without writing. This task makes no network calls; the snapshot is
  a local file you supply. The file is size-bounded (5,000,000 bytes) from
  `File.stat!` before `File.read!`, and the parser enforces its own document,
  record-count and string-byte budgets.
  """

  use Mix.Task

  alias Triage.Import

  @switches [file: :string, apply: :boolean]

  @impl Mix.Task
  def run(args) do
    {opts, argv, invalid} = OptionParser.parse(args, strict: @switches)

    if invalid != [] do
      Mix.raise("invalid option(s): #{inspect(invalid)}. See `mix help triage.import`.")
    end

    if argv != [] do
      Mix.raise("unexpected argument(s): #{inspect(argv)}. See `mix help triage.import`.")
    end

    path = opts[:file] || Mix.raise("missing --file. See `mix help triage.import`.")

    unless File.regular?(path) do
      Mix.raise("snapshot file not found: #{path}")
    end

    # Bound the file before reading or decoding it.
    max_bytes = Import.max_document_bytes()
    size = File.stat!(path).size

    if size > max_bytes do
      Mix.raise("snapshot file is #{size} bytes; the limit is #{max_bytes} bytes")
    end

    Mix.Task.run("app.start")

    json = File.read!(path)
    mode = if opts[:apply], do: :apply, else: :dry_run

    case mode do
      :dry_run ->
        with {:ok, snapshot} <- Import.parse(json),
             {:ok, report} <- Import.dry_run(snapshot) do
          print_report(path, :dry_run, report)
        else
          {:error, errors} ->
            Mix.raise("snapshot is invalid; nothing was written:\n" <> format_errors(errors))
        end

      :apply ->
        case Import.import_snapshot(json) do
          {:ok, report} ->
            print_report(path, :apply, report)

          {:error, errors} ->
            Mix.raise(
              "import failed; the transaction was rolled back:\n" <> format_errors(errors)
            )
        end
    end
  end

  defp print_report(path, mode, report) do
    label = if mode == :apply, do: "applied (committed)", else: "dry run (nothing written)"

    Mix.shell().info("""
    triage.import #{label}
      file: #{path}

    #{format_counts("images", report.summary.images)}
    #{format_counts("placements", report.summary.placements)}
    #{format_counts("findings", report.summary.findings)}
    #{format_counts("events", report.summary.events)}
    """)

    if report.warnings == [] do
      Mix.shell().info("warnings: none")
    else
      Mix.shell().info("warnings:")
      Mix.shell().info(format_errors(report.warnings))
    end

    case mode do
      :apply ->
        :ok

      :dry_run ->
        Mix.shell().info("re-run with --apply to commit these changes.")
    end
  end

  defp format_counts(label, counts) do
    "#{label}: create=#{counts.create} update=#{counts.update} " <>
      "unchanged=#{counts.unchanged} existing=#{counts.existing}"
  end

  defp format_errors(errors) do
    errors
    |> Enum.map(fn %{path: path, message: message} -> "  #{path}: #{message}" end)
    |> Enum.join("\n")
  end
end
