defmodule Mix.Tasks.Triage.Exposure do
  @shortdoc "Dry-runs or records which deployments are internal or internet-facing"

  @moduledoc """
  Records operator declarations of deployment exposure from a local JSON file.

      mix triage.exposure --file exposure.json
      mix triage.exposure --file exposure.json --apply

  The default is a dry run: it shows which active deployments the file covers
  and what would be recorded. `--apply` appends the evidence in one transaction.
  The file format is described in `Triage.Exposure.Declarations`. This task
  makes no network calls and never changes findings or decisions.
  """

  use Mix.Task

  alias Triage.Exposure.Declarations

  @switches [file: :string, apply: :boolean]

  @impl Mix.Task
  def run(args) do
    {opts, argv, invalid} = OptionParser.parse(args, strict: @switches)

    if invalid != [] or argv != [] do
      Mix.raise("unexpected option or argument. See `mix help triage.exposure`.")
    end

    path = opts[:file] || Mix.raise("missing --file. See `mix help triage.exposure`.")
    unless File.regular?(path), do: Mix.raise("file not found: #{path}")

    if File.stat!(path).size > Declarations.max_bytes() do
      Mix.raise("the file is larger than #{Declarations.max_bytes()} bytes")
    end

    Mix.Task.run("app.start")

    with {:ok, declaration} <- Declarations.parse(File.read!(path)),
         {:ok, plan} <- run_plan(declaration, opts[:apply] == true) do
      print(plan, opts[:apply] == true)
    else
      {:error, messages} ->
        Mix.raise("nothing was recorded:\n" <> Enum.map_join(messages, "\n", &"  #{&1}"))
    end
  end

  defp run_plan(declaration, true), do: Declarations.apply(declaration)
  defp run_plan(declaration, false), do: Declarations.plan(declaration)

  defp print(plan, applied?) do
    summary = Declarations.summary(plan)
    label = if applied?, do: "applied (committed)", else: "dry run (nothing written)"

    Mix.shell().info("""
    triage.exposure #{label}
      source: #{plan.source}
      observed at: #{DateTime.to_iso8601(plan.observed_at)}

    active deployments covered: #{summary.matched}
      #{if applied?, do: "recorded", else: "to record"}: #{summary.record}
      unchanged: #{summary.unchanged}
      skipped, newer evidence exists: #{summary.newer_exists}
    """)

    for %{action: :record, placement: placement, exposure: exposure} <- Enum.take(plan.rows, 20) do
      Mix.shell().info(
        "  #{placement.owner}/#{placement.environment}/#{placement.namespace}: #{exposure}"
      )
    end

    if summary.unmatched != [] do
      Mix.shell().info("entries that match no active deployment:")
      Enum.each(summary.unmatched, &Mix.shell().info("  #{&1}"))
    end

    unless applied?, do: Mix.shell().info("re-run with --apply to record this.")
  end
end
