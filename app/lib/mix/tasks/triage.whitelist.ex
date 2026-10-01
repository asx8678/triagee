defmodule Mix.Tasks.Triage.Whitelist do
  @shortdoc "Compares the Azure DevOps repository whitelist with Triage"

  @moduledoc """
  Reads the CVE whitelist kept in an Azure DevOps repository and sets it
  beside what Triage records. Read-only: nothing is written anywhere.

      mix triage.whitelist
      mix triage.whitelist --repo security-config --path /whitelist/cves.yaml
      mix triage.whitelist --file ./cves.yaml
      mix triage.whitelist --team payments --environment prod --all

  Without options the file location comes from `ADO_WHITELIST_REPO` and
  `ADO_WHITELIST_PATH` (see `Triage.RepoWhitelist`). `--repo`, `--path`,
  `--branch` and `--project` replace them for this run. `--file` compares a
  local copy instead and makes no network call.

  The output is the same picture as the Whitelist overview in the app: how the
  file was read, the totals, every whitelisted CVE with its end date on both
  sides, and the CVEs that need a decision and are in neither. `--all` lists
  every row instead of the first 40.
  """

  use Mix.Task

  alias Triage.RepoWhitelist

  @switches [
    repo: :string,
    path: :string,
    branch: :string,
    project: :string,
    file: :string,
    team: :string,
    environment: :string,
    all: :boolean
  ]
  @variables [
    repo: "ADO_WHITELIST_REPO",
    path: "ADO_WHITELIST_PATH",
    branch: "ADO_WHITELIST_BRANCH",
    project: "ADO_WHITELIST_PROJECT"
  ]
  @max_file_bytes 1_000_000
  @shown 40

  @impl Mix.Task
  def run(args) do
    {opts, argv, invalid} = OptionParser.parse(args, strict: @switches)

    if invalid != [] or argv != [] do
      Mix.raise("unexpected option or argument. See `mix help triage.whitelist`.")
    end

    for {option, variable} <- @variables, value = opts[option] do
      System.put_env(variable, value)
    end

    read = read_options(opts[:file])
    Mix.Task.run("app.start")

    scope =
      for {key, option} <- [{"team", :team}, {"environment", :environment}],
          value = opts[option],
          into: %{},
          do: {key, value}

    scope |> RepoWhitelist.overview(read) |> print(scope, opts[:all] == true)
  end

  defp read_options(nil), do: [reload: true]

  defp read_options(path) do
    unless File.regular?(path), do: Mix.raise("file not found: #{path}")

    if File.stat!(path).size > @max_file_bytes do
      Mix.raise("the file is larger than #{@max_file_bytes} bytes")
    end

    [file: {path, File.read!(path)}]
  end

  defp print(%{repository: %{state: :error} = repository}, _scope, _all?) do
    Mix.raise(
      "the repository list could not be read: #{repository.message}" <>
        if(repository[:label], do: "\n  #{repository.label}", else: "")
    )
  end

  defp print(overview, scope, all?) do
    counts = overview.counts

    Mix.shell().info("""
    triage.whitelist (read-only)
      scope: #{scope["team"] || "all teams"}, #{scope["environment"] || "all environments"}
      #{source(overview.repository)}
    """)

    if overview.repository.state == :loaded do
      Mix.shell().info("""
      in the repository list: #{counts.repository} (#{counts.expired} ended, #{counts.expiring} end within 30 days)
      whitelisted in Triage: #{counts.triage} (#{counts.triage_expiring} end within 30 days)
      differences:
        #{counts.triage_only} whitelisted in Triage, not in the list
        #{counts.open_in_triage} in the list, need a decision in Triage
        #{counts.not_in_findings} in the list, not in current findings
      need a decision, in neither: #{overview.missing.total}
      """)
    else
      Mix.shell().info("whitelisted in Triage: #{counts.triage}\n")
    end

    table("whitelisted, the soonest end date first", overview.rows, &line/1, all?)
    missing(overview.missing, all?)
  end

  defp source(%{state: :loaded} = repository) do
    commit =
      if repository.commit, do: ", commit #{String.slice(repository.commit, 0, 8)}", else: ""

    "repository list: #{repository.label}\n  read as: #{repository.format}, " <>
      "#{repository.total} CVEs, #{repository.dated} with an end date#{commit}"
  end

  defp source(_not_configured),
    do:
      "repository list: not configured. Set ADO_WHITELIST_REPO and ADO_WHITELIST_PATH, " <>
        "pass --repo and --path, or compare a local copy with --file."

  defp table(_title, [], _line, _all?), do: :ok

  defp table(title, rows, line, all?) do
    shown = if all?, do: rows, else: Enum.take(rows, @shown)
    Mix.shell().info("#{title}:")
    Enum.each(shown, &Mix.shell().info("  " <> line.(&1)))

    if length(rows) > length(shown) do
      Mix.shell().info("  ... #{length(rows) - length(shown)} more, pass --all to list them")
    end

    Mix.shell().info("")
  end

  defp missing(nil, _all?), do: :ok

  defp missing(missing, all?) do
    table(
      "need a decision, in neither",
      missing.rows,
      &"#{pad(&1.cve, 18)}#{pad(&1.severity, 10)}#{&1.packages}",
      all?
    )
  end

  defp line(row) do
    pad(row.cve, 18) <>
      pad(row.severity, 10) <>
      pad("list: " <> listed(row.repository), 46) <> "triage: " <> recorded(row.triage)
  end

  defp pad(value, width), do: String.pad_trailing(to_string(value || "-"), width)

  defp listed(nil), do: "not in the list"
  defp listed(entry), do: ends(entry.until, entry.days_left)

  defp recorded(%{until: %Date{} = until} = cell),
    do: ends(until, cell.days_left) <> partial(cell)

  defp recorded(%{state: :needs_decision}), do: "needs a decision"
  defp recorded(%{state: :not_observed}), do: "not in current findings"
  defp recorded(%{decided: [_ | _] = labels}), do: Enum.join(labels, ", ")
  defp recorded(_cell), do: "decided"

  defp partial(%{whitelisted: covered, deployments: all}) when covered < all,
    do: ", #{covered} of #{all} deployments"

  defp partial(_cell), do: ""

  defp ends(nil, _days), do: "no end date"
  defp ends(until, days) when days < 0, do: "ended #{until} (#{-days}d ago)"
  defp ends(until, days), do: "until #{until} (#{days}d left)"
end
