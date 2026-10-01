defmodule Triage.RepoWhitelist do
  @moduledoc """
  The whitelist kept in an Azure DevOps repository, set beside what Triage
  records: which CVEs the repository file whitelists and until when, which of
  those Triage also covers, and which CVEs still need a decision and are in
  neither.

  Read-only on both sides. The file is fetched when the overview is opened,
  never while browsing, and kept for ten minutes so reopening it is instant.

  Server configuration, next to the other `ADO_*` variables:

    * `ADO_WHITELIST_REPO` - the repository name or id;
    * `ADO_WHITELIST_PATH` - the file inside it, for example `/security/whitelist.yaml`;
    * `ADO_WHITELIST_BRANCH` - optional, the default branch otherwise;
    * `ADO_WHITELIST_PROJECT` - optional, `ADO_PROJECT` otherwise;
    * `ADO_WHITELIST_PAT` - optional token with the Code (Read) scope,
      `ADO_PAT` otherwise.

  An end date in the file is read as the last day the entry applies.
  """

  alias Triage.{AzureDevOps, Decisions, Workspace}
  alias Triage.RepoWhitelist.Parse

  @critical_days Triage.Attention.review_lead_days()
  @soon_days 30
  @cache_seconds 600
  @cache_key {__MODULE__, :file}

  @doc "Days left at or below which an end date reads as critical and as soon."
  def thresholds, do: %{critical: @critical_days, soon: @soon_days}

  @doc """
  How an end date stands on `today`: `:expired`, `:critical` (#{@critical_days}
  days or fewer), `:soon` (#{@soon_days} days or fewer), `:ok`, or
  `:open_ended` when there is no end date at all.
  """
  def status(nil, _today), do: :open_ended

  def status(%Date{} = until, %Date{} = today) do
    days = Date.diff(until, today)

    cond do
      days < 0 -> :expired
      days <= @critical_days -> :critical
      days <= @soon_days -> :soon
      true -> :ok
    end
  end

  @doc """
  Where the whitelist file lives. `{:ok, source}` holds no secret;
  `:not_configured` means the comparison is simply off.
  """
  def source do
    repository = env("ADO_WHITELIST_REPO")
    path = env("ADO_WHITELIST_PATH")
    project = env("ADO_WHITELIST_PROJECT") || env("ADO_PROJECT")

    cond do
      is_nil(repository) and is_nil(path) ->
        :not_configured

      is_nil(repository) or is_nil(path) ->
        {:error, "Set both ADO_WHITELIST_REPO and ADO_WHITELIST_PATH."}

      is_nil(project) ->
        {:error, "Set ADO_PROJECT, or ADO_WHITELIST_PROJECT when the file is in another project."}

      not AzureDevOps.repository_token?() ->
        {:error, "Set ADO_WHITELIST_PAT, or ADO_PAT, to a token with the Code (Read) scope."}

      true ->
        located(project, repository, path)
    end
  end

  defp located(project, repository, path) do
    with {:ok, org} <- AzureDevOps.organization() do
      {:ok,
       %{
         "org" => org,
         "project" => project,
         "repository" => repository,
         "path" => "/" <> String.trim_leading(path, "/"),
         "branch" => env("ADO_WHITELIST_BRANCH")
       }}
    end
  end

  defp env(name) do
    case String.trim(System.get_env(name) || "") do
      "" -> nil
      value -> value
    end
  end

  @doc """
  The whole picture for one team and environment scope.

    * `:repository` - whether the file was read, from where and when;
    * `:rows` - every CVE the file whitelists or Triage whitelists, the
      soonest end date first, with both sides' state;
    * `:missing` - CVEs that need a decision in Triage and that the file does
      not cover, most severe first (only when the file was read);
    * `:counts` - the totals shown above the table.

  Options: `reload: true` reads the file again instead of using the kept
  copy; `file: {label, text}` compares a local copy and never calls Azure
  DevOps.
  """
  def overview(scope \\ %{}, opts \\ []) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)
    today = DateTime.to_date(now)
    repository = repository(opts, now)
    entries = Map.get(repository, :entries, [])
    triage = triage(scope, now)
    rows = rows(entries, triage, today)

    %{
      today: today,
      repository: Map.delete(repository, :entries),
      rows: rows,
      missing: if(repository.state == :loaded, do: missing(entries, triage, today)),
      counts: counts(rows)
    }
  end

  ## The repository file

  defp repository(opts, now) do
    case Keyword.get(opts, :file) do
      {label, text} -> parsed(label, text, nil, now)
      nil -> remote(Keyword.get(opts, :reload, false), now)
    end
  end

  defp remote(reload?, now) do
    case source() do
      :not_configured -> %{state: :not_configured}
      {:error, message} -> %{state: :error, message: message}
      {:ok, source} -> kept(source, reload?, now) || read(source, now)
    end
  end

  defp kept(_source, true, _now), do: nil

  defp kept(source, false, now) do
    case :persistent_term.get(@cache_key, nil) do
      {^source, %{read_at: read_at} = list} ->
        if DateTime.diff(now, read_at) < @cache_seconds, do: list

      _other ->
        nil
    end
  end

  defp read(source, now) do
    case AzureDevOps.repository_file(source) do
      {:ok, %{content: text, commit: commit}} ->
        list =
          label(source)
          |> parsed(text, commit, now)
          |> Map.put(:url, AzureDevOps.repository_file_url(source))

        :persistent_term.put(@cache_key, {source, list})
        list

      {:error, reason} ->
        %{state: :error, label: label(source), message: explain(reason)}
    end
  end

  defp parsed(label, text, commit, now) do
    %{format: format, entries: entries} = Parse.entries(text)

    %{
      state: :loaded,
      label: label,
      read_at: now,
      commit: commit,
      format: format,
      total: length(entries),
      dated: Enum.count(entries, & &1.until),
      entries: entries
    }
  end

  defp label(source) do
    branch = if source["branch"], do: " on #{source["branch"]}", else: ""
    "#{source["project"]} / #{source["repository"]}#{source["path"]}#{branch}"
  end

  defp explain(:unauthorized),
    do: "Azure DevOps rejected the token. It needs the Code (Read) scope for this repository."

  defp explain(:not_found),
    do:
      "The repository, branch or file was not found, or the token cannot see that repository. " <>
        "Check ADO_WHITELIST_REPO, ADO_WHITELIST_PATH and ADO_WHITELIST_BRANCH."

  defp explain(:not_a_file), do: "The path does not point to a text file."
  defp explain(:too_large), do: "The file is larger than 1 MB."
  defp explain(_other), do: "Azure DevOps could not be reached. Try again in a moment."

  ## What Triage records

  defp triage(scope, now) do
    scope
    |> Map.take(["team", "environment"])
    |> Workspace.targets(now)
    |> Workspace.rows()
    |> Map.new(&{&1.cve, triage_row(&1)})
  end

  defp triage_row(row) do
    active = Enum.filter(row.scopes, & &1.active?)
    whitelisted = Enum.filter(active, &whitelisted?/1)
    open = Enum.count(active, & &1.needs_decision?)

    %{
      cve: row.cve,
      severity: row.severity,
      packages: row.packages,
      state: triage_state(active, whitelisted, open),
      until: last_day(whitelisted),
      deployments: length(active),
      whitelisted: length(whitelisted),
      open: open,
      decided:
        active
        |> Enum.filter(&(&1.covered? and not whitelisted?(&1)))
        |> Enum.map(&Decisions.label(&1.decision.decision))
        |> Enum.uniq()
    }
  end

  defp whitelisted?(target),
    do: target.covered? and target.decision.decision == "accepted_risk"

  defp triage_state([], _whitelisted, _open), do: :not_observed
  defp triage_state(_active, _whitelisted, open) when open > 0, do: :needs_decision

  defp triage_state(active, whitelisted, _open) when length(whitelisted) == length(active),
    do: :whitelisted

  defp triage_state(_active, _whitelisted, _open), do: :decided

  # A whitelist ends at the start of its `expires_at`, so the last day it
  # applies is the day before. The earliest one is the one that matters.
  defp last_day(whitelisted) do
    case whitelisted |> Enum.map(& &1.decision.expires_at) |> Enum.reject(&is_nil/1) do
      [] -> nil
      ends -> ends |> Enum.min(DateTime) |> DateTime.add(-1, :second) |> DateTime.to_date()
    end
  end

  ## Both sides together

  defp rows(entries, triage, today) do
    listed = Map.new(entries, &{&1.cve, &1})
    local = for {cve, row} <- triage, row.whitelisted > 0, do: cve

    (Map.keys(listed) ++ local)
    |> Enum.uniq()
    |> Enum.map(&row(&1, listed[&1], triage[&1], today))
    |> Enum.sort_by(&urgency/1)
  end

  defp row(cve, entry, local, today) do
    %{
      cve: cve,
      severity: local && local.severity,
      packages: local && local.packages,
      repository: entry && Map.merge(entry, expiry(entry.until, today)),
      triage: triage_cell(local, today)
    }
  end

  defp expiry(until, today),
    do: %{status: status(until, today), days_left: until && Date.diff(until, today)}

  defp triage_cell(nil, _today), do: %{state: :not_observed, until: nil}

  defp triage_cell(local, today) do
    cell = Map.take(local, [:state, :until, :decided, :deployments, :whitelisted, :open])
    if local.until, do: Map.merge(cell, expiry(local.until, today)), else: cell
  end

  # The soonest end date on either side first; entries with no end date last.
  defp urgency(row) do
    days =
      [row.repository && row.repository.days_left, row.triage[:days_left]]
      |> Enum.reject(&is_nil/1)
      |> Enum.min(fn -> 1_000_000 end)

    {days, row.cve}
  end

  # Needs a decision in Triage and has no entry in the file that still applies.
  defp missing(entries, triage, today) do
    covered =
      for entry <- entries, status(entry.until, today) != :expired, into: MapSet.new() do
        entry.cve
      end

    rows =
      triage
      |> Map.values()
      |> Enum.filter(&(&1.state == :needs_decision and not MapSet.member?(covered, &1.cve)))
      |> Enum.sort_by(&{-Triage.Severity.rank(&1.severity), &1.cve})

    %{total: length(rows), rows: Enum.map(rows, &Map.take(&1, [:cve, :severity, :packages]))}
  end

  defp counts(rows) do
    listed = Enum.filter(rows, & &1.repository)
    local = Enum.filter(rows, &((&1.triage[:whitelisted] || 0) > 0))

    %{
      repository: length(listed),
      expired: Enum.count(listed, &(&1.repository.status == :expired)),
      expiring: Enum.count(listed, &(&1.repository.status in [:critical, :soon])),
      not_in_findings: Enum.count(listed, &(&1.triage.state == :not_observed)),
      open_in_triage: Enum.count(listed, &(&1.triage.state == :needs_decision)),
      triage: length(local),
      triage_expiring: Enum.count(local, &(&1.triage[:status] in [:critical, :soon])),
      triage_only: Enum.count(local, &is_nil(&1.repository))
    }
  end
end
