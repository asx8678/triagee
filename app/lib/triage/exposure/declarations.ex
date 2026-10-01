defmodule Triage.Exposure.Declarations do
  @moduledoc """
  Operator declarations of which deployments are internet-facing, read from a
  local JSON file (`mix triage.exposure`).

  The scanner inventory does not say whether a deployment is reachable from the
  internet, so an operator states it per team, environment and, optionally,
  namespace:

      {
        "format": "triage.exposure",
        "version": 1,
        "source": "manual:security-team",
        "observed_at": "2026-10-01T06:00:00Z",
        "deployments": [
          {"team": "payments", "environment": "prod", "exposure": "internal"},
          {"team": "payments", "environment": "prod", "namespace": "gateway",
           "exposure": "internet_exposed"}
        ]
      }

  An entry without `namespace` covers every deployment of that team and
  environment; an entry with one is more specific and wins for that namespace.
  `observed_at` defaults to now and `expires_at` is optional. Each declaration
  is appended as exposure evidence through `Triage.Exposure.record/6`: history
  is never rewritten, and only active deployments are matched.

  Recording exposure changes the evidence a decision was made from, so a
  whitelist recorded while exposure was unknown needs a decision again. Declare
  exposure before triaging.
  """

  import Ecto.Query

  alias Triage.Exposure
  alias Triage.Inventory.ImagePlacement
  alias Triage.Repo

  @format "triage.exposure"
  @version 1
  @max_bytes 1_000_000
  @max_entries 5_000
  @max_text 120
  @root_keys ~w(format version source observed_at expires_at deployments)
  @entry_keys ~w(team environment namespace exposure)

  @doc "Largest accepted declaration file, in bytes."
  def max_bytes, do: @max_bytes

  @doc "Parses and validates a declaration document. Never touches the database."
  def parse(json) when is_binary(json) and byte_size(json) <= @max_bytes do
    case Jason.decode(json) do
      {:ok, %{} = raw} -> validate(raw)
      {:ok, _other} -> {:error, ["the file must be a JSON object"]}
      {:error, error} -> {:error, ["invalid JSON: #{Exception.message(error)}"]}
    end
  end

  def parse(_other), do: {:error, ["the file is too large or not text"]}

  defp validate(raw) do
    {observed_at, observed_errors} = time(raw["observed_at"], "observed_at")
    {expires_at, expires_errors} = time(raw["expires_at"], "expires_at")
    {entries, entry_errors} = entries(raw["deployments"])

    errors =
      unknown_keys(raw, @root_keys, "the file") ++
        check(raw["format"] == @format, ~s(format must be "#{@format}")) ++
        check(raw["version"] == @version, "version must be #{@version}") ++
        check(text?(raw["source"]), "source must be a short text naming who declares this") ++
        observed_errors ++ expires_errors ++ entry_errors

    if errors == [] do
      {:ok,
       %{
         source: String.trim(raw["source"]),
         observed_at: observed_at,
         expires_at: expires_at,
         entries: entries
       }}
    else
      {:error, errors}
    end
  end

  defp entries(list) when is_list(list) and list != [] and length(list) <= @max_entries do
    {entries, errors} =
      list
      |> Enum.with_index()
      |> Enum.map_reduce([], fn {raw, index}, errors ->
        case entry(raw, "deployments[#{index}]") do
          {:ok, entry} -> {entry, errors}
          {:error, found} -> {nil, errors ++ found}
        end
      end)

    {Enum.reject(entries, &is_nil/1), errors}
  end

  defp entries(_other),
    do: {[], ["deployments must be a list of 1 to #{@max_entries} entries"]}

  defp entry(%{} = raw, path) do
    errors =
      unknown_keys(raw, @entry_keys, path) ++
        check(text?(raw["team"]), "#{path}.team is required") ++
        check(text?(raw["environment"]), "#{path}.environment is required") ++
        check(
          is_nil(raw["namespace"]) or text?(raw["namespace"]),
          "#{path}.namespace must be a short text when given"
        ) ++
        check(
          raw["exposure"] in Exposure.exposures(),
          "#{path}.exposure must be one of #{Enum.join(Exposure.exposures(), ", ")}"
        )

    if errors == [] do
      {:ok,
       %{
         team: String.trim(raw["team"]),
         environment: String.trim(raw["environment"]),
         namespace: raw["namespace"] && String.trim(raw["namespace"]),
         exposure: raw["exposure"]
       }}
    else
      {:error, errors}
    end
  end

  defp entry(_other, path), do: {:error, ["#{path} must be an object"]}

  defp unknown_keys(raw, allowed, where) do
    case Map.keys(raw) -- allowed do
      [] -> []
      unknown -> ["#{where} has unknown keys: #{Enum.join(unknown, ", ")}"]
    end
  end

  defp check(true, _message), do: []
  defp check(_false, message), do: [message]

  defp text?(value),
    do:
      is_binary(value) and String.valid?(value) and String.trim(value) != "" and
        String.length(value) <= @max_text and not String.match?(value, ~r/[\x00-\x1F\x7F]/)

  defp time(nil, _key), do: {nil, []}

  defp time(value, key) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, time, _offset} -> {DateTime.truncate(time, :second), []}
      _invalid -> {nil, ["#{key} must be an ISO 8601 time with an offset"]}
    end
  end

  defp time(_value, key), do: {nil, ["#{key} must be an ISO 8601 time with an offset"]}

  @doc """
  Read-only: which active deployments the declaration covers and what would be
  recorded. Returns `{:ok, plan}` or `{:error, messages}`.
  """
  def plan(declaration, now \\ DateTime.utc_now()) do
    now = DateTime.truncate(now, :second)
    observed_at = declaration.observed_at || now
    placements = placements(declaration.entries)
    current = Exposure.current_evidence(Enum.map(placements, & &1.id), now)

    {decided, conflicts} =
      Enum.reduce(placements, {[], []}, fn placement, {decided, conflicts} ->
        case declared(placement, declaration.entries) do
          {:ok, exposure} -> {[{placement, exposure} | decided], conflicts}
          :conflict -> {decided, [scope(placement) | conflicts]}
        end
      end)

    rows =
      decided
      |> Enum.reverse()
      |> Enum.map(fn {placement, exposure} ->
        %{
          placement: placement,
          exposure: exposure,
          action:
            action(Map.get(current, placement.id), exposure, declaration.source, observed_at)
        }
      end)

    errors =
      time_errors(observed_at, declaration.expires_at, now) ++
        Enum.map(Enum.uniq(conflicts), &"entries disagree about #{&1}") ++
        for(
          %{action: :same_time_conflict, placement: placement} <- rows,
          do:
            "#{scope(placement)} already has different evidence observed at exactly " <>
              "#{DateTime.to_iso8601(observed_at)}; use a later observed_at"
        )

    if errors == [] do
      {:ok,
       %{
         source: declaration.source,
         observed_at: observed_at,
         expires_at: declaration.expires_at,
         rows: rows,
         unmatched: unmatched(declaration.entries, placements)
       }}
    else
      {:error, Enum.uniq(errors)}
    end
  end

  # The same two rules `Triage.Exposure.record/6` enforces, reported by the dry run.
  defp time_errors(observed_at, expires_at, now) do
    limit = DateTime.add(now, Exposure.Policy.clock_tolerance_seconds(), :second)

    check(DateTime.compare(observed_at, limit) != :gt, "observed_at is in the future") ++
      check(
        is_nil(expires_at) or DateTime.compare(expires_at, observed_at) != :lt,
        "expires_at is earlier than observed_at"
      )
  end

  defp placements(entries) do
    teams = entries |> Enum.map(& &1.team) |> Enum.uniq()
    environments = entries |> Enum.map(& &1.environment) |> Enum.uniq()
    pairs = MapSet.new(entries, &{&1.team, &1.environment})

    from(p in ImagePlacement,
      where: p.active and p.owner in ^teams and p.environment in ^environments,
      order_by: [asc: p.owner, asc: p.environment, asc: p.namespace, asc: p.id]
    )
    |> Repo.all()
    |> Enum.filter(
      &(MapSet.member?(pairs, {&1.owner, &1.environment}) and declared(&1, entries) != :none)
    )
  end

  # The namespace entry wins over the team-wide entry for the same deployment.
  defp declared(placement, entries) do
    matching =
      Enum.filter(
        entries,
        &(&1.team == placement.owner and &1.environment == placement.environment)
      )

    specific = Enum.filter(matching, &(&1.namespace == placement.namespace))
    general = Enum.filter(matching, &is_nil(&1.namespace))

    case Enum.uniq(Enum.map(if(specific != [], do: specific, else: general), & &1.exposure)) do
      [] -> :none
      [exposure] -> {:ok, exposure}
      _several -> :conflict
    end
  end

  defp action(nil, _exposure, _source, _observed_at), do: :record

  defp action(evidence, exposure, source, observed_at) do
    same? =
      evidence.exposure == exposure and evidence.source == source and evidence.state == :current

    case DateTime.compare(observed_at, evidence.observed_at) do
      :gt -> :record
      :eq -> if(same?, do: :unchanged, else: :same_time_conflict)
      :lt -> :newer_exists
    end
  end

  defp unmatched(entries, placements) do
    for entry <- entries,
        not Enum.any?(placements, fn placement ->
          placement.owner == entry.team and placement.environment == entry.environment and
            (is_nil(entry.namespace) or entry.namespace == placement.namespace)
        end) do
      Enum.join(Enum.reject([entry.team, entry.environment, entry.namespace], &is_nil/1), "/")
    end
  end

  defp scope(placement),
    do: "#{placement.owner}/#{placement.environment}/#{placement.namespace}"

  @doc "Records the planned evidence in one transaction. Returns `{:ok, plan}`."
  def apply(declaration, now \\ DateTime.utc_now()) do
    with {:ok, plan} <- plan(declaration, now),
         {:ok, plan} <- Repo.transaction(fn -> record_all!(plan, now) end) do
      {:ok, plan}
    else
      {:error, messages} when is_list(messages) -> {:error, messages}
      {:error, reason} -> {:error, [explain(reason)]}
    end
  end

  defp record_all!(plan, now) do
    for %{action: :record, placement: placement, exposure: exposure} <- plan.rows do
      evidence = {placement.id, exposure, plan.source, plan.observed_at, plan.expires_at}
      record!(evidence, now)
    end

    plan
  end

  defp record!({placement_id, exposure, source, observed_at, expires_at}, now) do
    case Exposure.record(placement_id, exposure, source, observed_at, expires_at, now) do
      {:ok, _evidence} -> :ok
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  defp explain(:future_observation), do: "observed_at is in the future"
  defp explain(:expiry_before_observation), do: "expires_at is earlier than observed_at"
  defp explain(reason), do: "the evidence was rejected: #{inspect(reason)}"

  @doc "Counts of the plan's rows by action, for the task's summary."
  def summary(plan) do
    counts = Enum.frequencies_by(plan.rows, & &1.action)

    %{
      matched: length(plan.rows),
      record: Map.get(counts, :record, 0),
      unchanged: Map.get(counts, :unchanged, 0),
      newer_exists: Map.get(counts, :newer_exists, 0),
      unmatched: plan.unmatched
    }
  end
end
