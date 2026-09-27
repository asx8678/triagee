defmodule Triage.Observations do
  @moduledoc """
  Offline ingestion of a normalized collection report.

  `ingest/2` accepts only a `%Triage.Collection.Report{}` and authorizes scope
  with `Triage.Collection.FixtureContract`. Payload `in_scope` flags are
  ignored. Content identity is an order-independent fallback, never a verified
  scan id, and does not clear evidence-packet live blockers.

  `pending_attention/1` is a bounded context read, not the current-run
  pointer and not a workspace UI queue. An eligible finding stays visible
  after a later omission, suppression, empty run, or wrong-scope run; this
  slice has no resolution authority. The same finding identity is returned
  once, preferring the higher severity and otherwise the earliest receipt.
  This module does not write inventory, decisions, cases, or packets, and it
  does not open a network transport.
  """

  import Ecto.Query
  alias Triage.{Canonical, Repo}
  alias Triage.Collection.{FixtureContract, Report}
  alias Triage.Observations.{Current, Observation, Run}

  @max_findings 200
  @max_images 100
  @max_placements 50
  @max_text 256
  @max_blocker 512
  @max_blockers 64
  @default_limit 50
  @max_limit 100
  @ingest_keys [:fetched_at, :ingested_at, :source_observed_at]
  @attention_keys [:limit]

  @type attention :: %{
          cve: String.t(),
          digest: String.t(),
          package_name: String.t(),
          package_version: String.t(),
          severity: String.t() | nil,
          identity_kind: String.t(),
          identity: String.t(),
          status_marker: String.t() | nil,
          source_observed_at: DateTime.t() | nil,
          fetched_at: DateTime.t(),
          ingested_at: DateTime.t(),
          paging_contract: String.t(),
          complete: boolean(),
          blockers: [String.t()],
          source_run_id: integer()
        }

  @doc """
  Persists one report under the fixture contract.

  Required clocks are `:fetched_at` and `:ingested_at`. `:source_observed_at`
  is stored only when that option is a valid UTC timestamp; a status marker
  is never parsed into it. Unknown options, including a caller-supplied scan
  id, are rejected.
  """
  @spec ingest(term(), keyword()) ::
          {:ok, %{run: Run.t(), created?: boolean()}} | {:error, term()}
  def ingest(report, opts \\ [])

  def ingest(%Report{} = report, opts) when is_list(opts) do
    with :ok <- known_opts(opts, @ingest_keys),
         {:ok, prepared} <- prepare(report, opts) do
      commit(prepared)
    end
  end

  def ingest(_other, _opts), do: {:error, :invalid_report}

  defp commit(prepared) do
    case Repo.transaction(fn -> write(prepared) end) do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Returns at most `:limit` attention-eligible observations on the current
  pointer. This is not a LiveView binding and it does not make a packet
  live-eligible.
  """
  @spec pending_attention(keyword()) ::
          {:ok, [attention()]} | {:error, :invalid_limit | :invalid_options}
  def pending_attention(opts \\ [])

  def pending_attention(opts) when is_list(opts) do
    with :ok <- known_opts(opts, @attention_keys),
         {:ok, limit} <- attention_limit(opts) do
      {:ok, Repo.all(attention_query(limit))}
    end
  end

  def pending_attention(_other), do: {:error, :invalid_options}

  @doc "Scope key derived only from the fixture contract."
  @spec scope_key() :: String.t()
  def scope_key do
    Canonical.hash({
      FixtureContract.source(),
      FixtureContract.environment(),
      FixtureContract.engine(),
      FixtureContract.query_version(),
      FixtureContract.owners()
    })
  end

  defp prepare(report, opts) do
    with :ok <- contract_match(report),
         {:ok, fetched_at} <- clock(Keyword.get(opts, :fetched_at), :fetched_at),
         {:ok, ingested_at} <- clock(Keyword.get(opts, :ingested_at), :ingested_at),
         {:ok, source_observed_at} <-
           clock(Keyword.get(opts, :source_observed_at), :source_observed_at),
         :ok <- clock_order(source_observed_at, fetched_at, ingested_at),
         {:ok, marker} <- marker(report.status_marker),
         {:ok, rows, notes} <- findings(report),
         {:ok, blockers} <- checked_blockers(report, notes, rows) do
      identity = content_identity(rows, blockers, Report.complete?(report))

      {:ok,
       %{
         identity: identity,
         run: %{
           source: FixtureContract.source(),
           scope_key: scope_key(),
           identity_kind: "content_fallback",
           identity: identity,
           status_marker: marker,
           source_observed_at: source_observed_at,
           fetched_at: fetched_at,
           ingested_at: ingested_at,
           paging_contract: FixtureContract.paging_contract(),
           complete: Report.complete?(report),
           blockers: blockers,
           counts: counts(rows),
           content_hash: identity,
           query_version: FixtureContract.query_version(),
           environment: FixtureContract.environment(),
           engine: FixtureContract.engine()
         },
         observations: rows
       }}
    end
  end

  defp contract_match(%Report{} = report) do
    if report.environment == FixtureContract.environment() and
         report.engine == FixtureContract.engine() do
      :ok
    else
      {:error, :contract_mismatch}
    end
  end

  defp findings(%Report{findings: findings, suppressed: suppressed, images: images})
       when is_list(findings) and is_list(suppressed) and is_list(images) do
    rows = findings ++ suppressed

    cond do
      length(rows) > @max_findings -> {:error, :too_many_findings}
      length(images) > @max_images -> {:error, :too_many_images}
      not Enum.all?(images, &is_map/1) -> {:error, :malformed_image}
      true -> classify_findings(rows, image_index(images))
    end
  end

  defp findings(_report), do: {:error, :malformed_report}

  defp image_index(images) do
    Enum.reduce_while(images, {:ok, %{}}, fn image, {:ok, acc} ->
      digest = Map.get(image, :digest)

      cond do
        not is_binary(digest) or not valid_text?(digest, @max_text) ->
          {:halt, {:error, :malformed_image}}

        Map.has_key?(acc, digest) ->
          {:halt, {:error, :conflicting_images}}

        true ->
          {:cont, {:ok, Map.put(acc, digest, image)}}
      end
    end)
  end

  defp classify_findings(_findings, {:error, reason}), do: {:error, reason}

  defp classify_findings(findings, {:ok, images}) do
    findings
    |> Enum.reduce_while({:ok, [], []}, fn finding, {:ok, rows, notes} ->
      case classify_finding(finding, images) do
        {:ok, row} -> {:cont, {:ok, [row | rows], notes}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, rows, notes} -> collapse(Enum.reverse(rows), notes)
      error -> error
    end
  end

  defp classify_finding(finding, images) when is_map(finding) do
    digest = Map.get(finding, :digest)
    cve = Map.get(finding, :cve)
    package_name = Map.get(finding, :package_name)
    package_version = Map.get(finding, :package_version)
    severity = Map.get(finding, :severity)
    suppressed = Map.get(finding, :suppressed)

    with :ok <- required_text(digest, :digest),
         :ok <- required_text(cve, :cve),
         :ok <- required_text(package_name, :package_name),
         :ok <- required_text(package_version, :package_version),
         :ok <- optional_text(severity, :severity),
         true <- is_boolean(suppressed) do
      {quarantine, owners} = scope(images[digest])

      {:ok,
       %{
         digest: digest,
         cve: cve,
         package_name: package_name,
         package_version: package_version,
         severity: severity,
         suppressed: suppressed,
         quarantine: quarantine,
         attention_eligible: not quarantine and not suppressed,
         placement_owners: owners,
         source_finding_identity:
           Canonical.hash({digest, cve, package_name, package_version, suppressed}),
         attention_identity: attention_identity(digest, cve, package_name, package_version)
       }}
    else
      false -> {:error, :malformed_finding}
      {:error, _} = error -> error
    end
  end

  defp classify_finding(_finding, _images), do: {:error, :malformed_finding}

  # Scope is the fixture contract's owner list. The payload's `in_scope` flag
  # is intentionally unread.
  defp scope(nil), do: {true, []}

  defp scope(image) do
    case placement_owners(Map.get(image, :placements)) do
      :quarantine -> {true, []}
      owners -> {outside_contract?(owners), owners}
    end
  end

  defp placement_owners(placements)
       when is_list(placements) and placements != [] and length(placements) <= @max_placements do
    case Enum.reduce_while(placements, {:ok, []}, &collect_owner/2) do
      :error -> :quarantine
      {:ok, owners} -> owners |> Enum.uniq() |> Enum.sort()
    end
  end

  defp placement_owners(_placements), do: :quarantine

  defp collect_owner(placement, {:ok, acc}) when is_map(placement) do
    owner = Map.get(placement, :owner)

    if is_binary(owner) and valid_text?(owner, @max_text) do
      {:cont, {:ok, [owner | acc]}}
    else
      {:halt, :error}
    end
  end

  defp collect_owner(_placement, _acc), do: {:halt, :error}

  defp outside_contract?(owners) do
    not Enum.all?(owners, &(&1 in FixtureContract.owners()))
  end

  defp collapse(rows, notes) do
    case fold_identities(rows) do
      :conflict ->
        {:error, :conflicting_findings}

      {kept, collapsed?} ->
        notes = if collapsed?, do: ["duplicate_findings_collapsed" | notes], else: notes
        {:ok, Enum.reverse(kept), notes}
    end
  end

  defp fold_identities(rows) do
    Enum.reduce_while(Enum.group_by(rows, & &1.source_finding_identity), {[], false}, fn
      {_id, group}, {acc, collapsed?} -> fold_group(group, acc, collapsed?)
    end)
  end

  defp fold_group(group, acc, collapsed?) do
    shapes = Enum.map(group, &Map.take(&1, [:severity, :quarantine, :suppressed]))

    cond do
      Enum.uniq(shapes) != [hd(shapes)] ->
        {:halt, :conflict}

      length(group) > 1 ->
        {:cont, {[hd(group) | acc], true}}

      true ->
        {:cont, {[hd(group) | acc], collapsed?}}
    end
  end

  defp blockers(report, notes, rows) do
    failures =
      if is_list(report.failures), do: report.failures, else: []

    quarantined = if Enum.any?(rows, & &1.quarantine), do: ["wrong_scope_quarantined"], else: []

    ["paging_contract_absent" | notes] ++ quarantined ++ failures
  end

  defp counts(rows) do
    %{
      "findings" => length(rows),
      "suppressed" => Enum.count(rows, & &1.suppressed),
      "quarantined" => Enum.count(rows, & &1.quarantine),
      "eligible" => Enum.count(rows, & &1.attention_eligible)
    }
  end

  defp content_identity(rows, blockers, complete) do
    material =
      rows
      |> Enum.map(fn row ->
        %{
          digest: row.digest,
          cve: row.cve,
          package_name: row.package_name,
          package_version: row.package_version,
          severity: row.severity,
          suppressed: row.suppressed,
          quarantine: row.quarantine,
          placement_owners: row.placement_owners
        }
      end)
      |> Enum.sort_by(&{&1.digest, &1.cve, &1.package_name, &1.package_version, &1.suppressed})

    Canonical.hash({
      FixtureContract.source(),
      scope_key(),
      material,
      %{complete: complete, blockers: Enum.sort(blockers)}
    })
  end

  defp attention_identity(digest, cve, package_name, package_version) do
    Canonical.hash({
      FixtureContract.source(),
      scope_key(),
      digest,
      cve,
      package_name,
      package_version
    })
  end

  defp write(prepared) do
    lock!()

    case Repo.get_by(Run,
           source: prepared.run.source,
           scope_key: prepared.run.scope_key,
           identity: prepared.identity
         ) do
      %Run{} = existing ->
        %{run: existing, created?: false}

      nil ->
        {run, created?} = insert_new(prepared)
        %{run: run, created?: created?}
    end
  end

  defp lock! do
    Repo.query!("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
      "observations:" <> FixtureContract.source() <> ":" <> scope_key()
    ])
  end

  defp insert_new(prepared) do
    Repo.query!("SAVEPOINT observation_insert")

    case %Run{} |> Run.changeset(prepared.run) |> Repo.insert() do
      {:ok, run} ->
        Repo.query!("RELEASE SAVEPOINT observation_insert")
        insert_observations!(run, prepared.observations)
        move_pointer!(run)
        {run, true}

      {:error, changeset} ->
        Repo.query!("ROLLBACK TO SAVEPOINT observation_insert")

        if unique_violation?(changeset) do
          {existing_run(prepared), false}
        else
          Repo.rollback(changeset)
        end
    end
  end

  defp existing_run(prepared) do
    Repo.get_by!(Run,
      source: prepared.run.source,
      scope_key: prepared.run.scope_key,
      identity: prepared.identity
    )
  end

  defp insert_observations!(run, rows) do
    Enum.each(rows, fn row ->
      attrs = row |> Map.drop([:placement_owners]) |> Map.put(:source_run_id, run.id)

      case %Observation{} |> Observation.changeset(attrs) |> Repo.insert() do
        {:ok, _observation} -> :ok
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  defp move_pointer!(run) do
    current =
      Repo.get_by(Current, source: run.source, scope_key: run.scope_key)

    if move_pointer?(current, run) do
      attrs = %{
        source: run.source,
        scope_key: run.scope_key,
        source_run_id: run.id,
        source_observed_at: run.source_observed_at
      }

      result =
        case current do
          nil -> %Current{} |> Current.changeset(attrs) |> Repo.insert()
          current -> current |> Current.changeset(attrs) |> Repo.update()
        end

      case result do
        {:ok, _} -> :ok
        {:error, changeset} -> Repo.rollback(changeset)
      end
    else
      :ok
    end
  end

  defp move_pointer?(nil, _run), do: true

  defp move_pointer?(%Current{source_observed_at: nil}, %Run{source_observed_at: %DateTime{}}),
    do: true

  defp move_pointer?(%Current{source_observed_at: %DateTime{} = old}, %Run{
         source_observed_at: %DateTime{} = new
       }) do
    DateTime.compare(new, old) == :gt
  end

  defp move_pointer?(_current, _run), do: false

  # Attention is not the current pointer. Every eligible receipt remains a
  # candidate. The same finding/scope identity is returned once: the higher
  # severity wins, and equal severity keeps the earliest receipt so a later
  # omission, suppression, empty run, or wrong-scope run cannot hide it.
  defp attention_query(limit) do
    source = FixtureContract.source()
    scope = scope_key()

    ranked =
      from o in Observation,
        join: r in Run,
        on: r.id == o.source_run_id,
        where: o.attention_eligible == true and r.source == ^source and r.scope_key == ^scope,
        windows: [
          attention: [
            partition_by: o.attention_identity,
            order_by: [
              desc:
                fragment(
                  "CASE ? WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END",
                  o.severity
                ),
              asc: o.id
            ]
          ]
        ],
        select: %{
          cve: o.cve,
          digest: o.digest,
          package_name: o.package_name,
          package_version: o.package_version,
          severity: o.severity,
          identity_kind: r.identity_kind,
          identity: r.identity,
          status_marker: r.status_marker,
          source_observed_at: r.source_observed_at,
          fetched_at: r.fetched_at,
          ingested_at: r.ingested_at,
          paging_contract: r.paging_contract,
          complete: r.complete,
          blockers: r.blockers,
          source_run_id: r.id,
          position: over(row_number(), :attention)
        }

    from row in subquery(ranked),
      where: row.position == 1,
      order_by: [asc: row.cve, asc: row.digest, asc: row.package_name, asc: row.package_version],
      limit: ^limit,
      select: %{
        cve: row.cve,
        digest: row.digest,
        package_name: row.package_name,
        package_version: row.package_version,
        severity: row.severity,
        identity_kind: row.identity_kind,
        identity: row.identity,
        status_marker: row.status_marker,
        source_observed_at: row.source_observed_at,
        fetched_at: row.fetched_at,
        ingested_at: row.ingested_at,
        paging_contract: row.paging_contract,
        complete: row.complete,
        blockers: row.blockers,
        source_run_id: row.source_run_id
      }
  end

  defp attention_limit(opts) do
    case Keyword.get(opts, :limit, @default_limit) do
      limit when is_integer(limit) and limit >= 1 and limit <= @max_limit -> {:ok, limit}
      _other -> {:error, :invalid_limit}
    end
  end

  defp known_opts(opts, allowed) do
    if Keyword.keyword?(opts) and Enum.all?(opts, fn {key, _value} -> key in allowed end) do
      :ok
    else
      {:error, :invalid_options}
    end
  end

  defp clock(nil, :source_observed_at), do: {:ok, nil}
  defp clock(nil, _field), do: {:error, :malformed_timestamp}

  defp clock(
         %DateTime{calendar: Calendar.ISO, time_zone: "Etc/UTC", microsecond: {0, 0}} = value,
         _field
       ) do
    {:ok, DateTime.truncate(value, :second)}
  end

  defp clock(_other, _field), do: {:error, :malformed_timestamp}

  defp clock_order(source_observed_at, fetched_at, ingested_at) do
    source_ok =
      is_nil(source_observed_at) or DateTime.compare(source_observed_at, fetched_at) != :gt

    if source_ok and DateTime.compare(fetched_at, ingested_at) != :gt do
      :ok
    else
      {:error, :malformed_timestamp}
    end
  end

  defp marker(nil), do: {:ok, nil}

  defp marker(value) when is_binary(value) do
    if valid_text?(value, @max_text), do: {:ok, value}, else: {:error, :invalid_marker}
  end

  defp marker(_other), do: {:error, :invalid_marker}

  defp required_text(value, _field) when is_binary(value) do
    if valid_text?(value, @max_text), do: :ok, else: {:error, :malformed_finding}
  end

  defp required_text(_value, _field), do: {:error, :malformed_finding}

  defp optional_text(nil, _field), do: :ok

  defp optional_text(value, _field) when is_binary(value) do
    if valid_text?(value, 64), do: :ok, else: {:error, :malformed_finding}
  end

  defp optional_text(_value, _field), do: {:error, :malformed_finding}

  defp valid_text?(value, max) do
    value != "" and byte_size(value) <= max and not Regex.match?(~r/[\x00-\x1F\x7F]/, value)
  end

  defp unique_violation?(changeset) do
    Enum.any?(changeset.errors, fn
      {_field, {_message, opts}} -> opts[:constraint] == :unique
      _other -> false
    end)
  end

  defp checked_blockers(report, notes, rows) do
    blockers = blockers(report, notes, rows)

    if blockers_ok?(blockers) do
      {:ok, blockers}
    else
      {:error, :invalid_blocker}
    end
  end

  defp blockers_ok?(blockers) do
    is_list(blockers) and length(blockers) <= @max_blockers and
      Enum.all?(blockers, &(is_binary(&1) and valid_text?(&1, @max_blocker)))
  end
end
