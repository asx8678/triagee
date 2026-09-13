defmodule Triage.Collection.Crawl do
  @moduledoc """
  Bounded, read-only two-stage crawl.

  Stage one lists the image inventory per owner. Stage two fetches findings per
  image id with the mandatory engine argument. No pagination is invented: the
  source returns a single inventory list and one detail list per id. The status
  marker is observational only and is never used as a freshness cursor.

  Source inventory entries are validated (`id` UUID, `digest`, `usedInNamespaces`)
  before any branch of work spawns, so a malformed upstream record is a controlled
  failure rather than a linked-worker crash. Malformed owner entries, namespace
  owners and metrics are explicit incomplete evidence. Owner scope is attributed:
  when owners are requested, placements observed outside the requested set are
  marked `in_scope: false` and flagged.

  Detail responses are reconciled to the exact requested id and inventory digest;
  disagreements between the API ids that share a digest are explicit failures.

  `max_images` budgets the total number of detail *id* requests, not the number
  of digests: when the cap truncates any id request it is explicit incomplete
  evidence, and no second id is queried once the budget is spent.

  Collection never writes the inventory and references no `Triage.Repo`.
  """

  alias Triage.Collection.{Client, Normalize, Query}
  alias Triage.Collection.Errors
  alias Triage.Collection.Errors.{GraphQLError, InvalidOptionsError, TransportError}

  @doc "Runs the crawl and returns `{:ok, %Report{}}` or `{:error, exception}`."
  def run(config, transport, transport_state, opts) do
    with :ok <- validate_run_options(opts) do
      do_run(config, transport, transport_state, opts)
    end
  end

  # All run options are validated before the first marker request, so malformed
  # options cannot cost an upstream call or be silently ignored.
  defp validate_run_options(opts) do
    with :ok <- validate_owners_option(opts[:owners]),
         :ok <- validate_max_images_option(opts[:max_images]) do
      validate_signal_option(opts[:signal])
    end
  end

  defp validate_owners_option(nil), do: :ok
  defp validate_owners_option([]), do: :ok

  defp validate_owners_option(owners) when is_list(owners) do
    if Enum.all?(owners, &Query.valid_identifier?/1) do
      :ok
    else
      {:error, %InvalidOptionsError{message: "owners must be nonblank strings"}}
    end
  end

  defp validate_owners_option(_other) do
    {:error, %InvalidOptionsError{message: "owners must be a list of owner strings"}}
  end

  defp validate_max_images_option(nil), do: :ok

  defp validate_max_images_option(value) when is_integer(value) and value >= 1, do: :ok

  defp validate_max_images_option(_other) do
    {:error, %InvalidOptionsError{message: "max_images must be a positive integer"}}
  end

  defp validate_signal_option(nil), do: :ok
  defp validate_signal_option(fun) when is_function(fun, 0), do: :ok

  defp validate_signal_option(_other) do
    {:error, %InvalidOptionsError{message: "signal must be a zero-arity function"}}
  end

  defp do_run(config, transport, transport_state, opts) do
    client = Client.new(config, transport, transport_state, opts)
    t0 = System.monotonic_time(:millisecond)

    with {:ok, marker} <- fetch_marker(client),
         {:ok, owners} <- resolve_owners(client, opts),
         {inventory, one_failures, one_warnings} <-
           stage_one(client, owners, requested_owners(opts)),
         {:ok, details, two_failures, two_warnings} <- stage_two(client, inventory, opts) do
      report =
        Normalize.build(%{
          config: config,
          scope: scope_of(opts),
          status_marker: marker,
          inventory: inventory,
          details: details,
          failures: one_failures ++ two_failures,
          warnings: one_warnings ++ two_warnings,
          requests: Client.request_count(client),
          owners: owners,
          requested_owners: requested_owners(opts),
          max_images: opts[:max_images],
          duration_ms: System.monotonic_time(:millisecond) - t0
        })

      {:ok, report}
    end
  end

  defp scope_of(opts) do
    cond do
      is_list(opts[:owners]) and opts[:owners] != [] and is_integer(opts[:max_images]) ->
        "owner-limit"

      is_list(opts[:owners]) and opts[:owners] != [] ->
        "owners"

      is_integer(opts[:max_images]) ->
        "max-images"

      true ->
        "full"
    end
  end

  defp requested_owners(opts) do
    case opts[:owners] do
      owners when is_list(owners) and owners != [] -> Enum.uniq(owners)
      _other -> []
    end
  end

  defp fetch_marker(client) do
    case Client.query(client, Query.status_query(), "status") do
      {:ok, data} -> {:ok, marker_of(data)}
      {:error, error} -> {:error, error}
    end
  end

  defp marker_of(%{"status" => %{"lastClusterScan" => value}}) when is_binary(value), do: value
  defp marker_of(_other), do: nil

  defp resolve_owners(client, opts) do
    case opts[:owners] do
      owners when is_list(owners) and owners != [] ->
        if Enum.all?(owners, &Query.valid_identifier?/1) do
          {:ok, Enum.uniq(owners)}
        else
          {:error, %InvalidOptionsError{message: "owners must be nonblank strings"}}
        end

      _other ->
        fetch_owners(client)
    end
  end

  defp fetch_owners(client) do
    case Client.query(client, Query.owners_query(), "owners") do
      {:ok, %{"owner" => list}} when is_list(list) ->
        with {:ok, owners} <- extract_owners(list) do
          if owners == [] do
            {:error, %GraphQLError{message: "source returned no owners"}}
          else
            {:ok, owners}
          end
        end

      {:ok, _other} ->
        {:error, %GraphQLError{message: "owners response had an unexpected shape"}}

      {:error, error} ->
        {:error, error}
    end
  end

  defp extract_owners(list) do
    {owners, malformed} =
      Enum.reduce(list, {[], 0}, fn entry, {acc, bad} ->
        case owner_id(entry) do
          nil -> {acc, bad + 1}
          id -> {[id | acc], bad}
        end
      end)

    if malformed > 0 do
      {:error,
       %GraphQLError{
         message:
           "owners response contained #{malformed} malformed owner entr#{if malformed == 1, do: "y", else: "ies"}"
       }}
    else
      {:ok, owners |> Enum.reverse() |> Enum.uniq()}
    end
  end

  defp owner_id(%{"id" => id}) when is_binary(id) and id != "", do: id
  defp owner_id(_other), do: nil

  defp stage_one(client, owners, requested) do
    Enum.reduce_while(owners, {%{}, [], []}, fn owner, {inventory, failures, warnings} ->
      label = "images(owner=#{owner})"

      case Client.query(client, Query.image_list_query(owner), label) do
        {:ok, %{"image" => list}} when is_list(list) ->
          {inventory, failures, warnings} =
            Enum.reduce(list, {inventory, failures, warnings}, fn image, acc ->
              absorb_image(acc, owner, image)
            end)

          failures =
            if requested != [] and list == [] do
              ["#{label}: no images returned for requested owner" | failures]
            else
              failures
            end

          {:cont, {inventory, failures, warnings}}

        {:ok, _other} ->
          {:cont, {inventory, ["#{label}: unexpected response shape" | failures], warnings}}

        {:error, error} ->
          if Errors.terminal?(error) do
            {:halt, {:fatal, error}}
          else
            {:cont,
             {inventory, ["#{label}: #{Errors.sanitize_message(error.message)}" | failures],
              warnings}}
          end
      end
    end)
    |> case do
      {:fatal, error} -> {:error, error}
      {inventory, failures, warnings} -> {inventory, failures, warnings}
    end
  end

  # An inventory entry is only absorbed when every trusted field is well-formed.
  # A single malformed entry invalidates that owner's inventory read as evidence
  # of completeness, so it never silently looks like an empty or partial success.
  defp absorb_image({inventory, failures, warnings}, owner, image) when is_map(image) do
    case validate_image(image) do
      {:ok, digest, id, namespaces} ->
        entry =
          Map.get(inventory, digest, %{
            digest: digest,
            api_ids: MapSet.new(),
            owners: MapSet.new(),
            placements: MapSet.new(),
            image: image
          })

        entry = %{
          entry
          | api_ids: maybe_put(entry.api_ids, id),
            owners: MapSet.put(entry.owners, owner),
            placements: Enum.reduce(namespaces, entry.placements, &MapSet.put(&2, &1))
        }

        {Map.put(inventory, digest, entry), failures, warnings}

      {:error, reason} ->
        {inventory, failures ++ ["image: #{reason}"], warnings}
    end
  end

  defp absorb_image({inventory, failures, warnings}, _owner, _image) do
    {inventory, failures ++ ["image: entry was not an object"], warnings}
  end

  defp validate_image(image) do
    with {:ok, id} <- validate_id(image["id"]),
         {:ok, digest} <- validate_digest(image["digest"]),
         {:ok, namespaces} <- validate_namespaces(image["usedInNamespaces"]) do
      {:ok, digest, id, namespaces}
    end
  end

  # The invalid upstream id is never echoed: the failure is a constant
  # path/classification so a hostile id cannot reach the report.
  defp validate_id(id) when is_binary(id) do
    if Query.valid_image_id?(id) do
      {:ok, id}
    else
      {:error, "malformed image id (not a uuid); completeness not implied"}
    end
  end

  defp validate_id(_other), do: {:error, "missing image id; completeness not implied"}

  defp validate_digest(digest) when is_binary(digest) do
    if digest != "" do
      {:ok, digest}
    else
      {:error, "blank image digest; completeness not implied"}
    end
  end

  defp validate_digest(_other), do: {:error, "image has no digest; skipped"}

  defp validate_namespaces(value) when is_list(value) do
    Enum.reduce_while(value, {:ok, []}, fn ns, {:ok, acc} ->
      case namespace_entry(ns) do
        {:ok, namespace} -> {:cont, {:ok, [namespace | acc]}}
        :error -> {:halt, :error}
      end
    end)
    |> case do
      {:ok, list} -> {:ok, Enum.reverse(list)}
      :error -> {:error, "malformed usedInNamespaces entry; completeness not implied"}
    end
  end

  defp validate_namespaces(_other),
    do: {:error, "usedInNamespaces was not a list; completeness not implied"}

  defp namespace_entry(%{"id" => id, "owner" => owner}) do
    if Query.valid_identifier?(id) and Query.valid_identifier?(owner) do
      {:ok, %{namespace: id, owner: owner}}
    else
      :error
    end
  end

  defp namespace_entry(_other), do: :error

  defp maybe_put(set, value) when is_binary(value) and value != "", do: MapSet.put(set, value)
  defp maybe_put(set, _value), do: set

  defp stage_two(client, inventory, opts) do
    entries = inventory |> Map.values() |> Enum.sort_by(& &1.digest)
    max_images = opts[:max_images]

    targets =
      for entry <- entries,
          id <- entry.api_ids |> MapSet.to_list() |> Enum.sort(),
          do: {entry, id}

    {targets, truncated?} =
      if is_integer(max_images) and length(targets) > max_images do
        {Enum.take(targets, max_images), true}
      else
        {targets, false}
      end

    with {:ok, details, failures} <- fetch_targets(client, targets) do
      truncation =
        if truncated? do
          [
            "max_images limit (#{max_images}) truncated image detail requests; report is incomplete"
          ]
        else
          []
        end

      {:ok, details, truncation ++ failures, []}
    end
  end

  defp fetch_targets(_client, []), do: {:ok, %{}, []}

  defp fetch_targets(client, targets) do
    stream =
      Task.async_stream(targets, fn {entry, id} -> fetch_one(client, entry, id) end,
        max_concurrency: client.config.concurrency,
        timeout: client.config.request_timeout_ms + 5_000,
        on_timeout: :kill_task,
        ordered: false
      )

    Enum.reduce_while(stream, {:ok, %{}, []}, fn result, {:ok, acc, failures} ->
      case result do
        {:ok, {digest, :ok, detail}} ->
          {:cont, {:ok, accumulate(acc, digest, detail), failures}}

        {:ok, {_digest, :fail, message}} ->
          {:cont, {:ok, acc, [message | failures]}}

        {:ok, {:fatal, error}} ->
          {:halt, {:error, error}}

        {:exit, :timeout} ->
          {:halt, {:error, %TransportError{message: "engine worker timed out", reason: :timeout}}}

        {:exit, _reason} ->
          {:halt, {:error, %TransportError{message: "engine worker exited", reason: :worker}}}
      end
    end)
    |> case do
      {:error, error} ->
        {:error, error}

      {:ok, acc, failures} ->
        {details, conflict_failures} = finalize(acc)
        {:ok, details, conflict_failures ++ failures}
    end
  end

  defp fetch_one(client, entry, id) do
    label = "image detail"

    case Client.query(client, Query.image_detail_query(id, client.config.engine), label) do
      {:ok, %{"image" => list}} when is_list(list) ->
        case validate_detail(list, id, entry.digest) do
          {:ok, detail} -> {entry.digest, :ok, detail}
          {:error, message} -> {entry.digest, :fail, message}
        end

      {:ok, _other} ->
        {entry.digest, :fail, "#{entry.digest}: detail response had an unexpected shape"}

      {:error, error} ->
        if Errors.terminal?(error) do
          {:fatal, error}
        else
          {entry.digest, :fail, "#{entry.digest}: #{Errors.sanitize_message(error.message)}"}
        end
    end
  end

  defp accumulate(acc, digest, detail) do
    Map.update(acc, digest, %{first: detail, count: 1, conflict?: false}, fn current ->
      if current.first == detail do
        %{current | count: current.count + 1}
      else
        %{current | count: current.count + 1, conflict?: true}
      end
    end)
  end

  defp finalize(acc) do
    Enum.reduce(acc, {%{}, []}, fn
      {digest, %{conflict?: true}}, {details, failures} ->
        {details,
         ["#{digest}: conflicting details across image ids; not silently resolved" | failures]}

      {digest, %{first: detail}}, {details, failures} ->
        {Map.put(details, digest, detail), failures}
    end)
  end

  # Exact cardinality/id/digest: the response must carry the requested id (never a
  # different API id's finding) and the inventory digest, and must contain exactly
  # one object.
  defp validate_detail([detail], requested_id, digest) when is_map(detail) do
    cond do
      detail["id"] != requested_id ->
        {:error, "#{digest}: detail id did not match the requested image id"}

      detail["digest"] != digest ->
        {:error, "#{digest}: detail digest did not match the inventory digest"}

      true ->
        # The API id rotates and usedInNamespaces is owner-scoped placement
        # metadata; neither is finding content. Drop both so two ids sharing a
        # digest compare on their findings, not on their id or placement.
        {:ok, detail |> Map.delete("id") |> Map.delete("usedInNamespaces")}
    end
  end

  defp validate_detail([], _requested_id, digest),
    do: {:error, "#{digest}: no detail object returned for a requested image id"}

  defp validate_detail(list, _requested_id, digest) when is_list(list),
    do: {:error, "#{digest}: expected exactly one detail object, got #{length(list)}"}
end
