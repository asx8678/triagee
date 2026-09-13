defmodule Triage.Replay do
  @moduledoc """
  Pure version-1 synthetic replay. No transport, process startup or persistence.
  Limits: 1 MiB JSON, lexical container depth 32 before decode, 4096 bytes per
  string (including keys), 5000 aggregate array elements, 64 keys per object,
  64 KiB output. Object keys are recursively sorted for SHA-256; array order
  is significant. Unknown envelope fields, including provenance, are rejected.
  Environments: test, development, staging, production. Engines: trivy, grype,
  Trivy, Grype. Diagnostics are classifications, never source text.
  """
  alias Triage.Collection.{Normalize, Query}
  @fields ~w(format version origin environment engine owners inventories details)
  @limits %{
    max_input_bytes: 1_048_576,
    max_depth: 32,
    max_string_bytes: 4096,
    max_records: 5000,
    max_output_bytes: 65_536
  }

  def json_limits, do: @limits

  def run(json) when is_binary(json) do
    cond do
      byte_size(json) > @limits.max_input_bytes ->
        {:error, :input_too_large}

      true ->
        case preflight(json, [], :plain, 0) do
          :ok -> decode_run(json)
          error -> error
        end
    end
  rescue
    _ -> {:error, :execution_error}
  catch
    _, _ -> {:error, :execution_error}
  end

  def run(_), do: {:error, :invalid_input}

  defp decode_run(json) do
    case Jason.decode(json) do
      {:ok, doc} ->
        if envelope?(doc) and bounded?(doc) and records(doc) <= 5000 do
          summarize(doc)
        else
          {:error, :invalid_document}
        end

      _ ->
        {:error, :invalid_json}
    end
  end

  defp envelope?(d) when is_map(d) do
    Enum.sort(Map.keys(d)) == Enum.sort(@fields) and
      d["format"] == "triage.replay" and d["version"] === 1 and
      d["origin"] == "synthetic" and
      d["environment"] in ~w(test development staging production) and
      d["engine"] in ~w(trivy grype Trivy Grype) and
      is_list(d["owners"]) and is_list(d["inventories"]) and is_list(d["details"]) and
      Enum.all?(d["owners"], &Query.valid_identifier?/1)
  end

  defp envelope?(_), do: false
  defp bounded?(v) when is_binary(v), do: byte_size(v) <= 4096
  defp bounded?(v) when is_list(v), do: Enum.all?(v, &bounded?/1)

  defp bounded?(v) when is_map(v),
    do: map_size(v) <= 64 and Enum.all?(v, fn {k, x} -> bounded?(k) and bounded?(x) end)

  defp bounded?(_), do: true
  defp records(v) when is_list(v), do: length(v) + Enum.sum(Enum.map(v, &records/1))
  defp records(v) when is_map(v), do: Enum.sum(Enum.map(Map.values(v), &records/1))
  defp records(_), do: 0

  # Resource lexer only: strings/escapes and scalar token boundaries, not JSON
  # grammar. Each array value is charged once at its start (containers included).
  # Object keys are charged before decode, including duplicate keys. Jason remains
  # the grammar authority for under-budget malformed documents.
  defp preflight(_, _, _, n) when n > 5000, do: {:error, :invalid_document}

  defp preflight(_, [{:object, _, n} | _], _, _) when n > 64,
    do: {:error, :invalid_document}

  defp preflight(<<>>, _, _, _), do: :ok

  defp preflight(<<_, rest::binary>>, stack, :escape, n),
    do: preflight(rest, stack, :string, n)

  defp preflight(<<92, rest::binary>>, stack, :string, n),
    do: preflight(rest, stack, :escape, n)

  defp preflight(<<34, rest::binary>>, stack, :string, n),
    do: preflight(rest, stack, :plain, n)

  defp preflight(<<_, rest::binary>>, stack, :string, n),
    do: preflight(rest, stack, :string, n)

  defp preflight(<<c, _::binary>> = input, stack, :token, n)
       when c in [32, 9, 10, 13, 44, 93, 125, 58, 91, 123, 34],
       do: preflight(input, stack, :plain, n)

  defp preflight(<<_, rest::binary>>, stack, :token, n),
    do: preflight(rest, stack, :token, n)

  defp preflight(<<c, rest::binary>>, stack, :plain, n) when c in [32, 9, 10, 13],
    do: preflight(rest, stack, :plain, n)

  defp preflight(<<44, rest::binary>>, [{kind, _, fields} | tail], :plain, n),
    do: preflight(rest, [{kind, :start, fields} | tail], :plain, n)

  defp preflight(<<58, rest::binary>>, stack, :plain, n),
    do: preflight(rest, stack, :plain, n)

  defp preflight(<<c, rest::binary>>, [{kind, _, _} | tail], :plain, n)
       when (c == 93 and kind == :array) or (c == 125 and kind == :object),
       do: preflight(rest, tail, :plain, n)

  defp preflight(<<c, _::binary>>, _, :plain, _) when c in [93, 125, 44], do: :ok

  defp preflight(<<c, rest::binary>>, stack, :plain, n) do
    {stack, n} =
      case stack do
        [{:array, :start, fields} | tail] -> {[{:array, :value, fields} | tail], n + 1}
        [{:object, :start, fields} | tail] -> {[{:object, :value, fields + 1} | tail], n}
        _ -> {stack, n}
      end

    cond do
      n > 5000 ->
        {:error, :invalid_document}

      match?([{:object, _, 65} | _], stack) ->
        {:error, :invalid_document}

      c in [91, 123] and length(stack) >= 32 ->
        {:error, :invalid_json}

      c in [91, 123] ->
        kind = if c == 91, do: :array, else: :object
        preflight(rest, [{kind, :start, 0} | stack], :plain, n)

      c == 34 ->
        preflight(rest, stack, :string, n)

      true ->
        preflight(rest, stack, :token, n)
    end
  end

  defp summarize(doc) do
    owners = doc["owners"]
    initial = {%{}, %{}, [], []}

    {inventory, ids, seen, failures} =
      Enum.reduce(doc["inventories"], initial, fn row, {inv, ids, seen, failures} ->
        case row do
          %{"owner" => owner, "images" => images} when is_list(images) ->
            bad = owner not in owners or owner in seen or map_size(row) != 2
            failures = if bad, do: ["inventory_invalid" | failures], else: failures

            {inv, ids, failures} =
              Enum.reduce(images, {inv, ids, failures}, &image(&1, owner, &2))

            {inv, ids, [owner | seen], failures}

          _ ->
            {inv, ids, seen, ["inventory_invalid" | failures]}
        end
      end)

    failures =
      if Enum.sort(seen) != Enum.sort(owners) or length(Enum.uniq(owners)) != length(owners),
        do: ["inventory_incomplete" | failures],
        else: failures

    {details, detail_ids, failures} =
      Enum.reduce(doc["details"], {%{}, [], failures}, fn row, acc ->
        detail(row, ids, inventory, acc)
      end)

    failures =
      if Enum.sort(detail_ids) != Enum.sort(Map.keys(ids)),
        do: ["detail_incomplete" | failures],
        else: failures

    report =
      Normalize.build(%{
        config: %{
          environment: doc["environment"],
          engine: doc["engine"],
          max_records: 5000,
          max_text_bytes: 4096,
          max_depth: 32,
          max_total_bytes: 8_388_608
        },
        scope: "owners",
        status_marker: nil,
        owners: owners,
        requested_owners: owners,
        inventory: inventory,
        details: details,
        warnings: [],
        failures: failures,
        requests: 0,
        duration_ms: 0
      })

    complete = failures == [] and not report.incomplete and report.failures == []
    codes = if complete, do: [], else: ["incomplete_evidence"]
    codes = if report.warnings == [], do: codes, else: codes ++ ["normalization_warning"]

    summary = %{
      "format" => "triage.replay.result",
      "version" => 1,
      "origin" => "synthetic",
      "complete" => complete,
      "actionable" => false,
      "inventory_changed" => false,
      "historical_provenance" => false,
      "environment" => doc["environment"],
      "engine" => doc["engine"],
      "scope" => "owners",
      "diagnostics" => codes,
      "input_sha256" => Base.encode16(:crypto.hash(:sha256, canonical(doc)), case: :lower),
      "counts" => %{
        "owners" => length(Enum.uniq(owners)),
        "images" => length(report.images),
        "findings" => length(report.findings),
        "suppressed" => length(report.suppressed),
        "actionable" => 0
      }
    }

    if byte_size(Jason.encode!(summary)) <= 65_536,
      do: {:ok, summary},
      else: {:error, :output_too_large}
  end

  defp image(raw, owner, {inv, ids, failures}) when is_map(raw) do
    id = raw["id"]
    digest = raw["digest"]
    ns = raw["usedInNamespaces"]

    valid =
      Query.valid_image_id?(id) and is_binary(digest) and digest != "" and
        allowed?(
          raw,
          ~w(id digest description repository tag usage softwareBillOfMaterialCreatedBy usedInNamespaces metrics)
        ) and
        counts?(raw, :inventory) and is_list(ns) and
        Enum.all?(ns, fn
          %{"id" => n, "owner" => o} = placement ->
            map_size(placement) == 2 and Query.valid_identifier?(n) and Query.valid_identifier?(o)

          _ ->
            false
        end)

    if valid do
      prior = Map.get(inv, digest)
      claim = MapSet.new(ns)

      conflict =
        (Map.has_key?(ids, id) and ids[id] != digest) or
          (prior != nil and Map.has_key?(prior.claims, id) and prior.claims[id] != claim) or
          (prior != nil and
             Map.drop(prior.image, ["id", "usedInNamespaces"]) !=
               Map.drop(raw, ["id", "usedInNamespaces"]))

      entry =
        prior ||
          %{
            digest: digest,
            image: raw,
            owners: MapSet.new(),
            api_ids: MapSet.new(),
            claims: %{},
            placements: MapSet.new()
          }

      placements = Enum.map(ns, &%{owner: &1["owner"], namespace: &1["id"]})

      entry = %{
        entry
        | owners: MapSet.put(entry.owners, owner),
          api_ids: MapSet.put(entry.api_ids, id),
          claims: Map.put(entry.claims, id, claim),
          placements: Enum.reduce(placements, entry.placements, &MapSet.put(&2, &1))
      }

      {Map.put(inv, digest, entry), Map.put(ids, id, digest),
       if(conflict, do: ["identity_conflict" | failures], else: failures)}
    else
      {inv, ids, ["image_invalid" | failures]}
    end
  end

  defp image(_, _, {inv, ids, failures}), do: {inv, ids, ["image_invalid" | failures]}

  defp detail(%{"id" => id, "image" => raw} = row, ids, inventory, {details, seen, failures})
       when is_map(raw) do
    digest = Map.get(ids, id)
    clean = Map.drop(raw, ["id", "usedInNamespaces"])

    valid =
      map_size(row) == 2 and digest != nil and raw["id"] == id and raw["digest"] == digest and
        allowed?(
          raw,
          ~w(id digest description tag softwareBillOfMaterialCreatedBy metrics vulnerabilities excludedVulnerabilities)
        ) and
        counts?(raw, :detail) and placement_claim?(raw, inventory[digest])

    conflict = Map.has_key?(details, digest) and details[digest] != clean

    if valid and not conflict and id not in seen do
      {Map.put(details, digest, clean), [id | seen], failures}
    else
      {details, seen, ["detail_invalid" | failures]}
    end
  end

  defp detail(_, _, _, {details, seen, failures}),
    do: {details, seen, ["detail_invalid" | failures]}

  # Query's two stages request different metrics. No missing/null count fallback.
  defp counts?(%{"metrics" => metrics}, stage) when is_map(metrics) do
    required =
      if stage == :inventory,
        do: ~w(vulnerabilities vulnerabilitiesSuppressed),
        else: ~w(vulnerabilities vulnerableComponents)

    allowed?(metrics, ["status" | required]) and
      Enum.all?(required, fn key -> is_integer(metrics[key]) and metrics[key] >= 0 end)
  end

  defp counts?(_, _), do: false
  defp allowed?(map, keys), do: Enum.all?(Map.keys(map), &(&1 in keys))

  # Inventory is the required placement authority. Optional detail claims must agree.
  defp placement_claim?(raw, entry) do
    if Map.has_key?(raw, "usedInNamespaces") do
      ns = raw["usedInNamespaces"]

      is_list(ns) and
        Enum.all?(ns, fn
          %{"id" => n, "owner" => o} = placement ->
            map_size(placement) == 2 and Query.valid_identifier?(n) and Query.valid_identifier?(o)

          _ ->
            false
        end) and
        MapSet.new(Enum.map(ns, &%{owner: &1["owner"], namespace: &1["id"]})) == entry.placements
    else
      true
    end
  end

  defp canonical(v) when is_map(v) do
    pairs =
      v
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map(fn {k, x} -> [Jason.encode!(k), ":", canonical(x)] end)

    ["{", Enum.intersperse(pairs, ","), "}"]
  end

  defp canonical(v) when is_list(v),
    do: ["[", Enum.intersperse(Enum.map(v, &canonical/1), ","), "]"]

  defp canonical(v), do: Jason.encode!(v)
end
