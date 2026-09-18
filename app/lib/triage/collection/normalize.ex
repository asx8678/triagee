defmodule Triage.Collection.Normalize do
  @moduledoc """
  Normalizes raw source responses into a read-only report.

  Invariants:

    * image identity is the immutable digest, never the rotating API id;
    * a finding is one `(digest, advisory, package, version)` occurrence;
    * placements are aggregated across owners with an explicit environment and an
      explicit `in_scope` flag relative to the requested owner set;
    * inventory AND detail claims are reconciled with the raw open + suppressed
      counts until the raw `null`/missing arrays are explicit incomplete evidence;
    * find more than the record budget is explicit incomplete evidence;
    * `max_text_bytes` bounds one string, while a distinct aggregate
      `max_total_bytes` bounds the sum of all owner/inventory/detail/raw metadata
      accumulated into the report, enforced as records accumulate;
    * measurements are not historical snapshots: no `first_seen`, no lifecycle,
      and no historical provenance is synthesized;
    * conflicts between duplicate identities are failures, never a silent pick;
    * malformed/null/missing identities never imply completeness;
    * whole recursive records are text/depth bounded before they accumulate, and
      the record budget bounds both images and findings;
    * raw metadata is retained only in bounded form.
  """

  alias Triage.Collection.{Preview, Report}

  @metadata_key_limit 64

  @shape_fields [
    :severity,
    :base_severity,
    :source,
    :package_type,
    :purl,
    :package_cpe,
    :fix,
    :url,
    :description,
    :attributed_on,
    :suppressed,
    :metadata
  ]

  @doc "Builds a `%Report{}` from crawl context."
  def build(ctx) do
    config = ctx.config

    base = %Report{
      scope: ctx.scope,
      environment: config.environment,
      engine: config.engine,
      status_marker: ctx.status_marker,
      owners: ctx.owners,
      images: [],
      findings: [],
      suppressed: [],
      warnings: ctx.warnings,
      failures: ctx.failures,
      requests: ctx.requests,
      duration_ms: ctx.duration_ms,
      raw: %{},
      blockers: [],
      historical_provenance: nil,
      incomplete: false
    }

    entries = ctx.inventory |> Map.values() |> Enum.sort_by(& &1.digest)

    {report, _remaining, _used} =
      entries
      |> Enum.reduce({base, config.max_records, 0}, fn entry, {report, remaining, used} ->
        if remaining <= 0 do
          {fail(
             report,
             "record budget (#{config.max_records}) exceeded; remaining records not normalized"
           ), remaining, used}
        else
          normalize_image(
            report,
            config,
            ctx,
            entry,
            Map.get(ctx.details, entry.digest),
            remaining - 1,
            used
          )
        end
      end)

    # Accumulate in reverse throughout; restore the public order once, before
    # deriving blockers from the completed report.
    report = %{
      report
      | images: Enum.reverse(report.images),
        findings: Enum.reverse(report.findings),
        suppressed: Enum.reverse(report.suppressed),
        warnings: Enum.reverse(report.warnings),
        failures: Enum.reverse(report.failures)
    }

    %{report | blockers: Preview.blockers(report)}
  end

  defp normalize_image(report, config, ctx, entry, detail, remaining, used) do
    requested = ctx.requested_owners || []
    owners = entry.owners |> MapSet.to_list() |> Enum.sort()
    api_ids = entry.api_ids |> MapSet.to_list() |> Enum.sort()

    placements =
      entry.placements
      |> MapSet.to_list()
      |> Enum.map(fn placement ->
        Map.merge(placement, %{
          environment: config.environment,
          in_scope: requested == [] or placement.owner in requested
        })
      end)
      |> Enum.sort_by(&{&1.owner, &1.namespace})

    out_of_scope = Enum.reject(placements, & &1.in_scope)

    report =
      if out_of_scope != [] do
        owners_out = out_of_scope |> Enum.map(& &1.owner) |> Enum.uniq() |> Enum.sort()

        fail(
          report,
          "#{entry.digest}: placement owner(s) #{Enum.join(owners_out, ", ")} outside requested owner scope; scope not silently expanded"
        )
      else
        report
      end

    image = if is_map(entry.image), do: entry.image, else: %{}

    {report, repository} =
      bounded_field(
        report,
        entry.digest,
        "repository",
        image["repository"],
        config.max_text_bytes
      )

    {report, tag} =
      bounded_field(report, entry.digest, "tag", image["tag"], config.max_text_bytes)

    {report, description} =
      bounded_field(
        report,
        entry.digest,
        "description",
        image["description"],
        config.max_text_bytes
      )

    {report, usage} =
      bounded_field(report, entry.digest, "usage", image["usage"], config.max_text_bytes)

    {report, sbom_tool} =
      bounded_field(
        report,
        entry.digest,
        "softwareBillOfMaterialCreatedBy",
        image["softwareBillOfMaterialCreatedBy"],
        config.max_text_bytes
      )

    {report, status} =
      case image["metrics"] do
        metrics when is_map(metrics) ->
          bounded_field(
            report,
            entry.digest,
            "metrics.status",
            metrics["status"],
            config.max_text_bytes
          )

        nil ->
          {report, nil}

        _other ->
          {fail(report, "#{entry.digest}: malformed image metrics; completeness not implied"),
           nil}
      end

    normalized = %{
      digest: entry.digest,
      api_ids: api_ids,
      owners: owners,
      placements: placements,
      repository: repository,
      tag: tag,
      description: description,
      usage: usage,
      sbom_tool: sbom_tool,
      status: status
    }

    raw_image = %{
      "owners" => owners,
      "placements" => placements,
      "api_ids" => api_ids,
      "repository" => repository,
      "tag" => tag,
      "description" => description,
      "usage" => usage,
      "sbom_tool" => sbom_tool,
      "status" => status
    }

    report = %{
      report
      | images: [normalized | report.images],
        raw: Map.put(report.raw, entry.digest, raw_image)
    }

    {report, used} =
      charge_total(report, config, used + measure_bytes(normalized) + measure_bytes(raw_image))

    if is_map(detail) do
      reconcile(report, config, entry, detail, remaining, used)
    else
      {fail(report, "#{entry.digest}: detail missing; completeness not implied"), remaining, used}
    end
  end

  defp reconcile(report, config, entry, detail, remaining, used) do
    open_raw = detail["vulnerabilities"]
    excluded_raw = detail["excludedVulnerabilities"]

    report = validate_arrays(report, entry.digest, open_raw, excluded_raw)

    open_list = if is_list(open_raw), do: open_raw, else: []
    excluded_list = if is_list(excluded_raw), do: excluded_raw, else: []

    report = reconcile_claims(report, entry, detail, length(open_list), length(excluded_list))

    {open_entries, report, remaining} =
      classify(report, config, entry.digest, open_list, false, remaining)

    {sup_entries, report, remaining} =
      classify(report, config, entry.digest, excluded_list, true, remaining)

    {kept, duplicates, conflicts} = dedupe(open_entries ++ sup_entries)

    report =
      if conflicts == [] do
        report
      else
        Enum.reduce(conflicts, report, fn group, acc ->
          fail(acc, conflict_message(entry, group))
        end)
      end

    report =
      if duplicates > 0,
        do: warn(report, "#{entry.digest}: #{duplicates} duplicate finding(s) collapsed"),
        else: report

    new_findings = Enum.reject(kept, & &1.suppressed)
    new_suppressed = Enum.filter(kept, & &1.suppressed)

    # Retain the bounded raw metadata for every finding that survived, so the
    # normalization does not silently discard unrecognized upstream fields.
    raw_findings =
      Enum.map(kept, fn finding ->
        %{
          "cve" => finding.cve,
          "package_name" => finding.package_name,
          "package_version" => finding.package_version,
          "suppressed" => finding.suppressed,
          "metadata" => finding.metadata
        }
      end)

    report = %{
      report
      | findings: Enum.reverse(new_findings, report.findings),
        suppressed: Enum.reverse(new_suppressed, report.suppressed),
        raw: Map.update!(report.raw, entry.digest, &Map.put(&1, "findings", raw_findings))
    }

    {report, used} =
      charge_total(
        report,
        config,
        used +
          measure_bytes(new_findings) + measure_bytes(new_suppressed) +
          measure_bytes(raw_findings)
      )

    {report, remaining, used}
  end

  defp validate_arrays(report, digest, open_raw, excluded_raw) do
    report =
      if is_list(open_raw) do
        report
      else
        fail(
          report,
          "#{digest}: vulnerabilities array was missing or null; completeness not implied"
        )
      end

    if is_list(excluded_raw) do
      report
    else
      fail(
        report,
        "#{digest}: excludedVulnerabilities array was missing or null; completeness not implied"
      )
    end
  end

  defp reconcile_claims(report, entry, detail, open_n, excluded_n) do
    inv = metrics_int(entry.image["metrics"], "vulnerabilities")
    det = metrics_int(detail_metrics(detail), "vulnerabilities")
    inv_sup = metrics_int(entry.image["metrics"], "vulnerabilitiesSuppressed")
    det_sup = metrics_int(detail_metrics(detail), "vulnerabilitiesSuppressed")

    report =
      if Enum.any?([inv, det, inv_sup, det_sup], &(&1 == :malformed)) do
        fail(report, "#{entry.digest}: malformed metrics; completeness not implied")
      else
        report
      end

    claimed =
      case {det, inv} do
        {d, _} when is_integer(d) -> d
        {_, i} when is_integer(i) -> i
        _ -> nil
      end

    raw_total = open_n + excluded_n

    report =
      if is_integer(inv) and is_integer(det) and inv != det do
        fail(
          report,
          "#{entry.digest}: contradictory claimed counts (inventory #{inv}, detail #{det}); completeness not implied"
        )
      else
        report
      end

    report =
      if claimed == nil do
        fail(
          report,
          "#{entry.digest}: no claimed vulnerability count; completeness cannot be established"
        )
      else
        report
      end

    report =
      cond do
        is_integer(claimed) and claimed > 0 and raw_total == 0 ->
          fail(
            report,
            "#{entry.digest}: metrics claim #{claimed} vulnerabilities but engine \"#{report.engine}\" returned none"
          )

        is_integer(claimed) and raw_total != claimed ->
          fail(
            report,
            "#{entry.digest}: incomplete — claimed #{claimed}, received #{raw_total} (#{open_n} open + #{excluded_n} suppressed, drift #{raw_total - claimed})"
          )

        true ->
          report
      end

    cond do
      is_integer(det_sup) and det_sup != excluded_n ->
        fail(
          report,
          "#{entry.digest}: suppressed claim #{det_sup} did not match #{excluded_n} returned"
        )

      is_integer(inv_sup) and inv_sup != excluded_n ->
        fail(
          report,
          "#{entry.digest}: inventory suppressed claim #{inv_sup} did not match #{excluded_n} returned"
        )

      true ->
        report
    end
  end

  defp detail_metrics(detail), do: if(is_map(detail), do: detail["metrics"], else: nil)

  defp metrics_int(nil, _key), do: nil

  defp metrics_int(metrics, key) when is_map(metrics) do
    case Map.get(metrics, key) do
      value when is_integer(value) and value >= 0 -> value
      nil -> nil
      _other -> :malformed
    end
  end

  defp metrics_int(_metrics, _key), do: :malformed

  defp classify(report, config, digest, list, suppressed?, remaining) do
    {keep, dropped} =
      if length(list) > remaining do
        Enum.split(list, remaining)
      else
        {list, []}
      end

    report =
      if dropped == [] do
        report
      else
        fail(
          report,
          "record budget (#{config.max_records}) exceeded; #{length(dropped)} additional finding(s) not normalized"
        )
      end

    remaining = remaining - length(keep)

    {entries, report} =
      Enum.reduce(keep, {[], report}, fn value, {entries, acc} ->
        classify_one(acc, config, digest, value, suppressed?, entries)
      end)

    {Enum.reverse(entries), report, remaining}
  end

  defp classify_one(report, config, digest, value, suppressed?, entries) do
    cond do
      not is_map(value) ->
        {entries,
         fail(report, "#{digest}: non-object vulnerability entry; completeness not implied")}

      depth_exceeds?(value, config.max_depth, 0) ->
        {entries, fail(report, "#{digest}: vulnerability metadata exceeded the depth budget")}

      record_oversize?(value, config.max_text_bytes) ->
        {entries, fail(report, "#{digest}: vulnerability text exceeded the byte budget")}

      map_size(value) > @metadata_key_limit ->
        {entries, fail(report, "#{digest}: vulnerability metadata exceeded the field budget")}

      true ->
        finding = normalize_finding(digest, value, suppressed?)

        if finding.identity_complete? do
          {[finding | entries], report}
        else
          {entries,
           fail(
             report,
             "#{digest}: finding with missing identity (cve/package/version); completeness not implied"
           )}
        end
    end
  end

  defp normalize_finding(digest, value, suppressed?) do
    cve = text(value["vuln"])
    package_name = text(value["packageName"])
    package_version = text(value["packageVersion"])

    %{
      digest: digest,
      cve: cve,
      package_name: package_name,
      package_version: package_version,
      severity: text(value["severity"]),
      base_severity: text(value["baseSeverity"]),
      source: text(value["source"]),
      package_type: text(value["packageType"]),
      purl: text(value["packagePath"]),
      package_cpe: text(value["packageCpe"]),
      fix: text(value["fix"]),
      url: text(value["url"]),
      description: text(value["description"]),
      attributed_on: text(value["attributedOn"]),
      metadata: value,
      suppressed: suppressed?,
      identity_complete?:
        not is_nil(cve) and not is_nil(package_name) and not is_nil(package_version)
    }
  end

  defp dedupe(entries) do
    {kept, duplicates, conflicts} =
      entries
      |> Enum.group_by(&{&1.cve, &1.package_name, &1.package_version})
      |> Enum.reduce({[], 0, []}, fn {_key, group}, {kept, dupes, conflicts} ->
        cond do
          length(group) == 1 ->
            {[hd(group) | kept], dupes, conflicts}

          distinct_shapes(group) == 1 ->
            {[hd(group) | kept], dupes + length(group) - 1, conflicts}

          true ->
            {kept, dupes, [group | conflicts]}
        end
      end)

    {Enum.reverse(kept), duplicates, Enum.reverse(conflicts)}
  end

  defp distinct_shapes(group) do
    group
    |> Enum.map(&Map.take(&1, @shape_fields))
    |> Enum.uniq()
    |> length()
  end

  defp conflict_message(entry, group) do
    sample = hd(group)

    "#{entry.digest}: conflicting duplicates for #{sample.cve}/#{sample.package_name}@#{sample.package_version}; fields are preserved as a conflict and never silently chosen"
  end

  defp bounded_field(report, digest, label, value, max) when is_binary(value) do
    if byte_size(value) > max do
      {fail(report, "#{digest}: #{label} exceeded the byte budget"), nil}
    else
      {report, text(value)}
    end
  end

  defp bounded_field(report, _digest, _label, value, _max), do: {report, text(value)}

  defp record_oversize?(value, max) when is_map(value) do
    Enum.any?(value, fn {_k, v} -> record_oversize?(v, max) end)
  end

  defp record_oversize?(value, max) when is_list(value) do
    Enum.any?(value, &record_oversize?(&1, max))
  end

  defp record_oversize?(value, max) when is_binary(value), do: byte_size(value) > max
  defp record_oversize?(_value, _max), do: false

  defp depth_exceeds?(value, max, level) when is_map(value) do
    level > max or Enum.any?(value, fn {_k, v} -> depth_exceeds?(v, max, level + 1) end)
  end

  defp depth_exceeds?(value, max, level) when is_list(value) do
    level > max or Enum.any?(value, &depth_exceeds?(&1, max, level + 1))
  end

  defp depth_exceeds?(_value, max, level), do: level > max

  # Aggregate byte budget, distinct from the per-string `max_text_bytes`. It is
  # charged as each record's normalized/raw metadata accumulates. Once exceeded
  # the report is marked incomplete with a single explicit failure.
  defp charge_total(report, config, used) do
    already? = Enum.any?(report.failures, &String.contains?(&1, "aggregate byte budget"))

    report =
      if used > config.max_total_bytes and not already? do
        fail(
          report,
          "aggregate byte budget (#{config.max_total_bytes}) exceeded; report is incomplete"
        )
      else
        report
      end

    {report, used}
  end

  defp measure_bytes(value) when is_binary(value), do: byte_size(value)

  defp measure_bytes(value) when is_list(value),
    do: Enum.reduce(value, 0, fn item, acc -> acc + measure_bytes(item) end)

  defp measure_bytes(value) when is_map(value),
    do: Enum.reduce(value, 0, fn {k, v}, acc -> acc + measure_bytes(k) + measure_bytes(v) end)

  defp measure_bytes(_value), do: 0

  defp text(value) when is_binary(value) do
    if value == "", do: nil, else: value
  end

  defp text(_value), do: nil

  defp fail(report, message) do
    %{report | failures: [message | report.failures], incomplete: true}
  end

  defp warn(report, message) do
    %{report | warnings: [message | report.warnings]}
  end
end
