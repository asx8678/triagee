defmodule Triage.Import do
  @moduledoc """
  Versioned snapshot import for approved historical inventory exports.

  This is deliberately two steps, and only the first one is exercised here:

    * `parse/1` is pure and strict. It decodes a JSON snapshot of the documented
      shape, rejects unknown keys, wrong formats/versions, malformed timestamps
      and unsafe text, enforces explicit document/record/string budgets, and
      reports every problem with a JSON path instead of stopping at the first
      one. Nothing is read from or written to the database.
    * `dry_run/1` performs a read-only reconciliation: it reports, per image,
      placement, finding and event, whether the record is `:create`, `:update`
      or `:unchanged` relative to the current local inventory. It never writes.

  Identity follows the same rules as the rest of the application, so a reimport
  is idempotent by construction: images by content digest, placements by
  `(namespace, owner, environment)` on an image, findings by
  `(cve, package_name, package_version)` on an image, and events by
  `(event, occurred_at)` on a finding. Reimporting the same snapshot therefore
  produces only `:unchanged`/`:existing` results and duplicate records are
  rejected at parse time rather than silently collapsed.

  Deliberate omissions:

    * Absent `resolved_at` stays absent. Resolution is never inferred from a
      missing field, a disappeared package or an incomplete snapshot. The same
      rule governs writes: a snapshot that does not state `resolved_at`,
      `suppressed` or `active` preserves the recorded local value instead of
      clearing it. The preservation warning is produced by the same shared
      reconciliation for both `dry_run/1` and `apply/1`, with the real indexed
      snapshot path (`$.images[i].findings[j].resolved_at`).
    * Nothing here contacts the legacy collector, a security API, or any network.
    * Events are recorded as given. This module does not invent lifecycle
      history for findings that appear without events.

  ## Write boundary and concurrency

  Every public write entry point (`apply/1`, `import_snapshot/1` and the
  composable `write!/1`) re-validates a normalized snapshot before touching the
  database: a mutable map that mutates a parsed snapshot cannot bypass the
  parser's format, enum, text or identity checks. `write!/1` also refuses to run
  outside a `Repo.transaction/1`.

  Every writer acquires a transaction-scoped PostgreSQL advisory lock
  (`pg_advisory_xact_lock/1`) *before* it re-reads the local inventory, so two
  concurrent imports of overlapping identities serialize and the second one
  re-reads the first one's committed rows instead of racing them. This is what
  makes concurrent imports converge on `:existing`/`:unchanged` rather than
  duplicate lifecycle rows or fail a unique constraint.

  ## Stale-import policy (conservative)

  Imported `generated_at` is parsed but is **not** treated as authoritative
  source ordering: no source history is persisted, so there is no stored
  baseline to compare it against. Instead, the writer rejects a snapshot that
  *provably* regresses a recorded observation time before writing anything:
  a `last_seen` earlier than the stored local value, or a `first_seen` later
  than the stored local value, for any matched placement or finding. The error
  carries the exact indexed JSON path.

  For equal or unproven ordering, the incoming snapshot's metadata is treated
  as authoritative and overwrites the local metadata (same-time overwrite
  policy). The remaining provenance limit — arrival order is not persisted and
  cannot be reconstructed later — is documented here rather than invented.

  ## Explicit budgets

  The parser rejects input before doing unbounded work:

    * document JSON: at most #{5_000_000} bytes;
    * at most #{1_000} images, #{500} placements per image, #{500} findings per
      image and #{200} events per finding;
    * at most #{10_000} total records across the whole snapshot;
    * a single text field: at most #{1024} graphemes and #{4096} bytes;
    * imported placement `owner`/`environment` must satisfy the same contract as
      the UI scope filter (at most #{120} characters / #{480} bytes), so an
      imported owner can never be offered by a feed that would then reject it.

  Collection parsing is linear (prepend then reverse); it never appends to the
  tail of an accumulator.

  `dry_run/1` uses a fixed number of SELECTs (four), independent of how many
  images, placements, findings or events the snapshot contains.
  """

  import Ecto.Query

  alias Triage.Repo
  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}

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

  @doc "Maximum accepted snapshot document size in bytes."
  def max_document_bytes, do: @max_document_bytes

  @doc """
  Parses and validates a snapshot JSON document.

  Returns `{:ok, snapshot}` where every timestamp is a `DateTime` truncated to
  seconds, or `{:error, errors}` with a list of `%{path: String.t(), message:
  String.t()}` covering every detected problem.
  """
  def parse(json) when is_binary(json) do
    if byte_size(json) > @max_document_bytes do
      {:error,
       [problem("$", "snapshot is #{byte_size(json)} bytes; the limit is #{@max_document_bytes}")]}
    else
      case Jason.decode(json) do
        {:ok, raw} when is_map(raw) -> normalize(raw)
        {:ok, _other} -> {:error, [problem("$", "snapshot must be a JSON object")]}
        {:error, error} -> {:error, [problem("$", "invalid JSON: #{Exception.message(error)}")]}
      end
    end
  end

  def parse(_other), do: {:error, [problem("$", "snapshot must be a JSON string")]}

  @doc """
  Re-validates an already-normalized snapshot and returns the canonical form.

  `apply/1`, `dry_run/1` and `write!/1` all funnel through this function, so a
  mutated public map cannot bypass the parser's format, enum, text, identity or
  budget checks. Pure; performs no database work.
  """
  def validate(snapshot) do
    with {:ok, _budget} <- preflight(snapshot, :root, "$", {0, 0}) do
      normalize(snapshot_to_raw(snapshot))
    end
  end

  # Validate the normalized atom-keyed shape BEFORE rebuilding it. Never drop
  # unknown keys, silently prefer atom/string aliases, or traverse an oversized
  # collection before enforcing its budget. JSON callers use parse/1 instead.
  defp preflight(record, kind, path, {count, bytes}) when is_map(record) do
    {keys, children} = shape(kind)

    cond do
      is_struct(record) or map_size(record) > length(keys) ->
        {:error, [problem(path, "expected a plain normalized map with only known atom keys")]}

      Enum.any?(Map.keys(record), &(not is_atom(&1) or Atom.to_string(&1) not in keys)) ->
        {:error, [problem(path, "unknown key; expected only normalized atom keys")]}

      true ->
        count = count + if(kind == :root, do: 0, else: 1)

        bytes =
          Enum.reduce(record, bytes, fn
            {_key, value}, acc when is_binary(value) -> acc + byte_size(value)
            _, acc -> acc
          end)

        if count > @max_total_records or bytes > @max_document_bytes do
          {:error, [problem(path, "normalized snapshot exceeds record or byte limit")]}
        else
          Enum.reduce_while(children, {:ok, {count, bytes}}, fn {key, child, max},
                                                                {:ok, budget} ->
            case preflight_list(Map.get(record, key), child, "#{path}.#{key}", max, budget) do
              {:ok, budget} -> {:cont, {:ok, budget}}
              error -> {:halt, error}
            end
          end)
        end
    end
  end

  defp preflight(_record, _kind, path, _budget),
    do: {:error, [problem(path, "expected a plain normalized map")]}

  defp preflight_list(list, kind, path, max, budget) when is_list(list) do
    # take(max + 1) bounds the count traversal as well as subsequent conversion.
    if length(Enum.take(list, max + 1)) > max do
      {:error, [problem(path, "records exceed the limit of #{max}")]}
    else
      list
      |> Enum.with_index()
      |> Enum.reduce_while({:ok, budget}, fn {record, index}, {:ok, budget} ->
        case preflight(record, kind, "#{path}[#{index}]", budget) do
          {:ok, budget} -> {:cont, {:ok, budget}}
          error -> {:halt, error}
        end
      end)
    end
  end

  # The normalizer reports the field-specific missing/non-list error.
  defp preflight_list(_other, _kind, _path, _max, budget), do: {:ok, budget}

  defp shape(:root), do: {@image_root_keys, [{:images, :image, @max_images}]}

  defp shape(:image),
    do:
      {@image_keys,
       [
         {:placements, :placement, @max_placements_per_image},
         {:findings, :finding, @max_findings_per_image}
       ]}

  defp shape(:placement), do: {@placement_keys, []}
  defp shape(:finding), do: {@finding_keys, [{:events, :event, @max_events_per_finding}]}
  defp shape(:event), do: {@event_keys, []}

  @doc """
  Read-only reconciliation of a parsed snapshot against the local inventory.

  Returns `{:ok, report}` with `:summary` counts, `:images` detail and
  `:warnings`. No rows are written and no schema is changed.
  """
  def dry_run(snapshot) do
    with {:ok, validated} <- validate(snapshot) do
      digests = Enum.map(validated.images, & &1.digest)
      images = load_images(digests)
      image_ids = existing_image_ids(images)
      placements = load_placements(image_ids)
      findings = load_findings(image_ids)
      events = load_events(findings)

      case regression_errors(validated, images, placements, findings) do
        [] ->
          rows = reconcile(validated, images, placements, findings, events)
          warnings = resolution_warnings(validated, images, findings)
          {:ok, %{summary: summarize(rows), images: rows, warnings: warnings}}

        errors ->
          {:error, errors}
      end
    end
  end

  @doc """
  Parses and applies a snapshot JSON document.

  Returns `{:ok, report}` from `apply/1`, or `{:error, errors}` from `parse/1`
  without writing anything.
  """
  def import_snapshot(json) do
    with {:ok, snapshot} <- parse(json) do
      apply(snapshot)
    end
  end

  @doc """
  Applies a parsed snapshot inside one database transaction.

  All-or-nothing: any failure rolls the entire import back and returns
  `{:error, errors}` with the local inventory exactly as it was. A snapshot that
  provably regresses a recorded observation time is rejected before any write,
  with the exact indexed JSON path. Reimporting the same snapshot only rewrites
  rows whose metadata actually differs, so a second run reports
  `:unchanged`/`:existing` and leaves review cases, evidence snapshots, reviews
  and case events alone - this module never updates or deletes them.

  The `report` has the same shape as `dry_run/1`: `:summary` counts
  (`:create`, `:update`, `:unchanged`; events also `:existing`), per-image
  `:images` detail and `:warnings`.
  """
  def apply(snapshot) do
    with {:ok, validated} <- validate(snapshot) do
      case Repo.transaction(fn -> do_write!(validated) end) do
        {:ok, report} ->
          {:ok, report}

        {:error, {:import_rejected, errors}} ->
          {:error, errors}

        {:error, reason} ->
          {:error, [problem("$", "import failed and was rolled back: #{inspect(reason)}")]}
      end
    end
  rescue
    error ->
      {:error, [problem("$", "import failed and was rolled back: #{Exception.message(error)}")]}
  end

  @doc """
  Writes a parsed snapshot's rows and returns the same report shape as
  `apply/1`.

  Public so a caller can compose it inside its own `Repo.transaction/1`, which
  is how the atomicity guarantee is tested. It **refuses** to run outside a
  transaction (raising `ArgumentError`) before any query or write, re-validates
  the snapshot, and acquires the transaction-scoped import advisory lock before
  re-reading the local inventory.
  """
  def write!(snapshot) do
    unless Repo.in_transaction?() do
      raise ArgumentError,
            "Triage.Import.write!/1 must be called inside Repo.transaction/1; " <>
              "use apply/1 or import_snapshot/1 for the guarded write path"
    end

    case validate(snapshot) do
      {:ok, validated} ->
        do_write!(validated)

      {:error, errors} ->
        raise ArgumentError, "invalid snapshot: " <> format_errors(errors)
    end
  end

  ## Write path (always inside the caller's transaction, lock held first)

  defp do_write!(snapshot) do
    lock_import!()

    digests = Enum.map(snapshot.images, & &1.digest)
    existing_images = load_images(digests)
    image_ids = existing_image_ids(existing_images)
    existing_placements = load_placements(image_ids)
    existing_findings = load_findings(image_ids)
    existing_events = load_events(existing_findings)

    case regression_errors(snapshot, existing_images, existing_placements, existing_findings) do
      [] ->
        :ok

      errors ->
        Repo.rollback({:import_rejected, errors})
    end

    warnings = resolution_warnings(snapshot, existing_images, existing_findings)

    rows =
      Enum.map(snapshot.images, fn image ->
        {record, action} = write_image(image, Map.get(existing_images, image.digest))

        placements = write_placements(image.placements, record.id, existing_placements)
        findings = write_findings(image.findings, record.id, existing_findings, existing_events)

        %{
          digest: image.digest,
          image_id: record.id,
          action: action,
          placements: placements,
          findings: findings
        }
      end)

    %{
      summary: summarize(rows),
      images: rows,
      warnings: warnings
    }
  end

  defp lock_import! do
    Repo.query!("SELECT pg_advisory_xact_lock($1)", [@import_lock_key])
  end

  defp write_image(image, nil) do
    record =
      %Image{}
      |> Image.changeset(%{
        digest: image.digest,
        repository: image.repository,
        tag: image.tag,
        description: image.description
      })
      |> Repo.insert!()

    {record, :create}
  end

  defp write_image(image, existing) do
    if image_action(existing, image) == :unchanged do
      {existing, :unchanged}
    else
      record =
        existing
        |> Image.changeset(%{
          repository: image.repository,
          tag: image.tag,
          description: image.description
        })
        |> Repo.update!()

      {record, :update}
    end
  end

  defp write_placements(placements, image_id, existing_map) do
    Enum.map(placements, fn placement ->
      key = {image_id, placement.namespace, placement.owner, placement.environment}

      action =
        case Map.get(existing_map, key) do
          nil ->
            %ImagePlacement{}
            |> ImagePlacement.changeset(%{
              image_id: image_id,
              namespace: placement.namespace,
              owner: placement.owner,
              environment: placement.environment,
              active: if(is_nil(placement.active), do: true, else: placement.active),
              first_seen: placement.first_seen,
              last_seen: placement.last_seen
            })
            |> Repo.insert!()

            :create

          existing ->
            if placement_changed?(existing, placement) do
              existing |> ImagePlacement.changeset(placement_attrs(placement)) |> Repo.update!()
              :update
            else
              :unchanged
            end
        end

      %{key: {placement.namespace, placement.owner, placement.environment}, action: action}
    end)
  end

  defp placement_attrs(placement) do
    attrs = %{first_seen: placement.first_seen, last_seen: placement.last_seen}

    if is_nil(placement.active), do: attrs, else: Map.put(attrs, :active, placement.active)
  end

  defp write_findings(findings, image_id, existing_map, existing_events) do
    Enum.map(findings, fn finding ->
      key = {image_id, finding.cve, finding.package_name, finding.package_version}
      existing = Map.get(existing_map, key)

      {record, action} =
        case existing do
          nil ->
            record =
              %Finding{}
              |> Finding.changeset(%{
                image_id: image_id,
                cve: finding.cve,
                package_name: finding.package_name,
                package_version: finding.package_version,
                severity: finding.severity,
                fix: finding.fix,
                url: finding.url,
                description: finding.description,
                suppressed: if(is_nil(finding.suppressed), do: false, else: finding.suppressed),
                first_seen: finding.first_seen,
                last_seen: finding.last_seen,
                resolved_at: finding.resolved_at
              })
              |> Repo.insert!()

            {record, :create}

          existing ->
            if finding_changed?(existing, finding) do
              {existing |> Finding.changeset(finding_attrs(finding)) |> Repo.update!(), :update}
            else
              {existing, :unchanged}
            end
        end

      known = Map.get(existing_events, record.id, MapSet.new())
      events = write_events(finding.events, record.id, known)

      %{
        key: {finding.cve, finding.package_name, finding.package_version},
        action: action,
        events: events
      }
    end)
  end

  # Update attrs never include `reopen_count` (local counter) and only include
  # `suppressed`/`resolved_at` when the snapshot actually states them.
  defp finding_attrs(finding) do
    attrs = %{
      severity: finding.severity,
      fix: finding.fix,
      url: finding.url,
      description: finding.description,
      first_seen: finding.first_seen,
      last_seen: finding.last_seen
    }

    attrs =
      if is_nil(finding.suppressed),
        do: attrs,
        else: Map.put(attrs, :suppressed, finding.suppressed)

    if is_nil(finding.resolved_at),
      do: attrs,
      else: Map.put(attrs, :resolved_at, finding.resolved_at)
  end

  defp write_events(events, finding_id, known) do
    Enum.map(events, fn event ->
      action =
        if MapSet.member?(known, {event.event, event.occurred_at}) do
          :existing
        else
          %FindingEvent{}
          |> FindingEvent.changeset(%{
            finding_id: finding_id,
            event: event.event,
            occurred_at: event.occurred_at,
            note: event.note
          })
          |> Repo.insert!()

          :create
        end

      %{key: {event.event, event.occurred_at}, action: action}
    end)
  end

  ## Stale-observation rejection (before any write)

  defp regression_errors(snapshot, images, placements, findings) do
    snapshot.images
    |> Enum.with_index()
    |> Enum.reduce([], fn {image, image_index}, errors ->
      case Map.get(images, image.digest) do
        nil ->
          errors

        existing_image ->
          errors
          |> placement_regressions(image, image_index, existing_image, placements)
          |> finding_regressions(image, image_index, existing_image, findings)
      end
    end)
    |> Enum.reverse()
  end

  defp placement_regressions(errors, image, image_index, existing_image, placements) do
    image.placements
    |> Enum.with_index()
    |> Enum.reduce(errors, fn {placement, index}, errors ->
      key = {existing_image.id, placement.namespace, placement.owner, placement.environment}
      path = "$.images[#{image_index}].placements[#{index}]"

      case Map.get(placements, key) do
        nil -> errors
        existing -> observation_regressions(errors, existing, placement, path)
      end
    end)
  end

  defp finding_regressions(errors, image, image_index, existing_image, findings) do
    image.findings
    |> Enum.with_index()
    |> Enum.reduce(errors, fn {finding, index}, errors ->
      key = {existing_image.id, finding.cve, finding.package_name, finding.package_version}
      path = "$.images[#{image_index}].findings[#{index}]"

      case Map.get(findings, key) do
        nil -> errors
        existing -> observation_regressions(errors, existing, finding, path)
      end
    end)
  end

  defp observation_regressions(errors, existing, incoming, path) do
    errors
    |> maybe_regression(
      earlier?(incoming.last_seen, existing.last_seen),
      "#{path}.last_seen",
      "incoming last_seen #{fmt(incoming.last_seen)} is older than the recorded local value " <>
        "#{fmt(existing.last_seen)}; refusing to regress a recorded observation time"
    )
    |> maybe_regression(
      later?(incoming.first_seen, existing.first_seen),
      "#{path}.first_seen",
      "incoming first_seen #{fmt(incoming.first_seen)} is later than the recorded local value " <>
        "#{fmt(existing.first_seen)}; refusing to regress a recorded observation time"
    )
  end

  defp maybe_regression(errors, true, path, message), do: errors ++ [problem(path, message)]
  defp maybe_regression(errors, false, _path, _message), do: errors

  defp earlier?(nil, _existing), do: false
  defp earlier?(_incoming, nil), do: false

  defp earlier?(incoming, existing),
    do: DateTime.compare(truncate(incoming), truncate(existing)) == :lt

  defp later?(nil, _existing), do: false
  defp later?(_incoming, nil), do: false

  defp later?(incoming, existing),
    do: DateTime.compare(truncate(incoming), truncate(existing)) == :gt

  defp truncate(%DateTime{} = datetime), do: DateTime.truncate(datetime, :second)
  defp truncate(other), do: other

  defp fmt(%DateTime{} = datetime), do: DateTime.to_iso8601(datetime)
  defp fmt(other), do: inspect(other)

  # Shared by `dry_run/1` and `write!/1` so the preview and the commit disclose
  # the same preservation decision, with the real indexed snapshot path.
  defp resolution_warnings(snapshot, images, findings) do
    snapshot.images
    |> Enum.with_index()
    |> Enum.reduce([], fn {image, image_index}, warnings ->
      case Map.get(images, image.digest) do
        nil ->
          warnings

        existing_image ->
          image.findings
          |> Enum.with_index()
          |> Enum.reduce(warnings, fn {finding, finding_index}, warnings ->
            key = {existing_image.id, finding.cve, finding.package_name, finding.package_version}

            case Map.get(findings, key) do
              %Finding{resolved_at: resolved} when not is_nil(resolved) ->
                if is_nil(finding.resolved_at) do
                  [
                    problem(
                      "$.images[#{image_index}].findings[#{finding_index}].resolved_at",
                      "snapshot does not state resolution; the recorded local resolved_at is preserved"
                    )
                    | warnings
                  ]
                else
                  warnings
                end

              _ ->
                warnings
            end
          end)
      end
    end)
    |> Enum.reverse()
  end

  ## Parsing and normalization

  defp normalize(raw) do
    errors =
      []
      |> check_unknown_keys(raw, @image_root_keys, "$")
      |> check_format(raw)
      |> check_version(raw)

    {source, source_errors} = optional_text(raw, "source", "$")
    {generated_at, generated_errors} = optional_time(raw, "generated_at", "$")
    {images, image_errors} = normalize_images(raw)

    errors = errors ++ source_errors ++ generated_errors ++ image_errors

    if errors == [] do
      {:ok,
       %{
         format: @format,
         version: @version,
         source: source,
         generated_at: generated_at,
         images: images
       }}
    else
      {:error, errors}
    end
  end

  # Rebuild the string-keyed raw shape so the same strict parser can validate a
  # mutable normalized map at every public write boundary. Non-map values pass
  # through unchanged so the parser reports "expected an object" for them.
  defp snapshot_to_raw(snapshot) do
    if is_map(snapshot) do
      %{
        "format" => Map.get(snapshot, :format),
        "version" => Map.get(snapshot, :version),
        "source" => Map.get(snapshot, :source),
        "generated_at" => time_to_raw(Map.get(snapshot, :generated_at)),
        "images" => list_to_raw(Map.get(snapshot, :images), &image_to_raw/1)
      }
    else
      snapshot
    end
  end

  defp image_to_raw(%{} = image) do
    %{
      "digest" => Map.get(image, :digest),
      "repository" => Map.get(image, :repository),
      "tag" => Map.get(image, :tag),
      "description" => Map.get(image, :description),
      "placements" => list_to_raw(Map.get(image, :placements), &placement_to_raw/1),
      "findings" => list_to_raw(Map.get(image, :findings), &finding_to_raw/1)
    }
  end

  defp image_to_raw(other), do: other

  defp placement_to_raw(%{} = placement) do
    %{
      "namespace" => Map.get(placement, :namespace),
      "owner" => Map.get(placement, :owner),
      "environment" => Map.get(placement, :environment),
      "active" => Map.get(placement, :active),
      "first_seen" => time_to_raw(Map.get(placement, :first_seen)),
      "last_seen" => time_to_raw(Map.get(placement, :last_seen))
    }
  end

  defp placement_to_raw(other), do: other

  defp finding_to_raw(%{} = finding) do
    %{
      "cve" => Map.get(finding, :cve),
      "package_name" => Map.get(finding, :package_name),
      "package_version" => Map.get(finding, :package_version),
      "severity" => Map.get(finding, :severity),
      "fix" => Map.get(finding, :fix),
      "url" => Map.get(finding, :url),
      "description" => Map.get(finding, :description),
      "suppressed" => Map.get(finding, :suppressed),
      "first_seen" => time_to_raw(Map.get(finding, :first_seen)),
      "last_seen" => time_to_raw(Map.get(finding, :last_seen)),
      "resolved_at" => time_to_raw(Map.get(finding, :resolved_at)),
      "events" => list_to_raw(Map.get(finding, :events), &event_to_raw/1)
    }
  end

  defp finding_to_raw(other), do: other

  defp event_to_raw(%{} = event) do
    %{
      "event" => Map.get(event, :event),
      "occurred_at" => time_to_raw(Map.get(event, :occurred_at)),
      "note" => Map.get(event, :note)
    }
  end

  defp event_to_raw(other), do: other

  defp list_to_raw(list, fun) when is_list(list), do: Enum.map(list, fun)
  defp list_to_raw(other, _fun), do: other

  defp time_to_raw(%DateTime{calendar: Calendar.ISO} = datetime) do
    DateTime.to_iso8601(datetime)
  rescue
    _ -> :invalid_timestamp
  end

  defp time_to_raw(%DateTime{}), do: :invalid_timestamp
  defp time_to_raw(other), do: other

  defp check_unknown_keys(errors, raw, allowed, path) do
    raw
    |> Map.keys()
    |> Enum.reject(&(&1 in allowed))
    |> Enum.sort()
    |> Enum.reduce(errors, fn key, acc ->
      acc ++ [problem(path, "unknown key #{inspect(key)}")]
    end)
  end

  defp check_format(errors, raw) do
    case Map.get(raw, "format") do
      @format ->
        errors

      other ->
        errors ++ [problem("$.format", "expected #{inspect(@format)}, got #{inspect(other)}")]
    end
  end

  defp check_version(errors, raw) do
    case Map.get(raw, "version") do
      @version -> errors
      other -> errors ++ [problem("$.version", "unsupported version #{inspect(other)}")]
    end
  end

  defp normalize_images(raw) do
    case Map.get(raw, "images") do
      images when is_list(images) ->
        case budget_errors(raw) do
          [] ->
            {parsed, errors} =
              collect(images, fn index -> "$.images[#{index}]" end, &normalize_image/2)

            {parsed, errors ++ duplicate_errors(parsed)}

          budget ->
            {[], budget}
        end

      other ->
        {[], [problem("$.images", "expected a list, got #{inspect(other)}")]}
    end
  end

  # Linear, bounded collection helper: prepend then reverse, never append.
  defp collect(list, path_fun, parse_fun) do
    {parsed_rev, errors_rev} =
      list
      |> Enum.with_index()
      |> Enum.reduce({[], []}, fn {item, index}, {parsed, errors} ->
        {value, errs} = parse_fun.(item, path_fun.(index))
        {[value | parsed], Enum.reverse(errs, errors)}
      end)

    {Enum.reverse(parsed_rev), Enum.reverse(errors_rev)}
  end

  defp budget_errors(raw) do
    case Map.get(raw, "images") do
      images when is_list(images) ->
        errors = check_count([], "$.images", length(images), @max_images)

        {errors, placements, findings, events} =
          Enum.reduce(images, {errors, 0, 0, 0}, fn image, {errors, pc, fc, ec} ->
            {image_placements, image_findings} =
              if is_map(image) do
                {Map.get(image, "placements"), Map.get(image, "findings")}
              else
                {nil, nil}
              end

            {placement_count, errors} =
              if is_list(image_placements) do
                n = length(image_placements)
                {n, check_count(errors, "$.images[*].placements", n, @max_placements_per_image)}
              else
                {0, errors}
              end

            {finding_count, errors} =
              if is_list(image_findings) do
                n = length(image_findings)
                {n, check_count(errors, "$.images[*].findings", n, @max_findings_per_image)}
              else
                {0, errors}
              end

            {event_count, errors} =
              image_findings
              |> List.wrap()
              |> Enum.reduce({0, errors}, fn finding, {count, errors} ->
                n =
                  if is_map(finding) do
                    case Map.get(finding, "events") do
                      events when is_list(events) -> length(events)
                      _ -> 0
                    end
                  else
                    0
                  end

                {count + n,
                 check_count(errors, "$.images[*].findings[*].events", n, @max_events_per_finding)}
              end)

            {errors, pc + placement_count, fc + finding_count, ec + event_count}
          end)

        total = length(images) + placements + findings + events
        check_count(errors, "$", total, @max_total_records)

      _ ->
        []
    end
  end

  defp check_count(errors, path, count, max) do
    if count > max do
      errors ++ [problem(path, "#{count} records exceed the limit of #{max}")]
    else
      errors
    end
  end

  defp normalize_image(raw, path) when is_map(raw) do
    errors = check_unknown_keys([], raw, @image_keys, path)
    {digest, digest_errors} = required_text(raw, "digest", path)
    {repository, repository_errors} = optional_text(raw, "repository", path)
    {tag, tag_errors} = optional_text(raw, "tag", path)
    {description, description_errors} = optional_text(raw, "description", path)
    {placements, placement_errors} = normalize_placements(raw, path)
    {findings, finding_errors} = normalize_findings(raw, path)

    image = %{
      digest: digest,
      repository: repository,
      tag: tag,
      description: description,
      placements: placements,
      findings: findings
    }

    {image,
     errors ++
       digest_errors ++
       repository_errors ++
       tag_errors ++
       description_errors ++
       placement_errors ++
       finding_errors}
  end

  defp normalize_image(_raw, path),
    do:
      {%{digest: nil, repository: nil, tag: nil, description: nil, placements: [], findings: []},
       [problem(path, "expected an object")]}

  defp normalize_placements(raw, base) do
    case Map.get(raw, "placements") do
      placements when is_list(placements) ->
        {parsed, errors} =
          collect(
            placements,
            fn index -> "#{base}.placements[#{index}]" end,
            &normalize_placement/2
          )

        {parsed, errors ++ duplicate_placement_errors(parsed, base)}

      other ->
        {[], [problem("#{base}.placements", "expected a list, got #{inspect(other)}")]}
    end
  end

  defp normalize_placement(raw, path) when is_map(raw) do
    errors = check_unknown_keys([], raw, @placement_keys, path)
    {namespace, e1} = required_text(raw, "namespace", path)
    {owner, e2} = required_scope(raw, "owner", path)
    {environment, e3} = required_scope(raw, "environment", path)
    {active, e4} = optional_flag(raw, "active", path)
    {first_seen, e5} = required_time(raw, "first_seen", path)
    {last_seen, e6} = required_time(raw, "last_seen", path)

    {%{
       namespace: namespace,
       owner: owner,
       environment: environment,
       active: active,
       first_seen: first_seen,
       last_seen: last_seen
     }, errors ++ e1 ++ e2 ++ e3 ++ e4 ++ e5 ++ e6}
  end

  defp normalize_placement(_raw, path),
    do:
      {%{
         namespace: nil,
         owner: nil,
         environment: nil,
         active: true,
         first_seen: nil,
         last_seen: nil
       }, [problem(path, "expected an object")]}

  defp normalize_findings(raw, base) do
    case Map.get(raw, "findings") do
      findings when is_list(findings) ->
        {parsed, errors} =
          collect(findings, fn index -> "#{base}.findings[#{index}]" end, &normalize_finding/2)

        {parsed, errors ++ duplicate_finding_errors(parsed, base)}

      other ->
        {[], [problem("#{base}.findings", "expected a list, got #{inspect(other)}")]}
    end
  end

  defp normalize_finding(raw, path) when is_map(raw) do
    errors = check_unknown_keys([], raw, @finding_keys, path)
    {cve, e1} = required_text(raw, "cve", path)
    {package_name, e2} = required_text(raw, "package_name", path)
    {package_version, e3} = required_text(raw, "package_version", path)
    {severity, e4} = optional_severity(raw, "severity", path)
    {fix, e5} = optional_text(raw, "fix", path)
    {url, e6} = optional_text(raw, "url", path)
    {description, e7} = optional_text(raw, "description", path)
    {suppressed, e8} = optional_flag(raw, "suppressed", path)
    {first_seen, e9} = required_time(raw, "first_seen", path)
    {last_seen, e10} = required_time(raw, "last_seen", path)
    {resolved_at, e11} = optional_time(raw, "resolved_at", path)
    {events, event_errors} = normalize_events(raw, path)

    finding = %{
      cve: cve,
      package_name: package_name,
      package_version: package_version,
      severity: severity,
      fix: fix,
      url: url,
      description: description,
      suppressed: suppressed,
      first_seen: first_seen,
      last_seen: last_seen,
      resolved_at: resolved_at,
      events: events
    }

    {finding,
     errors ++ e1 ++ e2 ++ e3 ++ e4 ++ e5 ++ e6 ++ e7 ++ e8 ++ e9 ++ e10 ++ e11 ++ event_errors}
  end

  defp normalize_finding(_raw, path),
    do:
      {%{
         cve: nil,
         package_name: nil,
         package_version: nil,
         severity: nil,
         fix: nil,
         url: nil,
         description: nil,
         suppressed: false,
         first_seen: nil,
         last_seen: nil,
         resolved_at: nil,
         events: []
       }, [problem(path, "expected an object")]}

  defp normalize_events(raw, base) do
    case Map.get(raw, "events") do
      events when is_list(events) ->
        {parsed, errors} =
          collect(events, fn index -> "#{base}.events[#{index}]" end, &normalize_event/2)

        {parsed, errors ++ duplicate_event_errors(parsed, base)}

      other ->
        {[], [problem("#{base}.events", "expected a list, got #{inspect(other)}")]}
    end
  end

  defp normalize_event(raw, path) when is_map(raw) do
    errors = check_unknown_keys([], raw, @event_keys, path)
    {event, e1} = required_event_name(raw, "event", path)
    {occurred_at, e2} = required_time(raw, "occurred_at", path)
    {note, e3} = optional_text(raw, "note", path)

    {%{event: event, occurred_at: occurred_at, note: note}, errors ++ e1 ++ e2 ++ e3}
  end

  defp normalize_event(_raw, path),
    do: {%{event: nil, occurred_at: nil, note: nil}, [problem(path, "expected an object")]}

  defp required_event_name(raw, key, path) do
    case Map.get(raw, key) do
      value when is_binary(value) ->
        if value in @events do
          {value, []}
        else
          {nil,
           [
             problem(
               "#{path}.#{key}",
               "expected one of #{Enum.join(@events, ", ")}, got #{inspect(value)}"
             )
           ]}
        end

      other ->
        {nil,
         [
           problem(
             "#{path}.#{key}",
             "expected one of #{Enum.join(@events, ", ")}, got #{inspect(other)}"
           )
         ]}
    end
  end

  defp optional_severity(raw, key, path) do
    case Map.get(raw, key) do
      nil ->
        {nil, []}

      value when is_binary(value) ->
        if value in @severities do
          {value, []}
        else
          {nil,
           [
             problem(
               "#{path}.#{key}",
               "expected one of #{Enum.join(@severities, ", ")} or null, got #{inspect(value)}"
             )
           ]}
        end

      other ->
        {nil,
         [
           problem(
             "#{path}.#{key}",
             "expected one of #{Enum.join(@severities, ", ")} or null, got #{inspect(other)}"
           )
         ]}
    end
  end

  defp required_text(raw, key, path) do
    case Map.get(raw, key) do
      value when is_binary(value) ->
        validate_text(value, key, path, true)

      other ->
        {nil, [problem("#{path}.#{key}", "expected a non-empty string, got #{inspect(other)}")]}
    end
  end

  defp optional_text(raw, key, path) do
    case Map.get(raw, key) do
      nil ->
        {nil, []}

      value when is_binary(value) ->
        validate_text(value, key, path, false)

      other ->
        {nil, [problem("#{path}.#{key}", "expected a string or null, got #{inspect(other)}")]}
    end
  end

  defp validate_text(value, key, path, required?) do
    cond do
      not String.valid?(value) ->
        {nil, [problem("#{path}.#{key}", "must be valid UTF-8")]}

      byte_size(value) > @max_text_bytes ->
        {nil, [problem("#{path}.#{key}", "must be at most #{@max_text_bytes} bytes")]}

      Regex.match?(@unsafe_text, value) ->
        {nil, [problem("#{path}.#{key}", "must not contain raw control characters")]}

      String.length(value) > @max_text ->
        {nil, [problem("#{path}.#{key}", "must be at most #{@max_text} characters")]}

      String.trim(value) == "" ->
        if required? do
          {nil, [problem("#{path}.#{key}", "must not be blank")]}
        else
          {nil, []}
        end

      true ->
        {if(required?, do: String.trim(value), else: value), []}
    end
  end

  # Imported owner/environment must satisfy the same contract as the UI scope
  # filter so an option offered by the feed can never be rejected by it.
  defp required_scope(raw, key, path) do
    case Map.get(raw, key) do
      value when is_binary(value) ->
        validate_scope(value, key, path)

      other ->
        {nil, [problem("#{path}.#{key}", "expected a non-empty string, got #{inspect(other)}")]}
    end
  end

  defp validate_scope(value, key, path) do
    cond do
      not String.valid?(value) ->
        {nil, [problem("#{path}.#{key}", "must be valid UTF-8")]}

      String.trim(value) == "" ->
        {nil, [problem("#{path}.#{key}", "must not be blank")]}

      Regex.match?(@unsafe_text, value) ->
        {nil, [problem("#{path}.#{key}", "must not contain raw control characters")]}

      byte_size(value) > @max_scope_bytes ->
        {nil, [problem("#{path}.#{key}", "must be at most #{@max_scope_bytes} bytes")]}

      String.length(value) > @scope_max ->
        {nil,
         [
           problem(
             "#{path}.#{key}",
             "must be at most #{@scope_max} characters to match the scope filter contract"
           )
         ]}

      true ->
        {String.trim(value), []}
    end
  end

  # A flag that may be absent. `nil` means "the snapshot does not state it";
  # writes then preserve the recorded local value (creation falls back to the
  # schema default) instead of silently clearing source state.
  defp optional_flag(raw, key, path) do
    case Map.get(raw, key) do
      nil -> {nil, []}
      value when is_boolean(value) -> {value, []}
      other -> {nil, [problem("#{path}.#{key}", "expected a boolean, got #{inspect(other)}")]}
    end
  end

  defp required_time(raw, key, path) do
    case Map.get(raw, key) do
      nil -> {nil, [problem("#{path}.#{key}", "is required")]}
      value -> parse_time(value, "#{path}.#{key}")
    end
  end

  defp optional_time(raw, key, path) do
    case Map.get(raw, key) do
      nil -> {nil, []}
      value -> parse_time(value, "#{path}.#{key}")
    end
  end

  defp parse_time(value, path) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> {DateTime.truncate(datetime, :second), []}
      {:error, reason} -> {nil, [problem(path, "invalid ISO 8601 timestamp (#{reason})")]}
    end
  end

  defp parse_time(other, path),
    do: {nil, [problem(path, "expected an ISO 8601 string, got #{inspect(other)}")]}

  defp duplicate_errors(images) do
    duplicate_errors(images, "$.images[", "].digest", & &1.digest, "image digest")
  end

  defp duplicate_placement_errors(placements, base) do
    duplicate_errors(
      placements,
      "#{base}.placements[",
      "]",
      &{&1.namespace, &1.owner, &1.environment},
      "placement"
    )
  end

  defp duplicate_finding_errors(findings, base) do
    duplicate_errors(
      findings,
      "#{base}.findings[",
      "]",
      &{&1.cve, &1.package_name, &1.package_version},
      "finding"
    )
  end

  defp duplicate_event_errors(events, base) do
    duplicate_errors(
      events,
      "#{base}.events[",
      "]",
      &{&1.event, &1.occurred_at},
      "event"
    )
  end

  defp duplicate_errors(items, prefix, suffix, key_fun, label) do
    items
    |> Enum.with_index()
    |> Enum.reduce({[], MapSet.new()}, fn {item, index}, {errors, seen} ->
      key = key_fun.(item)

      if MapSet.member?(seen, key) do
        {[problem("#{prefix}#{index}#{suffix}", "duplicate #{label} #{inspect(key)}") | errors],
         seen}
      else
        {errors, MapSet.put(seen, key)}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  defp problem(path, message), do: %{path: path, message: message}

  defp format_errors(errors) do
    errors
    |> Enum.map(fn %{path: path, message: message} -> "  #{path}: #{message}" end)
    |> Enum.join("\n")
  end

  ## Reconciliation

  defp load_images([]), do: %{}

  defp load_images(digests) do
    from(i in Image, where: i.digest in ^digests, select: i)
    |> Repo.all()
    |> Map.new(&{&1.digest, &1})
  end

  defp existing_image_ids(images), do: images |> Map.values() |> Enum.map(& &1.id)

  defp load_placements([]), do: %{}

  defp load_placements(image_ids) do
    from(p in ImagePlacement, where: p.image_id in ^image_ids)
    |> Repo.all()
    |> Map.new(&{{&1.image_id, &1.namespace, &1.owner, &1.environment}, &1})
  end

  defp load_findings([]), do: %{}

  defp load_findings(image_ids) do
    from(f in Finding, where: f.image_id in ^image_ids)
    |> Repo.all()
    |> Map.new(&{{&1.image_id, &1.cve, &1.package_name, &1.package_version}, &1})
  end

  defp load_events(findings) do
    finding_ids = findings |> Map.values() |> Enum.map(& &1.id)

    if finding_ids == [] do
      %{}
    else
      from(e in FindingEvent, where: e.finding_id in ^finding_ids)
      |> Repo.all()
      |> Enum.group_by(& &1.finding_id, &{&1.event, DateTime.truncate(&1.occurred_at, :second)})
      |> Map.new(fn {finding_id, keys} -> {finding_id, MapSet.new(keys)} end)
    end
  end

  defp reconcile(snapshot, images, placements, findings, events) do
    Enum.map(snapshot.images, fn image ->
      existing_image = Map.get(images, image.digest)
      image_action = image_action(existing_image, image)
      image_id = existing_image && existing_image.id

      placements = reconcile_placements(image.placements, image_id, placements)
      findings = reconcile_findings(image.findings, image_id, findings, events)

      %{
        digest: image.digest,
        action: image_action,
        image_id: image_id,
        placements: placements,
        findings: findings
      }
    end)
  end

  defp image_action(nil, _image), do: :create

  defp image_action(existing, image) do
    if existing.repository == image.repository and existing.tag == image.tag and
         existing.description == image.description do
      :unchanged
    else
      :update
    end
  end

  defp reconcile_placements(placements, image_id, existing_map) do
    Enum.map(placements, fn placement ->
      key = {image_id, placement.namespace, placement.owner, placement.environment}

      action =
        case Map.get(existing_map, key) do
          nil -> :create
          existing -> if placement_changed?(existing, placement), do: :update, else: :unchanged
        end

      %{key: {placement.namespace, placement.owner, placement.environment}, action: action}
    end)
  end

  defp placement_changed?(existing, placement) do
    (not is_nil(placement.active) and existing.active != placement.active) or
      DateTime.truncate(existing.first_seen, :second) != placement.first_seen or
      DateTime.truncate(existing.last_seen, :second) != placement.last_seen
  end

  defp reconcile_findings(findings, image_id, existing_map, events) do
    Enum.map(findings, fn finding ->
      key = {image_id, finding.cve, finding.package_name, finding.package_version}
      existing = Map.get(existing_map, key)

      action =
        case existing do
          nil -> :create
          existing -> if finding_changed?(existing, finding), do: :update, else: :unchanged
        end

      event_rows = reconcile_events(finding.events, existing && existing.id, events)

      %{
        key: {finding.cve, finding.package_name, finding.package_version},
        action: action,
        events: event_rows
      }
    end)
  end

  defp finding_changed?(existing, finding) do
    existing.severity != finding.severity or
      existing.fix != finding.fix or
      existing.url != finding.url or
      existing.description != finding.description or
      (not is_nil(finding.suppressed) and existing.suppressed != finding.suppressed) or
      DateTime.truncate(existing.first_seen, :second) != finding.first_seen or
      DateTime.truncate(existing.last_seen, :second) != finding.last_seen or
      resolution_changed?(existing, finding)
  end

  # A snapshot may set or move `resolved_at`, never clear it: an export that
  # omits resolution is not evidence that anything was remediated.
  defp resolution_changed?(existing, finding) do
    not is_nil(finding.resolved_at) and
      truncate_optional(existing.resolved_at) != finding.resolved_at
  end

  defp truncate_optional(nil), do: nil
  defp truncate_optional(datetime), do: DateTime.truncate(datetime, :second)

  defp reconcile_events(events, finding_id, existing_events) do
    known =
      if finding_id, do: Map.get(existing_events, finding_id, MapSet.new()), else: MapSet.new()

    Enum.map(events, fn event ->
      action =
        if MapSet.member?(known, {event.event, event.occurred_at}), do: :existing, else: :create

      %{key: {event.event, event.occurred_at}, action: action}
    end)
  end

  defp summarize(rows) do
    all_placements = Enum.flat_map(rows, & &1.placements)
    all_findings = Enum.flat_map(rows, & &1.findings)
    all_events = Enum.flat_map(all_findings, & &1.events)

    %{
      images: counts(Enum.map(rows, & &1.action)),
      placements: counts(Enum.map(all_placements, & &1.action)),
      findings: counts(Enum.map(all_findings, & &1.action)),
      events: counts(Enum.map(all_events, & &1.action))
    }
  end

  defp counts(actions) do
    Enum.reduce(actions, %{create: 0, update: 0, unchanged: 0, existing: 0}, fn action, acc ->
      Map.update!(acc, action, &(&1 + 1))
    end)
  end
end
