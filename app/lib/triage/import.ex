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
  use Triage.Import.Contract

  alias Triage.Import.Parse
  alias Triage.Import.Reconcile
  alias Triage.Import.Write
  alias Triage.Repo

  @typedoc "One detected problem: the JSON path it was found at and what is wrong there."
  @type problem :: %{path: String.t(), message: String.t()}

  @typedoc "A parsed snapshot document, with every timestamp a second-precision DateTime."
  @type snapshot :: map()

  @typedoc "An import report: `:summary` counts, per-image `:images` detail and `:warnings`."
  @type report :: map()

  @spec max_document_bytes() :: pos_integer()
  @doc "Maximum accepted snapshot document size in bytes."
  def max_document_bytes, do: @max_document_bytes

  @doc """
  Parses and validates a snapshot JSON document.

  Returns `{:ok, snapshot}` where every timestamp is a `DateTime` truncated to
  seconds, or `{:error, errors}` with a list of `%{path: String.t(), message:
  String.t()}` covering every detected problem.
  """
  @spec parse(term()) :: {:ok, snapshot()} | {:error, [problem()]}
  def parse(json) when is_binary(json) do
    if byte_size(json) > @max_document_bytes do
      {:error,
       [
         Parse.problem(
           "$",
           "snapshot is #{byte_size(json)} bytes; the limit is #{@max_document_bytes}"
         )
       ]}
    else
      case Jason.decode(json) do
        {:ok, raw} when is_map(raw) ->
          Parse.normalize(raw)

        {:ok, _other} ->
          {:error, [Parse.problem("$", "snapshot must be a JSON object")]}

        {:error, error} ->
          {:error, [Parse.problem("$", "invalid JSON: #{Exception.message(error)}")]}
      end
    end
  end

  def parse(_other), do: {:error, [Parse.problem("$", "snapshot must be a JSON string")]}

  @doc """
  Re-validates an already-normalized snapshot and returns the canonical form.

  `apply/1`, `dry_run/1` and `write!/1` all funnel through this function, so a
  mutated public map cannot bypass the parser's format, enum, text, identity or
  budget checks. Pure; performs no database work.
  """
  @spec validate(term()) :: {:ok, snapshot()} | {:error, [problem()]}
  def validate(snapshot) do
    with {:ok, _budget} <- preflight(snapshot, :root, "$", {0, 0}) do
      Parse.normalize(Parse.snapshot_to_raw(snapshot))
    end
  end

  # Validate the normalized atom-keyed shape BEFORE rebuilding it. Never drop
  # unknown keys, silently prefer atom/string aliases, or traverse an oversized
  # collection before enforcing its budget. JSON callers use parse/1 instead.
  defp preflight(record, kind, path, {count, bytes}) when is_map(record) do
    {keys, children} = shape(kind)

    cond do
      is_struct(record) or map_size(record) > length(keys) ->
        {:error,
         [Parse.problem(path, "expected a plain normalized map with only known atom keys")]}

      Enum.any?(Map.keys(record), &(not is_atom(&1) or Atom.to_string(&1) not in keys)) ->
        {:error, [Parse.problem(path, "unknown key; expected only normalized atom keys")]}

      true ->
        count = count + if(kind == :root, do: 0, else: 1)

        bytes =
          Enum.reduce(record, bytes, fn
            {_key, value}, acc when is_binary(value) -> acc + byte_size(value)
            _, acc -> acc
          end)

        if count > @max_total_records or bytes > @max_document_bytes do
          {:error, [Parse.problem(path, "normalized snapshot exceeds record or byte limit")]}
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
    do: {:error, [Parse.problem(path, "expected a plain normalized map")]}

  defp preflight_list(list, kind, path, max, budget) when is_list(list) do
    # take(max + 1) bounds the count traversal as well as subsequent conversion.
    if length(Enum.take(list, max + 1)) > max do
      {:error, [Parse.problem(path, "records exceed the limit of #{max}")]}
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
  @spec dry_run(term()) :: {:ok, report()} | {:error, [problem()]}
  def dry_run(snapshot) do
    with {:ok, validated} <- validate(snapshot) do
      digests = Enum.map(validated.images, & &1.digest)
      images = Reconcile.load_images(digests)
      image_ids = Reconcile.existing_image_ids(images)
      placements = Reconcile.load_placements(image_ids)
      findings = Reconcile.load_findings(image_ids)
      events = Reconcile.load_events(findings)

      case Write.regression_errors(validated, images, placements, findings) do
        [] ->
          rows = Reconcile.reconcile(validated, images, placements, findings, events)
          warnings = Write.resolution_warnings(validated, images, findings)
          {:ok, %{summary: Reconcile.summarize(rows), images: rows, warnings: warnings}}

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
  @spec import_snapshot(term()) :: {:ok, report()} | {:error, [problem()]}
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
  @spec apply(term()) :: {:ok, report()} | {:error, [problem()]}
  def apply(snapshot) do
    with {:ok, validated} <- validate(snapshot) do
      case Repo.transaction(fn -> Write.do_write!(validated) end) do
        {:ok, report} ->
          {:ok, report}

        {:error, {:import_rejected, errors}} ->
          {:error, errors}

        {:error, reason} ->
          {:error, [Parse.problem("$", "import failed and was rolled back: #{inspect(reason)}")]}
      end
    end
  rescue
    error ->
      {:error,
       [Parse.problem("$", "import failed and was rolled back: #{Exception.message(error)}")]}
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
  @spec write!(term()) :: report()
  def write!(snapshot) do
    unless Repo.in_transaction?() do
      raise ArgumentError,
            "Triage.Import.write!/1 must be called inside Repo.transaction/1; " <>
              "use apply/1 or import_snapshot/1 for the guarded write path"
    end

    case validate(snapshot) do
      {:ok, validated} ->
        Write.do_write!(validated)

      {:error, errors} ->
        raise ArgumentError, "invalid snapshot: " <> Parse.format_errors(errors)
    end
  end
end
