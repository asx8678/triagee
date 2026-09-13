defmodule Triage.ImportFlow do
  @moduledoc """
  Local UI import boundary. Previews reserve nothing; apply rechecks the full
  reconciliation under the same transaction lock as every Import writer.
  Prepared values belong in server state, not client forms. This is not auth.
  """
  alias Triage.{Import, Repo}
  @max_bytes 1_000_000
  @lock 7_433_921_021_337

  def max_bytes, do: @max_bytes

  def prepare(json) when is_binary(json) and byte_size(json) <= @max_bytes do
    with :ok <- depth(json, 0, false, false),
         {:ok, snapshot} <- Import.parse(json),
         {:ok, report} <- preview_report(snapshot) do
      digest = hash(snapshot)

      {:ok,
       %{
         snapshot: snapshot,
         report: report,
         digest: digest,
         fingerprint: hash({digest, report}),
         nonce: Ecto.UUID.generate()
       }}
    else
      _ -> {:error, :invalid_snapshot}
    end
  rescue
    _ -> {:error, :invalid_snapshot}
  end

  def prepare(_), do: {:error, :invalid_snapshot}

  # Only upload metadata supplied by LiveView may provide this path.
  # No event handler accepts a path from the client.
  def read_upload(path) when is_binary(path) do
    case File.open(path, [:read, :binary], fn file -> IO.binread(file, @max_bytes + 1) end) do
      {:ok, data} when is_binary(data) and byte_size(data) <= @max_bytes -> {:ok, data}
      _ -> {:error, :invalid_snapshot}
    end
  rescue
    _ -> {:error, :invalid_snapshot}
  end

  def apply(prepared, nonce, ack) do
    with true <- ack == "true",
         {:ok, snapshot} <- bound_snapshot(prepared, nonce) do
      case Repo.transaction(fn ->
             Repo.query!("SELECT pg_advisory_xact_lock($1)", [@lock])

             case preview_report(snapshot) do
               {:ok, report} ->
                 if hash({prepared.digest, report}) != prepared.fingerprint do
                   Repo.rollback(:stale_preview)
                 end

                 Import.write!(snapshot)

               _ ->
                 Repo.rollback(:stale_preview)
             end
           end) do
        {:ok, report} -> {:ok, report}
        {:error, :stale_preview} -> {:error, :stale_preview}
        _ -> {:error, :apply_failed}
      end
    else
      _ -> {:error, :invalid_confirmation}
    end
  rescue
    _ -> {:error, :apply_failed}
  end

  defp bound_snapshot(
         %{
           snapshot: snapshot,
           report: report,
           digest: digest,
           fingerprint: fingerprint,
           nonce: nonce
         } = prepared,
         submitted
       )
       when map_size(prepared) == 5 and is_binary(nonce) and is_binary(digest) and
              is_binary(fingerprint) and is_map(report) and nonce == submitted do
    with {:ok, _} <- Ecto.UUID.cast(nonce),
         {:ok, normalized} <- Import.validate(snapshot),
         true <- normalized == snapshot,
         true <- digest == hash(normalized),
         true <- fingerprint == hash({digest, report}) do
      {:ok, normalized}
    else
      _ -> {:error, :invalid_confirmation}
    end
  end

  defp bound_snapshot(_, _), do: {:error, :invalid_confirmation}

  # The import report describes actions, not old metadata. Two different local
  # values can both be :update. Bind the actual affected inventory as well, so
  # an equal-count / equal-action change cannot be silently overwritten.
  defp preview_report(snapshot) do
    with {:ok, report} <- Import.dry_run(snapshot) do
      digests = Enum.map(snapshot.images, & &1.digest)

      states =
        for {table, join} <- [
              {"images", "JOIN images i ON i.id = t.id"},
              {"image_placements", "JOIN images i ON i.id = t.image_id"},
              {"findings", "JOIN images i ON i.id = t.image_id"},
              {"finding_events",
               "JOIN findings f ON f.id = t.finding_id JOIN images i ON i.id = f.image_id"}
            ] do
          # Fixed server identifiers only; no source text is interpolated.
          rows =
            Repo.query!(
              "SELECT to_jsonb(t) FROM #{table} t #{join} WHERE i.digest = ANY($1::text[]) ORDER BY t.id",
              [digests],
              log: false
            ).rows

          {table, hash(rows)}
        end

      {:ok, Map.put(report, :inventory_fingerprint, hash(states))}
    end
  end

  # Tagged, sorted terms avoid map iteration ordering and encode timestamps
  # explicitly. Hash the entire report, never just its summary counts.
  defp hash(value),
    do:
      :crypto.hash(:sha256, :erlang.term_to_binary(canonical(value)))
      |> Base.encode16(case: :lower)

  defp canonical(%DateTime{} = value), do: {:datetime, DateTime.to_iso8601(value)}

  defp canonical(value) when is_map(value),
    do: {:map, value |> Enum.map(fn {k, v} -> {canonical(k), canonical(v)} end) |> Enum.sort()}

  defp canonical(value) when is_list(value), do: {:list, Enum.map(value, &canonical/1)}

  defp canonical(value) when is_tuple(value),
    do: {:tuple, value |> Tuple.to_list() |> Enum.map(&canonical/1)}

  defp canonical(value), do: value

  # Byte lexer before Jason: brackets inside strings (including escaped quotes)
  # do not count. Jason remains responsible for actual JSON syntax validation.
  defp depth(<<>>, 0, false, false), do: :ok
  defp depth(<<>>, _, _, _), do: :error
  defp depth(<<_, rest::binary>>, n, true, true), do: depth(rest, n, true, false)
  defp depth(<<92, rest::binary>>, n, true, false), do: depth(rest, n, true, true)
  defp depth(<<34, rest::binary>>, n, quoted, false), do: depth(rest, n, not quoted, false)

  defp depth(<<c, rest::binary>>, n, false, false) when c in [123, 91] and n < 32,
    do: depth(rest, n + 1, false, false)

  defp depth(<<c, _::binary>>, _, false, false) when c in [123, 91], do: :error

  defp depth(<<c, rest::binary>>, n, false, false) when c in [125, 93] and n > 0,
    do: depth(rest, n - 1, false, false)

  defp depth(<<c, _::binary>>, _, false, false) when c in [125, 93], do: :error
  defp depth(<<_, rest::binary>>, n, quoted, escaped), do: depth(rest, n, quoted, escaped)
end
