defmodule Triage.Replay.Runs do
  @moduledoc """
  Explicit, summary-only synthetic replay ledger. Caller must start Repo.

  `record_result/2` accepts a nonempty UTF-8 key of at most 128 bytes and JSON,
  never a report/map. It recomputes Replay.run before any database access.
  Keys are SHA256-hashed; neither raw keys nor input documents are persisted.
  A transaction advisory lock (distinct from Import) serializes deduplication,
  quota checks and explicit purge. Maximum 1000 physical rows, 64KiB JSON each.

  Receipts expire after 30 days. Retries never extend TTL. Expired rows are hidden
  from get/list; retry of an expired retained key returns :expired (or conflict).
  They still consume quota until an operator calls purge_expired!/0. There is no
  automatic physical retention job and no asserted historical provenance.
  """
  import Ecto.Query
  alias Triage.{Repo, Replay}
  alias Triage.Replay.Run

  @lock_key 7_433_921_021_338
  @ttl 30 * 24 * 60 * 60
  @max_rows 1000
  @max_bytes 65_536

  def record_result(key, json) do
    with :ok <- validate_key(key),
         {:ok, summary} <- Replay.run(json),
         {:ok, attrs} <- summary_attrs(summary) do
      database(fn ->
        Repo.transaction(
          fn ->
            lock!()
            now = DateTime.utc_now()
            key_hash = hash(key)

            case Repo.get_by(Run, [key_hash: key_hash], log: false) do
              %Run{input_sha256: digest} = existing when digest == attrs.input_sha256 ->
                if DateTime.compare(existing.expires_at, now) == :gt,
                  do: existing,
                  else: Repo.rollback(:expired)

              %Run{} ->
                Repo.rollback(:idempotency_conflict)

              nil ->
                if Repo.aggregate(Run, :count, :id, log: false) >= @max_rows,
                  do: Repo.rollback(:quota_exceeded)

                %Run{}
                |> Ecto.Changeset.change(
                  Map.merge(attrs, %{
                    key_hash: key_hash,
                    received_at: now,
                    expires_at: DateTime.add(now, @ttl, :second)
                  })
                )
                |> Repo.insert!(log: false)
            end
          end,
          log: false
        )
      end)
    end
  end

  @doc "Fetch an unexpired receipt by its original idempotency key."
  def get(key) do
    with :ok <- validate_key(key) do
      database(fn ->
        now = DateTime.utc_now()
        digest = hash(key)

        {:ok,
         Repo.one(from(r in Run, where: r.key_hash == ^digest and r.expires_at > ^now),
           log: false
         )}
      end)
    end
  end

  @doc "Ascending ID cursor pagination; limit 1..100, after_id >= 0."
  def list(opts \\ []) do
    if is_list(opts) and Keyword.keyword?(opts) and
         Enum.all?(Keyword.keys(opts), &(&1 in [:limit, :after_id])) do
      list_page(Keyword.get(opts, :limit, 100), Keyword.get(opts, :after_id, 0))
    else
      {:error, :invalid_pagination}
    end
  end

  defp list_page(limit, after_id)
       when is_integer(limit) and limit >= 1 and limit <= 100 and
              is_integer(after_id) and after_id >= 0 and after_id <= 9_223_372_036_854_775_807 do
    database(fn ->
      now = DateTime.utc_now()

      {:ok,
       Repo.all(
         from(r in Run,
           where: r.expires_at > ^now and r.id > ^after_id,
           order_by: [asc: r.id],
           limit: ^limit
         ),
         log: false
       )}
    end)
  end

  defp list_page(_, _), do: {:error, :invalid_pagination}

  @doc "Operator-only explicit physical deletion. Returns {:ok, count} or closed error."
  def purge_expired! do
    database(fn ->
      Repo.transaction(
        fn ->
          lock!()
          now = DateTime.utc_now()
          {count, _} = Repo.delete_all(from(r in Run, where: r.expires_at <= ^now), log: false)
          count
        end,
        log: false
      )
    end)
  end

  defp validate_key(key) when is_binary(key) and byte_size(key) in 1..128 do
    if String.valid?(key), do: :ok, else: {:error, :invalid_key}
  end

  defp validate_key(_), do: {:error, :invalid_key}

  # Only called with the result of Replay.run, never with a caller-supplied map.
  defp summary_attrs(
         %{
           "format" => "triage.replay.result",
           "version" => 1,
           "origin" => "synthetic",
           "complete" => complete,
           "actionable" => false,
           "inventory_changed" => false,
           "historical_provenance" => false,
           "input_sha256" => digest,
           "counts" => counts
         } = summary
       )
       when is_boolean(complete) and is_binary(digest) and is_map(counts) do
    with true <- Regex.match?(~r/\A[0-9a-f]{64}\z/, digest),
         {:ok, encoded} <- Jason.encode(summary),
         true <- byte_size(encoded) <= @max_bytes do
      {:ok,
       %{
         summary: summary,
         input_sha256: digest,
         outcome: if(complete, do: "complete", else: "incomplete")
       }}
    else
      _ -> {:error, :invalid_result}
    end
  end

  defp summary_attrs(_), do: {:error, :invalid_result}
  defp hash(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)
  defp lock!, do: Repo.query!("SELECT pg_advisory_xact_lock($1)", [@lock_key], log: false)

  defp database(fun) do
    if Process.whereis(Repo) do
      fun.()
    else
      {:error, :database_unavailable}
    end
  rescue
    _ in DBConnection.ConnectionError -> {:error, :database_unavailable}
    _ in Postgrex.Error -> {:error, :database_error}
  end
end
