defmodule Triage.GuidedReview.PageOptions do
  @moduledoc "Strict queue filters and a versioned rank/CVE keyset cursor bound to those filters."
  @keys [:q, :team, :severity, :exposure, :kev]

  def parse(opts) when is_list(opts) do
    if Keyword.keyword?(opts), do: parse_keywords(opts), else: {:error, :invalid_page}
  end

  def parse(_), do: {:error, :invalid_page}

  defp parse_keywords(opts) do
    filters = Map.new(@keys, &{&1, Keyword.get(opts, &1, "")})
    limit = Keyword.get(opts, :limit, 25)

    with true <- valid_keys?(Keyword.keys(opts)),
         true <- is_integer(limit) and limit in 1..100,
         true <- Enum.all?(filters, &valid_filter?/1),
         {:ok, cursor} <- decode(Keyword.get(opts, :after_cve), filters) do
      {:ok, cursor, limit, filters}
    else
      _ -> {:error, :invalid_page}
    end
  end

  defp valid_keys?(keys),
    do: keys -- (@keys ++ [:limit, :after_cve]) == [] and keys == Enum.uniq(keys)

  defp valid_filter?({key, value}) when key in [:q, :team], do: text?(value, 200)
  defp valid_filter?({:severity, v}), do: v in ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
  defp valid_filter?({:exposure, v}), do: v in ["", "internet_exposed", "internal", "unknown"]
  defp valid_filter?({:kev, v}), do: v in ["", "yes", "no"]

  defp text?(v, max) when is_binary(v),
    do: byte_size(v) <= max and String.valid?(v) and not String.contains?(v, <<0>>)

  defp text?(_, _), do: false

  def encode(%{rank: rank, cve: cve}, filters) do
    [1, rank, cve, signature(filters)] |> Jason.encode!() |> Base.url_encode64(padding: false)
  end

  defp decode(nil, _filters), do: {:ok, nil}

  defp decode(value, filters) when is_binary(value) and byte_size(value) <= 1024 do
    with {:ok, json} <- Base.url_decode64(value, padding: false),
         {:ok, [1, rank, cve, signature]} <- Jason.decode(json),
         true <- is_integer(rank) and rank in 1..4,
         true <- text?(cve, 200) and cve != "",
         true <- signature == signature(filters) do
      {:ok, %{rank: rank, cve: cve}}
    else
      _ -> {:error, :invalid_page}
    end
  end

  defp decode(_, _), do: {:error, :invalid_page}

  defp signature(filters) do
    filters
    |> Enum.sort()
    |> :erlang.term_to_binary()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16()
  end
end
