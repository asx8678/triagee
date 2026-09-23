defmodule Triage.Reporting.Filters do
  @moduledoc false

  alias Triage.Intel.Sanitize

  @common ~w(team environment q severity)
  @allowed %{
    summary: @common,
    cves: @common ++ ~w(cve whitelist_coverage active limit cursor),
    cve: ~w(cve team environment),
    targets:
      @common ++
        ~w(cve active whitelisted needs_decision needs_attention expires_within_days limit cursor),
    packages: ~w(cve placement_id team environment limit cursor),
    options: ~w(q limit cursor)
  }
  @boolean_keys ~w(active whitelisted needs_decision needs_attention)
  @field_atoms %{
    "team" => :team,
    "environment" => :environment,
    "q" => :q,
    "active" => :active,
    "whitelisted" => :whitelisted,
    "needs_decision" => :needs_decision,
    "needs_attention" => :needs_attention
  }

  def validate(kind, params) when is_map(params) and is_map_key(@allowed, kind) do
    with :ok <- known_keys(kind, params),
         {:ok, filters} <- normalize(kind, params),
         :ok <- combinations(kind, filters) do
      {:ok, filters}
    end
  end

  def validate(_kind, _params), do: error("invalid_parameters", "Parameters must be an object")

  def fingerprint(filters), do: Map.drop(filters, [:cursor, :cursor_position])

  defp known_keys(kind, params) do
    unknown = Map.keys(params) -- Map.fetch!(@allowed, kind)

    if unknown == [],
      do: :ok,
      else: error("unknown_parameter", "Unknown parameter: #{hd(unknown)}")
  end

  defp normalize(kind, params) do
    with {:ok, text} <- text_fields(params),
         {:ok, severity} <- severity(params["severity"]),
         {:ok, cve} <- cve(params["cve"], kind),
         {:ok, booleans} <- booleans(params),
         {:ok, limit} <- integer(params["limit"], 50, 1, 100, "limit"),
         {:ok, expires} <-
           integer(params["expires_within_days"], nil, 1, 90, "expires_within_days"),
         {:ok, placement_id} <-
           integer(params["placement_id"], nil, 1, 9_223_372_036_854_775_807, "placement_id"),
         {:ok, coverage} <-
           enum(
             params["whitelist_coverage"],
             ~w(none partial full not_applicable),
             "whitelist_coverage"
           ),
         {:ok, cursor} <- cursor(params["cursor"]) do
      filters =
        text
        |> Map.merge(booleans)
        |> Map.merge(%{
          severity: severity,
          cve: cve,
          limit: limit,
          expires_within_days: expires,
          placement_id: placement_id,
          whitelist_coverage: coverage,
          cursor: cursor
        })
        |> defaults(kind)

      {:ok, filters}
    end
  end

  defp text_fields(params) do
    Enum.reduce_while([{"team", 120}, {"environment", 120}, {"q", 200}], {:ok, %{}}, fn {key, max},
                                                                                        {:ok, acc} ->
      case bounded_text(params[key], max, key) do
        {:ok, value} -> {:cont, {:ok, Map.put(acc, Map.fetch!(@field_atoms, key), value)}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp booleans(params) do
    Enum.reduce_while(@boolean_keys, {:ok, %{}}, fn key, {:ok, acc} ->
      case boolean(params[key], key) do
        {:ok, value} -> {:cont, {:ok, Map.put(acc, Map.fetch!(@field_atoms, key), value)}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp defaults(filters, :targets),
    do: Map.update!(filters, :active, &if(is_nil(&1), do: true, else: &1))

  defp defaults(filters, :cves),
    do: Map.update!(filters, :active, &if(is_nil(&1), do: true, else: &1))

  defp defaults(filters, _kind), do: filters

  defp combinations(:targets, %{expires_within_days: days, whitelisted: true})
       when not is_nil(days), do: :ok

  defp combinations(:targets, %{expires_within_days: nil}), do: :ok

  defp combinations(:targets, %{expires_within_days: _days}),
    do: error("invalid_filter_combination", "expires_within_days requires whitelisted=true")

  defp combinations(:cves, %{active: true}), do: :ok

  defp combinations(:cves, _filters),
    do: error("invalid_filter_combination", "The v1 CVE list supports active=true only")

  defp combinations(_kind, _filters), do: :ok

  defp bounded_text(nil, _max, _key), do: {:ok, ""}

  defp bounded_text(value, max, key) when is_binary(value) do
    value = String.trim(value)
    if String.valid?(value) and byte_size(value) <= max, do: {:ok, value}, else: invalid(key)
  end

  defp bounded_text(_value, _max, key), do: invalid(key)

  defp severity(nil), do: {:ok, ""}
  defp severity(""), do: {:ok, ""}

  defp severity(value) when is_binary(value) do
    value = String.upcase(String.trim(value))
    if value in Triage.Severity.order(), do: {:ok, value}, else: invalid("severity")
  end

  defp severity(_value), do: invalid("severity")

  defp cve(nil, kind) when kind in [:cve, :packages], do: invalid("cve")
  defp cve(nil, _kind), do: {:ok, ""}
  defp cve("", kind) when kind in [:cve, :packages], do: invalid("cve")
  defp cve("", _kind), do: {:ok, ""}

  defp cve(value, _kind) when is_binary(value) do
    case Sanitize.normalize_cve_id(value) do
      nil -> invalid("cve")
      normalized when byte_size(normalized) <= 40 -> {:ok, normalized}
      _ -> invalid("cve")
    end
  end

  defp cve(_value, _kind), do: invalid("cve")

  defp boolean(nil, _key), do: {:ok, nil}
  defp boolean("true", _key), do: {:ok, true}
  defp boolean("false", _key), do: {:ok, false}
  defp boolean(_value, key), do: invalid(key)

  defp integer(nil, default, _min, _max, _key), do: {:ok, default}

  defp integer(value, _default, min, max, key) when is_binary(value) do
    case Integer.parse(value) do
      {number, ""} when number >= min and number <= max -> {:ok, number}
      _ -> invalid(key)
    end
  end

  defp integer(_value, _default, _min, _max, key), do: invalid(key)

  defp enum(nil, _allowed, _key), do: {:ok, ""}
  defp enum("", _allowed, _key), do: {:ok, ""}

  defp enum(value, allowed, key) when is_binary(value) do
    if value in allowed, do: {:ok, value}, else: invalid(key)
  end

  defp enum(_value, _allowed, key), do: invalid(key)

  defp cursor(nil), do: {:ok, nil}
  defp cursor(""), do: {:ok, nil}

  defp cursor(value) when is_binary(value) and byte_size(value) <= 4096,
    do: {:ok, value}

  defp cursor(_value), do: invalid("cursor")

  defp invalid(key), do: error("invalid_parameter", "Invalid #{key}")
  defp error(code, detail), do: {:error, %{status: 400, code: code, detail: detail}}
end
