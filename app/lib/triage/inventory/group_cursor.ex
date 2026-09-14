defmodule Triage.Inventory.GroupCursor do
  @moduledoc """
  The keyset position contract for the advisory list: which fields each
  published result order compares, and the one definition of how a position
  is written into a URL and read back.

  A cursor is a position, never an authorization token: it says only which
  group the next page continues after. Every order published by
  `Triage.Inventory.group_sorts/0` ends in the advisory id, which is unique
  per group, so a position is strict — paging with these cursors can neither
  duplicate nor skip a group at any depth, and each page costs one page of
  work rather than one offset.

  `keys/1` is the single definition of each order's compared fields, in
  comparison order. `Triage.Inventory.list_groups/1` derives both its ORDER
  BY and its cursor predicate from that list, so the order and the position
  cannot drift apart.

  Encoding joins the field values, most significant first, with `~`:

      severity     "4~12~CVE-2024-1001"     rank, distinct images, advisory id
      newest       "2026-09-10T12:00:00Z~CVE-2024-1001"
      last_seen    "2026-09-14T06:00:00Z~CVE-2024-1001"
      occurrences  "12~CVE-2024-1001"
      cve          "CVE-2024-1001"

  `parse/2` is strict and total. A cursor is accepted only when it carries
  exactly the fields of the order it is used with, each in its canonical
  form within its own bounds: ASCII decimal integers without leading zeros
  and within range, a whole-second UTC ISO-8601 timestamp that re-encodes to
  itself, and advisory text that is plain, valid UTF-8, unblank, without control
  characters, at most 120 characters and without the field separator.
  Anything else — a wrong field count, a malformed, non-canonical or
  out-of-range value, another term shape entirely — is `{:error, :before}`
  so the caller renders a visible invalid-parameter state with no rows,
  instead of coercing it into a position in a slice the caller never saw.
  """

  @separator "~"
  @max_text 120
  @max_count 9_223_372_036_854_775_807
  @max_rank 4
  @unsafe_text ~r/[\x00-\x1F\x7F]/
  @canonical_integer ~r/\A(0|[1-9][0-9]{0,18})\z/

  @typedoc "A compared field of a published result order."
  @type name :: :severity_rank | :images | :occurrences | :first_seen | :last_seen | :cve

  @typedoc "How one compared field is written into a cursor."
  @type field_type :: :rank | :count | :timestamp | :text

  @typedoc "A parsed position: one value per compared field of its order."
  @type t :: %{optional(name) => integer | DateTime.t() | String.t()}

  @doc """
  The compared fields of one published order, most significant first, as
  `{name, direction, type}`.

  `direction` is the ORDER BY direction of the field and the direction the
  cursor continues in: a `:desc` field continues with a smaller value, an
  `:asc` field with a larger one. Raises for a sort no order publishes,
  because that is a programming error rather than user input; `parse/2`
  stays total for the user-facing direction.
  """
  @spec keys(binary) :: [{name, :asc | :desc, field_type}]
  def keys(sort) do
    case sort_keys(sort) do
      nil ->
        raise ArgumentError,
              "unsupported group sort #{inspect(sort)}; expected one of " <>
                inspect(Triage.Inventory.group_sorts())

      keys ->
        keys
    end
  end

  @doc """
  Encodes the position of one group row for one order.

  The row must carry this order's compared fields (`Triage.Inventory`'s
  grouped rows do). Raises for a row that does not, because a cursor built
  from the wrong row shape would be a silently wrong position.
  """
  @spec encode(binary, map) :: binary
  def encode(sort, group) when is_map(group) and not is_struct(group) do
    sort
    |> keys()
    |> Enum.map_join(@separator, fn {name, _direction, type} ->
      case Map.fetch(group, name) do
        {:ok, value} -> encode_value(name, type, value)
        :error -> raise ArgumentError, "group row #{inspect(group)} is missing #{inspect(name)}"
      end
    end)
  end

  @doc """
  Parses one cursor for one order: `{:ok, nil}` for the absent or blank
  start of the order, `{:ok, position}` for a canonical position, and
  `{:error, :before}` for everything else, including a sort this module does
  not publish.
  """
  @spec parse(binary | nil, binary | nil | term) :: {:ok, t | nil} | {:error, :before}
  def parse(sort, value) do
    case sort_keys(sort) do
      nil -> {:error, :before}
      keys -> parse_keys(keys, value)
    end
  end

  defp parse_keys(_keys, nil), do: {:ok, nil}
  defp parse_keys(_keys, ""), do: {:ok, nil}

  defp parse_keys(keys, value) when is_binary(value) do
    fields = String.split(value, @separator)

    if length(fields) == length(keys) do
      fields
      |> Enum.zip(keys)
      |> Enum.reduce_while({:ok, %{}}, fn {field, {name, _direction, type}}, {:ok, acc} ->
        case parse_value(type, field) do
          {:ok, parsed} -> {:cont, {:ok, Map.put(acc, name, parsed)}}
          {:error, :before} -> {:halt, {:error, :before}}
        end
      end)
    else
      {:error, :before}
    end
  end

  defp parse_keys(_keys, _other), do: {:error, :before}

  defp sort_keys(sort) do
    if sort in Triage.Inventory.group_sorts() do
      case sort do
        "severity" ->
          [{:severity_rank, :desc, :rank}, {:images, :desc, :count}, {:cve, :asc, :text}]

        "newest" ->
          [{:first_seen, :desc, :timestamp}, {:cve, :asc, :text}]

        "last_seen" ->
          [{:last_seen, :desc, :timestamp}, {:cve, :asc, :text}]

        "occurrences" ->
          [{:occurrences, :desc, :count}, {:cve, :asc, :text}]

        "cve" ->
          [{:cve, :asc, :text}]

        _other ->
          nil
      end
    end
  end

  defp encode_value(_name, :rank, value)
       when is_integer(value) and value >= 0 and value <= @max_rank,
       do: Integer.to_string(value)

  defp encode_value(_name, :count, value) when is_integer(value) and value >= 0,
    do: Integer.to_string(value)

  defp encode_value(_name, :timestamp, %DateTime{} = value), do: DateTime.to_iso8601(value)

  defp encode_value(_name, :text, value) when is_binary(value) do
    case parse_value(:text, value) do
      {:ok, text} -> text
      {:error, :before} -> raise ArgumentError, "invalid advisory id #{inspect(value)}"
    end
  end

  defp encode_value(name, type, value) do
    raise ArgumentError,
          "invalid #{inspect(type)} cursor field #{inspect(name)}: #{inspect(value)}"
  end

  defp parse_value(:rank, field) do
    case canonical_integer(field) do
      {:ok, n} when n >= 0 and n <= @max_rank -> {:ok, n}
      _other -> {:error, :before}
    end
  end

  defp parse_value(:count, field) do
    case canonical_integer(field) do
      {:ok, n} when n >= 0 and n <= @max_count -> {:ok, n}
      _other -> {:error, :before}
    end
  end

  defp parse_value(:timestamp, field) do
    case DateTime.from_iso8601(field) do
      # Only the canonical whole-second UTC form is accepted. An offset that
      # is not zero, fractional seconds this order never produces, or a value
      # that does not re-encode to exactly what arrived is rejected rather
      # than normalized into a different position.
      {:ok, datetime, 0} ->
        if DateTime.to_iso8601(datetime) == field and datetime.microsecond == {0, 0},
          do: {:ok, datetime},
          else: {:error, :before}

      _other ->
        {:error, :before}
    end
  end

  defp parse_value(:text, field) do
    cond do
      field == "" -> {:error, :before}
      not String.valid?(field) -> {:error, :before}
      Regex.match?(@unsafe_text, field) -> {:error, :before}
      String.contains?(field, @separator) -> {:error, :before}
      String.trim(field) != field -> {:error, :before}
      String.length(field) > @max_text -> {:error, :before}
      true -> {:ok, field}
    end
  end

  # Canonical digits only: no sign, no whitespace, no leading zeros, and no
  # more digits than a positive int8 can hold.
  defp canonical_integer(field) do
    if Regex.match?(@canonical_integer, field) do
      case Integer.parse(field) do
        {n, ""} -> {:ok, n}
        _other -> {:error, :before}
      end
    else
      {:error, :before}
    end
  end
end
