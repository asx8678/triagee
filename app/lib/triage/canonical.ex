defmodule Triage.Canonical do
  @moduledoc """
  Deterministic, versioned encoding for values persisted through hashes.

  Workspace evidence fingerprints, decision request hashes, draft fingerprints
  and ticket payload hashes are stored in PostgreSQL and compared on later
  reads, so they must outlive the BEAM that computed them. Default
  `term_to_binary/1` orders small maps by the running VM's atom table, which
  differs between startups: identical evidence then hashes differently, and
  unchanged decisions, drafts and retries silently stop matching.

  This encoding is a pure function of the logical value:

    * maps and structs sort their entries by encoded key, so neither map
      iteration order nor atom creation order can influence the result;
    * atoms encode by name, never by identity;
    * every variable-width scalar carries its byte length, so encodings are
      self-delimiting and distinct values cannot splice into one another;
    * timestamps always carry six fractional digits, so the SQL twin of this
      encoding can reproduce the text byte for byte.

  Change `@version` only together with a migration for every persisted hash;
  values hashed under different versions are not comparable.
  """

  @version "triage.canonical.v1"

  @doc "The version prefix hashed into every value. Bump only with a migration."
  @spec version() :: String.t()
  def version, do: @version

  @doc "Lowercase SHA-256 hex of the versioned canonical encoding of `value`."
  @spec hash(term()) :: String.t()
  def hash(value) do
    :crypto.hash(:sha256, version() <> "|" <> canonical(value))
    |> Base.encode16(case: :lower)
  end

  @doc "The canonical encoding itself. Public so callers can pin its shape."
  @spec canonical(term()) :: binary()

  def canonical(nil), do: "n"
  def canonical(true), do: "t"
  def canonical(false), do: "f"

  def canonical(value) when is_integer(value) do
    digits = Integer.to_string(value)
    "i" <> Integer.to_string(byte_size(digits)) <> ":" <> digits
  end

  def canonical(value) when is_float(value) do
    digits = :erlang.float_to_binary(value, [:short])
    "g" <> Integer.to_string(byte_size(digits)) <> ":" <> digits
  end

  def canonical(value) when is_binary(value),
    do: "s" <> Integer.to_string(byte_size(value)) <> ":" <> value

  def canonical(value) when is_atom(value) do
    name = Atom.to_string(value)
    "a" <> Integer.to_string(byte_size(name)) <> ":" <> name
  end

  def canonical(%Date{} = value), do: "d" <> Date.to_iso8601(value)

  def canonical(%Time{} = value), do: "o" <> format_time(value)

  def canonical(%DateTime{} = value), do: "w" <> format_datetime(value)

  def canonical(%NaiveDateTime{} = value), do: "v" <> format_naive_datetime(value)

  def canonical(value) when is_list(value),
    do: "l[" <> Enum.map_join(value, ",", &canonical/1) <> "]"

  def canonical(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.map_join(",", &canonical/1) |> then(&("p[" <> &1 <> "]"))

  def canonical(value) when is_map(value) do
    # :maps.to_list/1, not Enum: Elixir 1.20 no longer lets Enum enumerate
    # arbitrary structs, and hashed values legitimately contain them. Structs
    # keep their __struct__ => module entry, so equal structs encode equally.
    "m{" <>
      (value
       |> :maps.to_list()
       |> Enum.map(fn {key, item} -> canonical(key) <> "=" <> canonical(item) end)
       |> Enum.sort()
       |> Enum.join(",")) <>
      "}"
  end

  def canonical(value) do
    raise ArgumentError,
          "no canonical encoding for #{inspect(value, limit: 8)}: hash only plain data"
  end

  # Fixed-width timestamps: always six fractional digits so the matching SQL
  # expressions reproduce the text exactly. DateTime shifts to UTC first.
  defp format_datetime(%DateTime{time_zone: "Etc/UTC"} = value),
    do:
      timestamp(
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        elem(value.microsecond, 0),
        "Z"
      )

  defp format_datetime(%DateTime{} = value) do
    value
    |> DateTime.to_naive()
    |> NaiveDateTime.add(-(value.utc_offset + value.std_offset))
    |> format_naive_datetime()
    |> then(&(&1 <> "Z"))
  end

  defp format_naive_datetime(%NaiveDateTime{} = value),
    do:
      timestamp(
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        elem(value.microsecond, 0),
        ""
      )

  defp format_time(%Time{} = value) do
    :io_lib.format("~2..0B:~2..0B:~2..0B.~6..0B", [
      value.hour,
      value.minute,
      value.second,
      elem(value.microsecond, 0)
    ])
    |> IO.iodata_to_binary()
  end

  defp timestamp(year, month, day, hour, minute, second, microsecond, suffix) do
    :io_lib.format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B.~6..0B", [
      year,
      month,
      day,
      hour,
      minute,
      second,
      microsecond
    ])
    |> IO.iodata_to_binary()
    |> then(&(&1 <> suffix))
  end
end
