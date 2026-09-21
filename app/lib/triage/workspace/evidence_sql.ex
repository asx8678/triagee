defmodule Triage.Workspace.EvidenceSQL do
  @moduledoc """
  SQL encoding of the existing workspace evidence fingerprint, not a new hash policy.

  Workspace hashes Erlang's external term format (ETF). Comparing JSON snapshots
  instead would miss reopen counts, accept forged hashes, and change legacy
  coverage. These expressions encode only the small, fixed maps used by that
  fingerprint. Constants (including atom encodings) come from the running VM;
  strings, integers and UTC second-precision timestamps come from PostgreSQL.
  No SQL functions/extensions or database writes are required.
  """

  @doc false
  def hash_sql, do: "encode(sha256(#{term_sql()}), 'hex')"

  @doc false
  def term_sql do
    placement =
      map_sql(%{
        id: integer("p.id"),
        image_id: integer("p.image_id"),
        owner: string("p.owner"),
        environment: string("p.environment"),
        namespace: string("p.namespace"),
        active: boolean("p.active")
      })

    finding =
      map_sql(%{
        id: integer("hf.id"),
        package_name: string("hf.package_name"),
        package_version: string("hf.package_version"),
        severity: string("hf.severity"),
        fix: string("hf.fix"),
        description: string("hf.description"),
        resolved_at: datetime("hf.resolved_at"),
        reopen_count: small_integer("hf.reopen_count"),
        first_seen: datetime("hf.first_seen"),
        suppressed: boolean("hf.suppressed")
      })

    # A target necessarily has at least one finding. The list tail is NIL_EXT.
    findings = """
    (SELECT decode('6c', 'hex') || int4send(count(*)::integer) ||
      string_agg(#{finding}, ''::bytea ORDER BY hf.id) || decode('6a', 'hex')
      FROM findings hf WHERE hf.image_id = p.image_id AND hf.cve = t.cve)
    """

    "(decode('836803', 'hex') || #{placement} || #{string("i.digest")} || #{findings})"
  end

  defp map_sql(fields) do
    body =
      fields
      # Default term_to_binary/1 uses the VM's native small-map key order,
      # not atom term order (Enum.sort/1). Keep that order for every map,
      # including DateTime; equal decoded terms alone do not imply equal hashes.
      |> :maps.to_list()
      |> Enum.flat_map(fn {key, expression} -> [constant(key), expression] end)

    "(" <> Enum.join([bytes(<<116, map_size(fields)::32>>) | body], " || ") <> ")"
  end

  defp constant(value) do
    <<131, body::binary>> = :erlang.term_to_binary(value)
    bytes(body)
  end

  defp bytes(value), do: "decode('#{Base.encode16(value, case: :lower)}', 'hex')"

  defp nullable(column, expression),
    do: "(CASE WHEN #{column} IS NULL THEN #{constant(nil)} ELSE #{expression} END)"

  defp string(column) do
    nullable(
      column,
      "decode('6d', 'hex') || int4send(octet_length(convert_to(#{column}, 'UTF8'))) || convert_to(#{column}, 'UTF8')"
    )
  end

  defp boolean(column) do
    nullable(column, "CASE WHEN #{column} THEN #{constant(true)} ELSE #{constant(false)} END")
  end

  defp integer(column) do
    # Positive bigint IDs can exceed INTEGER_EXT. ETF big digits are little-endian.
    big =
      for size <- 4..8 do
        digits =
          for index <- 0..(size - 1) do
            "set_byte(decode('00', 'hex'), 0, (((#{column})::bigint >> #{index * 8}) & 255)::integer)"
          end

        bound = Integer.pow(256, size) - 1

        "WHEN (#{column})::numeric <= #{bound} THEN #{bytes(<<110, size, 0>>)} || " <>
          Enum.join(digits, " || ")
      end

    nullable(column, """
    CASE WHEN (#{column}) BETWEEN 0 AND 255
      THEN set_byte(decode('6100', 'hex'), 1, (#{column})::integer)
    WHEN (#{column}) BETWEEN -2147483648 AND 2147483647
      THEN decode('62', 'hex') || int4send((#{column})::integer)
    ELSE CASE #{Enum.join(big, " ")} END END
    """)
  end

  defp datetime(column) do
    fields = %{
      __struct__: constant(DateTime),
      calendar: constant(Calendar.ISO),
      year: date_part(column, "year"),
      month: date_part(column, "month"),
      day: date_part(column, "day"),
      hour: date_part(column, "hour"),
      minute: date_part(column, "minute"),
      second: date_part(column, "second"),
      microsecond: constant({0, 0}),
      time_zone: constant("Etc/UTC"),
      zone_abbr: constant("UTC"),
      utc_offset: constant(0),
      std_offset: constant(0)
    }

    nullable(column, map_sql(fields))
  end

  defp small_integer(column) do
    nullable(column, """
    CASE WHEN (#{column}) BETWEEN 0 AND 255
      THEN set_byte(decode('6100', 'hex'), 1, (#{column})::integer)
      ELSE decode('62', 'hex') || int4send((#{column})::integer) END
    """)
  end

  defp date_part(column, part), do: small_integer("extract(#{part} from #{column})::integer")
end
