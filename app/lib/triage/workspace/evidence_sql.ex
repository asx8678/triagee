defmodule Triage.Workspace.EvidenceSQL do
  @moduledoc """
  SQL encoding of the workspace evidence hash.

  `Triage.Workspace.hash/1` hashes `Triage.Canonical`'s versioned, VM-state-free
  encoding, so identical evidence hashes identically in any BEAM. These
  expressions rebuild exactly that encoding from PostgreSQL — atom keys as
  name literals, map entries sorted by encoded key, length-prefixed scalars
  and fixed-width timestamps — so a database-side hash matches the
  application-side hash for the same row without hydrating evidence. Only the
  small, fixed evidence maps are encoded; no functions or extensions beyond
  `sha256`, `convert_to` and `to_char` are required, and nothing is written.
  """

  @doc false
  def hash_sql,
    do: "encode(sha256(convert_to('#{version()}|' || #{term_sql()}, 'UTF8')), 'hex')"

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
        reopen_count: integer("hf.reopen_count"),
        first_seen: datetime("hf.first_seen"),
        suppressed: boolean("hf.suppressed")
      })

    # Elixir sorts a target's findings by id before hashing; a target always
    # has at least one finding, and the coalesce keeps an empty list encodable.
    findings = """
    (SELECT 'l[' || coalesce(string_agg(#{finding}, ',' ORDER BY hf.id), '') || ']'
       FROM findings hf WHERE hf.image_id = p.image_id AND hf.cve = t.cve)
    """

    "'p[' || #{placement} || ',' || #{string("i.digest")} || ',' || #{findings} || ']'"
  end

  # Map entries sort by their encoded keys, mirroring Triage.Canonical: the
  # scalar encodings are self-delimiting, so key order decides entry order.
  defp map_sql(fields) do
    body =
      fields
      |> Enum.sort_by(fn {key, _expression} -> Triage.Canonical.canonical(key) end)
      |> Enum.map_join(" || ',' || ", fn {key, expression} ->
        literal(Triage.Canonical.canonical(key)) <> " || '=' || " <> expression
      end)

    "'m{' || " <> body <> " || '}'"
  end

  defp literal(text), do: "'#{String.replace(text, "'", "''")}'"

  defp version, do: String.replace(Triage.Canonical.version(), "'", "''")

  defp nullable(column, expression),
    do: "(CASE WHEN #{column} IS NULL THEN 'n' ELSE #{expression} END)"

  # The server encoding is UTF-8, so the column text already is the byte
  # sequence Triage.Canonical hashes; convert_to() would return bytea, which
  # concatenates as hex-escaped text instead of the raw bytes.
  defp string(column) do
    nullable(column, "'s' || octet_length(#{column})::text || ':' || #{column}")
  end

  defp boolean(column), do: nullable(column, "(CASE WHEN #{column} THEN 't' ELSE 'f' END)")

  defp integer(column),
    do: nullable(column, "'i' || length((#{column})::text)::text || ':' || (#{column})::text")

  # Matches Triage.Canonical's fixed six-digit-microsecond UTC format exactly.
  defp datetime(column),
    do: nullable(column, "'w' || to_char(#{column}, 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
end
