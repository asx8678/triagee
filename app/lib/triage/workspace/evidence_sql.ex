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

  @doc """
  The v1 evidence hash (placement, image digest, findings only). Kept because
  stored decisions carry it and work requests still bind to it; it cannot
  express exposure or intelligence change, so it is never a current approval.
  """
  def term_sql do
    "'p[' || #{placement_sql()} || ',' || #{string("i.digest")} || ',' || #{findings_sql()} || ']'"
  end

  @doc """
  SQL for the pre-packet dismissal policy: under the default `:flag` a legacy
  dismissal keeps covering while its own v1 hash is absent or still matches;
  under `:demote` it never covers. Mirrors `Triage.Evidence.legacy_policy/0`.
  """
  def legacy_dismissal_sql do
    if Triage.Evidence.legacy_policy() == :demote do
      "false"
    else
      "(coalesce(d.metadata->>'evidence_hash', '') = '' OR d.metadata->>'evidence_hash' = #{hash_sql()})"
    end
  end

  @doc """
  The v2 packet hash, byte-identical to `Triage.Evidence.Packet.hash/1`:
  a two-tuple of the hash domain and the material map (version, cve, placement,
  digest, findings, material exposure, material intelligence).
  """
  def packet_hash_sql,
    do: "encode(sha256(convert_to('#{version()}|' || #{packet_term_sql()}, 'UTF8')), 'hex')"

  @doc false
  def packet_term_sql do
    domain = literal(Triage.Canonical.canonical(Triage.Evidence.Packet.hash_domain()))
    version = literal(Triage.Canonical.canonical(Triage.Evidence.Packet.version()))

    material =
      map_sql(%{
        "version" => version,
        "cve" => string("t.cve"),
        "placement" => placement_sql(),
        "image_digest" => string("i.digest"),
        "findings" => findings_sql(),
        "exposure" => exposure_material_sql(),
        "intel" => intel_material_sql()
      })

    "'p[' || #{domain} || ',' || #{material} || ']'"
  end

  # Material exposure mirrors Triage.Evidence.Packet.exposure_material/1: the
  # validity class plus the displayed value, never observation timestamps.
  defp exposure_material_sql do
    map_sql(%{
      "state" => string("coalesce(t.exposure_state, 'none')"),
      "value" => string("coalesce(t.exposure, 'unknown')")
    })
  end

  # Material intelligence mirrors intel_material/1: per-CVE KEV facts only, so
  # an unrelated advisory changing elsewhere does not invalidate an approval.
  defp intel_material_sql do
    map_sql(%{
      "kev" => boolean("coalesce(t.kev_present, false)"),
      "ransomware" => boolean("t.kev_ransomware"),
      "due_date" => datetime("t.kev_due_date"),
      "required_action" => boolean("coalesce(t.kev_required_action, false)")
    })
  end

  defp placement_sql do
    map_sql(%{
      id: integer("p.id"),
      image_id: integer("p.image_id"),
      owner: string("p.owner"),
      environment: string("p.environment"),
      namespace: string("p.namespace"),
      active: boolean("p.active")
    })
  end

  defp findings_sql do
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
    """
    (SELECT 'l[' || coalesce(string_agg(#{finding}, ',' ORDER BY hf.id), '') || ']'
       FROM findings hf WHERE hf.image_id = p.image_id AND hf.cve = t.cve)
    """
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
