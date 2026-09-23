defmodule Triage.Workspace.TargetSQL do
  @moduledoc false

  alias Triage.Workspace.EvidenceSQL

  @doc "Shared current target facts used by the workspace and read-only reporting."
  def ctes do
    """
    target_facts AS (
      SELECT f.cve, p.id, p.image_id,
        CASE WHEN p.owner IS NULL OR p.owner IN ('', '(unknown)', 'unassigned')
          THEN '__unassigned__' ELSE p.owner END AS team,
        p.environment, p.namespace, i.digest AS image_digest,
        i.repository AS image_repository, i.tag AS image_tag,
        bool_or(f.resolved_at IS NULL) AND p.active AS active,
        max(#{severity("f.severity")}) AS severity,
        max(CASE WHEN f.resolved_at IS NULL THEN #{priority()} END) AS priority,
        min(f.first_seen) AS first_seen,
        max(f.last_seen) AS last_seen,
        count(DISTINCT f.id) AS finding_count,
        count(DISTINCT f.package_name) AS package_count,
        coalesce(e.exposure, 'unknown') AS exposure,
        e.state AS exposure_state,
        bool_or(k.present) AS kev_present,
        bool_or(k.required_action) AS kev_required_action,
        max(k.due_date) AS kev_due_date,
        bool_or(k.known_ransomware) AS kev_ransomware,
        strpos(lower(f.cve || ' ' || coalesce(i.repository, '') || ' ' ||
          string_agg(coalesce(f.package_name, ''), ' ' ORDER BY f.id)), $5::text) > 0 AS text_match,
        ($6::text = '' OR bool_or(f.severity = $6::text)) AS severity_match
      FROM findings f
      JOIN image_placements p ON p.image_id = f.image_id
      JOIN images i ON i.id = f.image_id
      LEFT JOIN LATERAL (
        SELECT s.state,
          CASE WHEN s.state = 'current' THEN s.exposure ELSE 'unknown' END AS exposure
        FROM (
          SELECT x.exposure,
            CASE
              WHEN x.expires_at < $3::timestamp THEN 'expired'
              WHEN x.observed_at > ($3::timestamp + interval '#{Triage.Exposure.Policy.clock_tolerance_seconds()} seconds') THEN 'future_dated'
              WHEN (SELECT count(DISTINCT y.exposure) FROM exposure_evidences y
                    WHERE y.placement_id = p.id AND y.observed_at = x.observed_at) > 1 THEN 'conflicting'
              ELSE 'current'
            END AS state
          FROM exposure_evidences x WHERE x.placement_id = p.id
          ORDER BY x.observed_at DESC, x.id DESC LIMIT 1
        ) s
      ) e ON true
      LEFT JOIN LATERAL (
        SELECT true AS present,
          (a.required_action IS NOT NULL) AS required_action,
          a.due_date,
          a.known_ransomware
        FROM intel_advisories a
        WHERE a.source = 'kev' AND a.external_id = f.cve
          AND (a.generation_id = (SELECT c.generation_id FROM intel_current_generations c WHERE c.source = 'kev')
               OR (a.generation_id IS NULL
                   AND NOT EXISTS (SELECT 1 FROM intel_current_generations c WHERE c.source = 'kev')))
        ORDER BY a.fetched_at DESC, a.id DESC LIMIT 1
      ) k ON true
      WHERE (p.owner IS NULL OR p.owner <> 'public-reference')
        AND (p.environment IS NULL OR p.environment <> 'not-a-deployment')
        AND NOT coalesce(i.repository = 'public-reference/nvd-catalogue' AND
          i.tag = 'reference' AND starts_with(i.description, 'NVD PUBLIC REFERENCE — '), false)
        AND ($1::text = '' OR
          ($1 = '__unassigned__' AND (p.owner IS NULL OR p.owner IN ('', '(unknown)', 'unassigned', '__unassigned__')))
          OR p.owner = $1)
        AND ($2::text = '' OR p.environment = $2)
      GROUP BY f.cve, p.id, i.repository, i.digest, i.tag, e.exposure, e.state
    ), targets AS (
      SELECT t.*,
        d.id AS decision_id, d.decision, d.decided_at,
        d.expires_at AS decision_expires_at, d.metadata AS decision_metadata,
        d.work_owner, d.due_on,
        coalesce(
          (d.expires_at IS NULL OR d.expires_at > $3::timestamp OR
            (d.expires_at = $3::timestamp AND coalesce(d.metadata->>'expiry_boundary', '') <> 'exclusive'))
          AND d.id IS NOT NULL AND
          CASE
            WHEN NOT t.active THEN true
            WHEN coalesce(d.metadata->>'packet_hash', '') <> ''
              THEN d.metadata->>'packet_hash' = #{EvidenceSQL.packet_hash_sql()}
            WHEN d.decision IN ('accepted_risk', 'fixed', 'not_affected')
              THEN #{EvidenceSQL.legacy_dismissal_sql()}
            WHEN coalesce(d.metadata->>'evidence_hash', '') = '' THEN true
            ELSE d.metadata->>'evidence_hash' = #{EvidenceSQL.hash_sql()} END,
          false) AS covered
      FROM target_facts t
      JOIN image_placements p ON p.id = t.id
      JOIN images i ON i.id = t.image_id
      LEFT JOIN LATERAL (
        SELECT d.* FROM advisory_decisions d
        WHERE d.cve = t.cve AND (d.placement_id IS NULL OR d.placement_id = t.id)
          AND d.decided_at <= $3::timestamp
        ORDER BY d.decided_at DESC, d.id DESC LIMIT 1
      ) d ON true
    ), scored AS (
      SELECT t.*,
        CASE
          WHEN NOT t.active THEN 4
          WHEN NOT t.covered THEN 0
          WHEN t.decision_expires_at IS NOT NULL AND t.decision_expires_at <= ($3::timestamp + interval '#{Triage.Attention.review_lead_days()} days') THEN 1
          WHEN t.covered AND t.decision = 'fixed' THEN 1
          WHEN t.covered AND t.decision IN ('investigate', 'request_remediation', 'request_verification', 'create_ticket') THEN 2
          ELSE 3
        END AS attention
      FROM targets t
    )
    """
  end

  defp severity(column) do
    clauses =
      Enum.map_join(
        Triage.Severity.order(),
        " ",
        &"WHEN '#{&1}' THEN #{Triage.Severity.rank(&1)}"
      )

    "CASE #{column} #{clauses} ELSE 0 END"
  end

  defp priority do
    whitespace =
      [9, 10, 11, 12, 13, 32, 133, 160, 5760] ++
        Enum.to_list(8192..8202) ++ [8232, 8233, 8239, 8287, 12_288]

    trim_chars = Enum.map_join(whitespace, " || ", &"chr(#{&1})")
    base = severity("upper(btrim(f.severity, #{trim_chars}))")

    """
    CASE WHEN EXISTS (SELECT 1 FROM intel_advisories k WHERE k.source = 'kev' AND k.external_id = f.cve)
      OR coalesce(e.exposure, 'unknown') = 'internet_exposed'
      THEN CASE WHEN (#{base}) >= 3 THEN 4 ELSE 3 END
      ELSE CASE WHEN (#{base}) = 0 THEN 2 ELSE (#{base}) END END
    """
  end
end
