defmodule Triage.Reporting.Query do
  @moduledoc false

  alias Triage.{Repo, Workspace}
  alias Triage.Workspace.TargetSQL

  @statement_timeout_ms 2_000

  def snapshot(fun) when is_function(fun, 0) do
    if Repo.in_transaction?() or Repo.config()[:pool] == Ecto.Adapters.SQL.Sandbox do
      fun.()
    else
      {:ok, result} =
        Repo.transaction(fn ->
          Repo.query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
          Repo.query!("SET LOCAL statement_timeout = '#{@statement_timeout_ms}ms'")
          fun.()
        end)

      result
    end
  end

  def summary(filters, access, now) do
    sql = """
    #{scope_ctes()}
    , matched_cves AS (
      SELECT DISTINCT cve FROM authorized
      WHERE active AND text_match AND severity_match
    ), eligible AS (
      SELECT authorized.* FROM authorized
      JOIN matched_cves USING (cve)
      WHERE active
    ), decorated AS (
      SELECT *,
        active AND covered AND decision = 'accepted_risk' AS whitelisted,
        active AND NOT covered AS needs_decision,
        active AND attention IN (0, 1) AS needs_attention,
        active AND covered AND decision = 'not_affected' AS not_affected,
        active AND covered AND decision = 'fixed' AS reported_fixed,
        active AND covered AND decision = 'accepted_risk' AND decision_expires_at IS NOT NULL
          AND decision_expires_at <= ($3::timestamp + interval '#{Triage.Attention.review_lead_days()} days') AS expiring_whitelist,
        active AND covered AND decision IN ('accepted_risk', 'fixed', 'not_affected')
          AND coalesce(decision_metadata->>'packet_hash', '') = '' AS legacy_flagged
      FROM eligible
    ), per_cve AS (
      SELECT cve,
        count(*) FILTER (WHERE active) AS active_targets,
        count(*) FILTER (WHERE whitelisted) AS whitelisted_targets,
        bool_or(needs_decision) AS needs_decision,
        bool_or(needs_attention) AS needs_attention
      FROM decorated GROUP BY cve HAVING count(*) FILTER (WHERE active) > 0
    )
    SELECT jsonb_build_object(
      'active_cves', (SELECT count(*) FROM per_cve),
      'active_targets', (SELECT count(*) FROM decorated WHERE active),
      'needs_decision_cves', (SELECT count(*) FROM per_cve WHERE needs_decision),
      'needs_attention_cves', (SELECT count(*) FROM per_cve WHERE needs_attention),
      'fully_whitelisted_cves', (SELECT count(*) FROM per_cve WHERE active_targets > 0 AND active_targets = whitelisted_targets),
      'partially_whitelisted_cves', (SELECT count(*) FROM per_cve WHERE whitelisted_targets > 0 AND whitelisted_targets < active_targets),
      'whitelisted_targets', (SELECT count(*) FROM decorated WHERE whitelisted),
      'expiring_whitelist_targets', (SELECT count(*) FROM decorated WHERE expiring_whitelist),
      'not_affected_targets', (SELECT count(*) FROM decorated WHERE not_affected),
      'reported_fixed_targets', (SELECT count(*) FROM decorated WHERE reported_fixed),
      'unknown_exposure_targets', (SELECT count(*) FROM decorated WHERE active AND exposure = 'unknown'),
      'legacy_flagged_targets', (SELECT count(*) FROM decorated WHERE legacy_flagged),
      'breakdown_truncated', jsonb_build_object(
        'teams', (SELECT count(*) FROM (
          SELECT team FROM decorated WHERE active GROUP BY team
        ) team_dimensions) > 100,
        'environments', (SELECT count(*) FROM (
          SELECT environment FROM decorated WHERE active GROUP BY environment
        ) environment_dimensions) > 100
      ),
      'by_severity', coalesce((
        SELECT jsonb_agg(to_jsonb(x) ORDER BY x.severity DESC) FROM (
          SELECT severity, count(DISTINCT cve) AS cves, count(*) AS targets
          FROM decorated WHERE active GROUP BY severity
        ) x
      ), '[]'::jsonb),
      'by_team', coalesce((
        SELECT jsonb_agg(to_jsonb(x) ORDER BY x.team COLLATE "C") FROM (
          SELECT team, count(DISTINCT cve) AS cves, count(*) AS targets,
            count(*) FILTER (WHERE whitelisted) AS whitelisted_targets
          FROM decorated WHERE active GROUP BY team
          ORDER BY team COLLATE "C" LIMIT 100
        ) x
      ), '[]'::jsonb),
      'by_environment', coalesce((
        SELECT jsonb_agg(to_jsonb(x) ORDER BY x.environment COLLATE "C") FROM (
          SELECT environment, count(DISTINCT cve) AS cves, count(*) AS targets,
            count(*) FILTER (WHERE whitelisted) AS whitelisted_targets
          FROM decorated WHERE active GROUP BY environment
          ORDER BY environment COLLATE "C" LIMIT 100
        ) x
      ), '[]'::jsonb)
    )
    """

    query_json(sql, base_args(filters, access, now))
  end

  def cves(filters, access, now, cursor) do
    after_cve = if cursor, do: cursor["cve"] || cursor[:cve], else: ""

    sql = """
    #{scope_ctes()}
    , matched_cves AS (
      SELECT DISTINCT cve FROM authorized
      WHERE active AND text_match AND severity_match
        AND ($11::text = '' OR cve = $11::text)
    ), eligible AS (
      SELECT authorized.* FROM authorized
      JOIN matched_cves USING (cve)
      WHERE active
    ), per_cve AS (
      SELECT cve, max(severity) AS severity, max(priority) AS priority,
        min(first_seen) AS first_seen, max(last_seen) AS last_seen,
        count(*) AS active_targets,
        count(*) FILTER (WHERE covered AND decision = 'accepted_risk') AS whitelisted_targets,
        count(*) FILTER (WHERE NOT covered) AS needs_decision_targets,
        count(*) FILTER (WHERE attention IN (0, 1)) AS needs_attention_targets
      FROM eligible GROUP BY cve
    ), selected AS (
      SELECT *, CASE
        WHEN active_targets = 0 THEN 'not_applicable'
        WHEN whitelisted_targets = 0 THEN 'none'
        WHEN whitelisted_targets = active_targets THEN 'full'
        ELSE 'partial' END AS whitelist_coverage
      FROM per_cve
    ), filtered AS (
      SELECT * FROM selected
      WHERE ($12::text = '' OR whitelist_coverage = $12::text)
    ), page AS (
      SELECT * FROM filtered
      WHERE ($9::text = '' OR cve COLLATE "C" > $9::text COLLATE "C")
      ORDER BY cve COLLATE "C" LIMIT $10::integer
    )
    SELECT jsonb_build_object(
      'total', (SELECT count(*) FROM filtered),
      'rows', coalesce((SELECT jsonb_agg(to_jsonb(page) ORDER BY cve COLLATE "C") FROM page), '[]'::jsonb)
    )
    """

    args =
      base_args(filters, access, now) ++
        [after_cve, filters.limit + 1, filters.cve, filters.whitelist_coverage]

    query_json(sql, args)
  end

  def target_keys(filters, access, now, cursor) do
    {after_cve, after_id} =
      if cursor,
        do: {cursor["cve"] || cursor[:cve], cursor["placement_id"] || cursor[:placement_id]},
        else: {"", 0}

    sql = """
    #{scope_ctes()}
    , decorated AS (
      SELECT *,
        active AND covered AND decision = 'accepted_risk' AS whitelisted,
        active AND NOT covered AS needs_decision,
        active AND attention IN (0, 1) AS needs_attention
      FROM authorized WHERE text_match AND severity_match
        AND ($12::text = '' OR cve = $12::text)
    ), filtered AS (
      SELECT * FROM decorated WHERE
        ($13::boolean IS NULL OR active = $13::boolean) AND
        ($14::boolean IS NULL OR whitelisted = $14::boolean) AND
        ($15::boolean IS NULL OR needs_decision = $15::boolean) AND
        ($16::boolean IS NULL OR needs_attention = $16::boolean) AND
        ($17::integer IS NULL OR (whitelisted AND decision_expires_at IS NOT NULL AND
          decision_expires_at <= ($3::timestamp + ($17::integer * interval '1 day'))))
    ), page AS (
      SELECT cve, id FROM filtered
      WHERE ($9::text = '' OR (cve COLLATE "C", id) > ($9::text COLLATE "C", $10::bigint))
      ORDER BY cve COLLATE "C", id LIMIT $11::integer
    )
    SELECT jsonb_build_object(
      'total', (SELECT count(*) FROM filtered),
      'rows', coalesce((SELECT jsonb_agg(to_jsonb(page) ORDER BY cve COLLATE "C", id) FROM page), '[]'::jsonb)
    )
    """

    args =
      base_args(filters, access, now) ++
        [
          after_cve,
          after_id,
          filters.limit + 1,
          filters.cve,
          filters.active,
          filters.whitelisted,
          filters.needs_decision,
          filters.needs_attention,
          filters.expires_within_days
        ]

    query_json(sql, args)
  end

  def hydrate_targets(keys, now) do
    cves = Enum.map(keys, & &1["cve"]) |> Enum.uniq()
    ids = Enum.map(keys, & &1["id"]) |> Enum.uniq()

    targets = Workspace.targets(%{"cves" => cves, "placement_ids" => ids}, now)
    by_key = Map.new(targets, &{{&1.cve, &1.id}, &1})
    Enum.map(keys, &Map.fetch!(by_key, {&1["cve"], &1["id"]}))
  end

  def packages(filters, access, cursor) do
    after_id = if cursor, do: cursor["finding_id"] || cursor[:finding_id], else: 0
    {grants, all?} = grants(access)

    sql = """
    WITH eligible AS (
      SELECT f.id, f.package_name, f.package_version, f.severity, f.fix,
        f.suppressed, f.first_seen, f.last_seen, f.resolved_at
      FROM findings f
      JOIN image_placements p ON p.image_id = f.image_id
      JOIN images i ON i.id = f.image_id
      WHERE f.cve = $1::text AND p.id = $2::bigint
        AND (p.owner IS NULL OR p.owner <> 'public-reference')
        AND (p.environment IS NULL OR p.environment <> 'not-a-deployment')
        AND NOT coalesce(i.repository = 'public-reference/nvd-catalogue' AND i.tag = 'reference'
          AND starts_with(i.description, 'NVD PUBLIC REFERENCE — '), false)
        AND ($6::boolean OR EXISTS (
          SELECT 1 FROM jsonb_array_elements($5::jsonb) AS grant_row
          WHERE grant_row->>'team' = CASE WHEN p.owner IS NULL OR p.owner IN ('', '(unknown)', 'unassigned')
            THEN '__unassigned__' ELSE p.owner END
            AND grant_row->>'environment' = coalesce(p.environment, '')
        ))
        AND ($7::text = '' OR (CASE WHEN p.owner IS NULL OR p.owner IN ('', '(unknown)', 'unassigned')
          THEN '__unassigned__' ELSE p.owner END) = $7::text)
        AND ($8::text = '' OR p.environment = $8::text)
    ), page AS (
      SELECT * FROM eligible WHERE id > $3::bigint ORDER BY id LIMIT $4::integer
    )
    SELECT jsonb_build_object(
      'total', (SELECT count(*) FROM eligible),
      'rows', coalesce((SELECT jsonb_agg(to_jsonb(page) ORDER BY id) FROM page), '[]'::jsonb)
    )
    """

    query_json(sql, [
      filters.cve,
      filters.placement_id,
      after_id,
      filters.limit + 1,
      grants,
      all?,
      filters.team,
      filters.environment
    ])
  end

  def options(filters, access, cursor) do
    after_pair =
      if cursor,
        do: {cursor["team"] || cursor[:team], cursor["environment"] || cursor[:environment]},
        else: {"", ""}

    {grants, all?} = grants(access)

    sql = """
    WITH eligible AS (
      SELECT DISTINCT
        CASE WHEN p.owner IS NULL OR p.owner IN ('', '(unknown)', 'unassigned')
          THEN '__unassigned__' ELSE p.owner END AS team,
        p.environment
      FROM findings f
      JOIN image_placements p ON p.image_id = f.image_id
      JOIN images i ON i.id = f.image_id
      WHERE p.active AND f.resolved_at IS NULL
        AND (p.owner IS NULL OR p.owner <> 'public-reference')
        AND (p.environment IS NULL OR p.environment <> 'not-a-deployment')
        AND NOT coalesce(i.repository = 'public-reference/nvd-catalogue' AND i.tag = 'reference'
          AND starts_with(i.description, 'NVD PUBLIC REFERENCE — '), false)
        AND ($2::boolean OR EXISTS (
          SELECT 1 FROM jsonb_array_elements($1::jsonb) AS grant_row
          WHERE grant_row->>'team' = CASE WHEN p.owner IS NULL OR p.owner IN ('', '(unknown)', 'unassigned')
            THEN '__unassigned__' ELSE p.owner END
            AND grant_row->>'environment' = coalesce(p.environment, '')
        ))
        AND ($3::text = '' OR strpos(lower(coalesce(p.owner, '') || ' ' || coalesce(p.environment, '')), $3::text) > 0)
    ), page AS (
      SELECT * FROM eligible
      WHERE ($4::text = '' OR (team COLLATE "C", environment COLLATE "C") > ($4::text COLLATE "C", $5::text COLLATE "C"))
      ORDER BY team COLLATE "C", environment COLLATE "C" LIMIT $6::integer
    )
    SELECT coalesce(jsonb_agg(to_jsonb(page) ORDER BY team COLLATE "C", environment COLLATE "C"), '[]'::jsonb) FROM page
    """

    query_json(sql, [
      grants,
      all?,
      String.downcase(filters.q),
      elem(after_pair, 0),
      elem(after_pair, 1),
      filters.limit + 1
    ])
  end

  defp scope_ctes do
    """
    WITH #{TargetSQL.ctes()}, authorized AS (
      SELECT s.* FROM scored s WHERE $4::text = 'all' AND ($8::boolean OR EXISTS (
        SELECT 1 FROM jsonb_array_elements($7::jsonb) AS grant_row
        WHERE grant_row->>'team' = s.team
          AND grant_row->>'environment' = coalesce(s.environment, '')
      ))
    )
    """
  end

  defp base_args(filters, access, now) do
    {grants, all?} = grants(access)

    [
      filters.team,
      filters.environment,
      DateTime.to_naive(now),
      "all",
      String.downcase(filters.q),
      filters.severity,
      grants,
      all?
    ]
  end

  defp grants(%{grants: :all}), do: {[], true}

  defp grants(%{grants: scopes}) do
    grants =
      Enum.map(scopes, fn {team, environment} -> %{team: team, environment: environment} end)

    {grants, false}
  end

  defp query_json(sql, args) do
    case Repo.query!(sql, args, timeout: @statement_timeout_ms).rows do
      [[value]] -> value
      other -> raise "unexpected reporting query result: #{inspect(other)}"
    end
  end
end
