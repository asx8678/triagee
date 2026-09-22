defmodule Triage.Workspace.Query do
  @moduledoc """
  Database-side target reduction and CVE pagination. Only the selected CVE IDs,
  scalar metric counts and team counts cross the database boundary. Evidence is
  subsequently hydrated by Workspace for those CVEs, never limited mid-target.

  Aggregation still scans the scoped estate, and OFFSET is not a keyset cursor.
  Hash-bound decisions cost a database-side evidence hash; no application-wide
  evidence cache, temporary tables or write-through projection is involved.
  """
  alias Triage.{Repo, Workspace}
  alias Triage.Workspace.EvidenceSQL

  @page_size 50

  def page(params, now) do
    # Keep IDs, counts and their hydration on one snapshot during concurrent
    # imports/decisions. Callers already in a transaction own its isolation.
    # SQL.Sandbox owns an outer database transaction even when Ecto reports no
    # application transaction. Its checkout controls isolation, not this reader.
    if Repo.in_transaction?() or Repo.config()[:pool] == Ecto.Adapters.SQL.Sandbox do
      read_page(params, now)
    else
      {:ok, page} =
        Repo.transaction(fn ->
          Repo.query!("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
          read_page(params, now)
        end)

      page
    end
  end

  defp read_page(params, now) do
    mode = params["mode"] || if(params["page"] == "review", do: "needs", else: "active")
    offset = offset(params["offset"])
    result = query_result(params, mode, offset, now)
    ids = result["ids"]
    item = params["item"] || if(params["page"] == "review", do: result["first"])

    hydrate_ids = Enum.uniq(Enum.reject(ids ++ [item, params["inspect"]], &is_nil/1))
    scope = Map.take(params, ~w(team environment))
    targets = Workspace.targets(Map.put(scope, "cves", hydrate_ids), now)
    matching = targets |> Workspace.select(mode) |> filter_text(params)
    rows_by_cve = matching |> Workspace.rows() |> Map.new(&{&1.cve, &1})
    page_rows = Enum.map(ids, &Map.fetch!(rows_by_cve, &1))
    row = targets |> Enum.filter(&(&1.cve == item)) |> Workspace.rows() |> List.first()

    inspector_source =
      if params["page"] == "inventory" and mode in ["unknown", "urgent"],
        do: matching,
        else: targets

    inspect_targets = Enum.filter(inspector_source, &(&1.cve == params["inspect"]))

    %{
      page_rows: page_rows,
      total: result["total"],
      metrics: metrics(result["metrics"]),
      teams: Enum.map(result["teams"], &%{name: &1["name"], metrics: metrics(&1)}),
      options: Workspace.options(),
      mode: mode,
      offset: offset,
      item: item,
      row: row,
      targets: targets,
      matching: matching,
      inspector: inspect_targets |> Workspace.rows() |> List.first(),
      inspector_targets: inspect_targets
    }
  end

  defp query_result(params, mode, offset, now) do
    args = [
      params["team"] || "",
      params["environment"] || "",
      DateTime.to_naive(now),
      mode,
      String.downcase(params["q"] || ""),
      params["severity"] || "",
      String.split(params["batch"] || "", ",", trim: true),
      offset,
      @page_size
    ]

    [[result]] = Repo.query!(sql(params["sort"]), args).rows
    result
  end

  defp metrics(values), do: Map.new(~w(active needs urgent unknown), &{&1, %{value: values[&1]}})

  defp offset(value) when is_binary(value) do
    case Integer.parse(value) do
      {n, ""} when n >= 0 and n <= 1_000_000 -> n
      _ -> 0
    end
  end

  defp offset(_), do: 0

  # This repeats only the bounded target predicate, never the estate projection.
  # A match keeps ALL packages in the target, including nonmatching evidence.
  defp filter_text(targets, params) do
    query = String.downcase(params["q"] || "")

    Enum.filter(targets, fn t ->
      text = Enum.join([t.cve, t.image.repository | Enum.map(t.findings, & &1.package_name)], " ")

      String.contains?(String.downcase(text), query) and
        (params["severity"] in [nil, ""] or
           Enum.any?(t.findings, &(&1.severity == params["severity"])))
    end)
  end

  @doc false
  def sql(sort) do
    order =
      if sort == "age",
        do: "first_seen, cve COLLATE \"C\"",
        else: "severity DESC, priority DESC NULLS LAST, cve COLLATE \"C\""

    """
    WITH target_facts AS (
      SELECT f.cve, p.id, p.image_id,
        CASE WHEN p.owner IS NULL OR p.owner IN ('', '(unknown)', 'unassigned')
          THEN '__unassigned__' ELSE p.owner END AS team,
        bool_or(f.resolved_at IS NULL) AND p.active AS active,
        max(#{severity("f.severity")}) AS severity,
        max(CASE WHEN f.resolved_at IS NULL THEN #{priority()} END) AS priority,
        min(f.first_seen) AS first_seen,
        coalesce(e.exposure, 'unknown') AS exposure,
        strpos(lower(f.cve || ' ' || coalesce(i.repository, '') || ' ' ||
          string_agg(coalesce(f.package_name, ''), ' ' ORDER BY f.id)), $5::text) > 0 AS text_match,
        ($6::text = '' OR bool_or(f.severity = $6::text)) AS severity_match
      FROM findings f
      JOIN image_placements p ON p.image_id = f.image_id
      JOIN images i ON i.id = f.image_id
      LEFT JOIN LATERAL (
        SELECT CASE WHEN x.expires_at < $3::timestamp THEN 'unknown' ELSE x.exposure END AS exposure
        FROM exposure_evidences x WHERE x.placement_id = p.id
        ORDER BY x.observed_at DESC, x.id DESC LIMIT 1
      ) e ON true
      WHERE (p.owner IS NULL OR p.owner <> 'public-reference')
        AND (p.environment IS NULL OR p.environment <> 'not-a-deployment')
        AND NOT coalesce(i.repository = 'public-reference/nvd-catalogue' AND
          i.tag = 'reference' AND starts_with(i.description, 'NVD PUBLIC REFERENCE — '), false)
        AND ($1::text = '' OR
          ($1 = '__unassigned__' AND (p.owner IS NULL OR p.owner IN ('', '(unknown)', 'unassigned', '__unassigned__')))
          OR p.owner = $1)
        AND ($2::text = '' OR p.environment = $2)
      GROUP BY f.cve, p.id, i.repository, e.exposure
    ), targets AS (
      SELECT t.*,
        d.decision,
        coalesce(
          (d.expires_at IS NULL OR d.expires_at > $3::timestamp OR
            (d.expires_at = $3::timestamp AND coalesce(d.metadata->>'expiry_boundary', '') <> 'exclusive'))
          AND d.id IS NOT NULL AND
          CASE WHEN NOT t.active THEN true
            WHEN d.metadata->>'evidence_hash' IS NULL THEN true
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
    ), matching AS (
      SELECT * FROM targets WHERE text_match AND severity_match AND
        CASE $4::text
          WHEN 'all' THEN true
          WHEN 'history' THEN NOT active
          WHEN 'needs' THEN active AND NOT covered
          WHEN 'urgent' THEN active AND priority = 4
          WHEN 'unknown' THEN active AND exposure = 'unknown'
          WHEN 'fixed' THEN covered AND decision = 'fixed'
          WHEN 'accepted' THEN active AND covered AND decision = 'accepted_risk'
          WHEN 'progress' THEN active AND covered AND decision IN ('request_remediation', 'investigate', 'request_verification', 'create_ticket')
          ELSE active
        END
    ), rows AS (
      SELECT cve, max(severity) AS severity, max(priority) AS priority, min(first_seen) AS first_seen
      FROM matching WHERE cardinality($7::text[]) = 0 OR cve = ANY($7::text[])
      GROUP BY cve
    ), page AS (
      SELECT * FROM rows ORDER BY #{order} LIMIT $9::integer OFFSET $8::integer
    ), metrics AS (
      SELECT #{counts()} FROM targets
    ), teams AS (
      SELECT team AS name, #{counts()} FROM targets GROUP BY team
      HAVING count(*) FILTER (WHERE active) > 0
    )
    SELECT jsonb_build_object(
      'ids', coalesce((SELECT jsonb_agg(cve ORDER BY #{order}) FROM page), '[]'::jsonb),
      'first', (SELECT cve FROM rows ORDER BY #{order} LIMIT 1),
      'total', (SELECT count(*) FROM rows),
      'metrics', (SELECT to_jsonb(metrics) FROM metrics),
      'teams', coalesce((SELECT jsonb_agg(to_jsonb(teams) ORDER BY name COLLATE "C") FROM teams), '[]'::jsonb)
    )
    """
  end

  defp counts do
    """
    count(DISTINCT cve) FILTER (WHERE active) AS active,
    count(DISTINCT cve) FILTER (WHERE active AND NOT covered) AS needs,
    count(DISTINCT cve) FILTER (WHERE active AND priority = 4) AS urgent,
    count(*) FILTER (WHERE active AND exposure = 'unknown') AS unknown
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
    # String.trim/1 uses Unicode White_Space, not just ASCII spaces. Avoid E'\\v'
    # (PostgreSQL treats that escape as the literal letter v).
    whitespace =
      [9, 10, 11, 12, 13, 32, 133, 160, 5760] ++
        Enum.to_list(8192..8202) ++
        [8232, 8233, 8239, 8287, 12_288]

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
