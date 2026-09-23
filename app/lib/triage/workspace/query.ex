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
  alias Triage.Workspace.TargetSQL

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
        else: "attention ASC, severity DESC, priority DESC NULLS LAST, cve COLLATE \"C\""

    """
    WITH #{TargetSQL.ctes()}, matching AS (
      SELECT * FROM scored WHERE text_match AND severity_match AND
        CASE $4::text
          WHEN 'all' THEN true
          WHEN 'history' THEN NOT active
          WHEN 'needs' THEN active AND NOT covered
          WHEN 'urgent' THEN active AND priority = 4
          WHEN 'unknown' THEN active AND exposure = 'unknown'
          WHEN 'fixed' THEN covered AND decision = 'fixed'
          WHEN 'accepted' THEN active AND covered AND decision = 'accepted_risk'
          WHEN 'progress' THEN active AND covered AND decision IN ('request_remediation', 'investigate', 'request_verification', 'create_ticket')
            AND NOT (decision_expires_at IS NOT NULL AND decision_expires_at <= ($3::timestamp + interval '7 days'))
          ELSE active
        END
    ), rows AS (
      SELECT cve, max(severity) AS severity, max(priority) AS priority, min(first_seen) AS first_seen,
        min(attention) AS attention
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
end
