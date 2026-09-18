defmodule Triage.GuidedReview.Candidates do
  @moduledoc "Database-ranked, bounded candidates. Filters select CVEs, never truncate their scopes."
  import Ecto.Query
  alias Triage.{Exposure, Intel}
  alias Triage.Inventory.Image

  # Mirrors Risk policy v1; exhaustive SQL/classifier parity is tested.
  @base "CASE upper(btrim(?)) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 2 END"

  def query(active, filters, now) do
    latest =
      from e in Exposure.Evidence,
        distinct: e.placement_id,
        order_by: [asc: e.placement_id, desc: e.observed_at, desc: e.id]

    kev =
      from a in Intel.Advisory,
        where: a.source == "kev",
        distinct: true,
        select: %{cve: a.external_id}

    scopes =
      from [f, p] in active,
        join: i in Image,
        on: i.id == f.image_id,
        left_join: e in subquery(latest),
        on: e.placement_id == p.id,
        left_join: k in subquery(kev),
        on: k.cve == f.cve,
        select: %{
          cve: f.cve,
          owner: p.owner,
          package: f.package_name,
          repository: i.repository,
          severity: fragment("upper(btrim(?))", f.severity),
          base: fragment(@base, f.severity),
          kev: not is_nil(k.cve),
          exposure:
            fragment(
              "CASE WHEN ? IS NULL OR ? < ? THEN 'unknown' ELSE ? END",
              e.id,
              e.expires_at,
              ^now,
              e.exposure
            )
        }

    matching = scopes |> subquery() |> filter(filters) |> select([s], s.cve)

    from s in subquery(scopes),
      where: s.cve in subquery(matching),
      group_by: s.cve,
      select: %{
        cve: s.cve,
        rank:
          max(
            fragment(
              "CASE WHEN ? OR ? = 'internet_exposed' THEN CASE WHEN ? >= 3 THEN 4 ELSE 3 END ELSE ? END",
              s.kev,
              s.exposure,
              s.base,
              s.base
            )
          )
      }
  end

  defp filter(query, filters) do
    Enum.reduce(filters, query, fn
      {_key, ""}, q -> q
      {:team, value}, q -> where(q, [s], s.owner == ^value)
      {:severity, value}, q -> where(q, [s], s.severity == ^value)
      {:exposure, value}, q -> where(q, [s], s.exposure == ^value)
      {:kev, "yes"}, q -> where(q, [s], s.kev)
      {:kev, "no"}, q -> where(q, [s], not s.kev)
      {:q, value}, q -> search(q, String.downcase(value))
    end)
  end

  # strpos provides literal substring matching: % and _ are not wildcards.
  defp search(query, value) do
    where(
      query,
      [s],
      fragment("strpos(lower(?), ?) > 0", s.cve, ^value) or
        fragment("strpos(lower(?), ?) > 0", s.package, ^value) or
        fragment("strpos(lower(?), ?) > 0", s.repository, ^value)
    )
  end
end
