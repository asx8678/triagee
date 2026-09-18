defmodule Triage.GuidedReview.Query do
  @moduledoc "Bounded CVE-keyset reads for guided review; individual advisory scopes are never truncated."
  import Ecto.Query
  alias Triage.{Decisions, Exposure, Intel, Repo, Risk}
  alias Triage.GuidedReview.Request
  alias Triage.Inventory.{Finding, Image, ImagePlacement}

  alias Triage.GuidedReview.{Candidates, PageOptions}
  @max_page_size 100

  @doc """
  Traverses candidates by descending review priority then ascending CVE.
  The opaque next_after_cve token binds the last rank/CVE to the filters.
  Covered/ticketed candidates are removed after bounded hydration, so an empty
  page may still have a continuation. Scopes are never truncated by filters.
  Ordering is stable for unchanged evidence; restart when live risk changes.
  """
  def page(opts \\ []) do
    with {:ok, cursor, limit, filters} <- PageOptions.parse(opts) do
      candidates =
        active_scopes()
        |> Candidates.query(filters, DateTime.utc_now())
        |> subquery()
        |> after_position(cursor)
        |> order_by([c], desc: c.rank, asc: c.cve)
        |> limit(^(limit + 1))
        |> Repo.all()

      selected = Enum.take(candidates, limit)
      cves = Enum.map(selected, & &1.cve)
      positions = cves |> Enum.with_index() |> Map.new()
      more? = length(candidates) > limit

      {:ok,
       %{
         rows: load(cves) |> Enum.sort_by(&Map.fetch!(positions, &1.cve)),
         has_more?: more?,
         next_after_cve:
           if(more?, do: PageOptions.encode(List.last(selected), filters), else: nil)
       }}
    end
  end

  @doc "Loads only the requested CVE, independently of queue pagination."
  def get(cve) when is_binary(cve) do
    if valid_cursor?(cve), do: List.first(load([cve])), else: nil
  end

  def get(_), do: nil

  @doc "Actionable rows for an already bounded caller selection (e.g. timeline lanes)."
  def actionable_for(cves) do
    cves |> Enum.uniq() |> Enum.chunk_every(@max_page_size) |> Enum.flat_map(&load/1)
  end

  defp valid_cursor?(value) when is_binary(value) do
    byte_size(value) in 1..200 and String.valid?(value) and not String.contains?(value, <<0>>)
  end

  defp after_position(query, nil), do: query

  defp after_position(query, %{rank: rank, cve: cve}),
    do: where(query, [c], c.rank < ^rank or (c.rank == ^rank and c.cve > ^cve))

  defp active_scopes do
    from(f in Finding,
      join: p in ImagePlacement,
      on: p.image_id == f.image_id and p.active,
      where: is_nil(f.resolved_at) and not f.suppressed
    )
  end

  defp load([]), do: []

  defp load(cves) do
    scopes =
      active_scopes()
      |> where([f], f.cve in ^cves)
      |> join(:inner, [f], i in Image, on: i.id == f.image_id)
      |> order_by([f, p], asc: f.cve, asc: p.owner, asc: p.id, asc: f.id)
      |> select([f, p, i], %{finding: f, placement: p, image: i})
      |> Repo.all()

    now = DateTime.utc_now()
    exposure = Exposure.current_by_placement(Enum.map(scopes, & &1.placement.id), now)
    decisions = Decisions.latest_by_scope(cves, now)
    kev = Intel.kev_index(cves)

    rows =
      scopes
      |> Enum.group_by(& &1.finding.cve)
      |> Enum.map(fn {cve, items} ->
        build_row(cve, items, exposure, decisions, Map.has_key?(kev, cve))
      end)

    requests = current_requests(rows)

    rows
    |> Enum.map(&with_requests(&1, requests))
    |> Enum.filter(&(&1.pending != []))
    |> Enum.sort_by(& &1.cve)
  end

  defp build_row(cve, scopes, exposure, decisions, known_exploited?) do
    items = Enum.map(scopes, &decorate_scope(&1, exposure, decisions, known_exploited?))

    teams =
      items
      |> Enum.reject(& &1.covered?)
      |> Enum.group_by(& &1.placement.owner)
      |> Enum.map(fn {owner, team_items} ->
        %{owner: owner, scopes: team_items, scope_key: scope_key(team_items), request: nil}
      end)
      |> Enum.sort_by(& &1.owner)

    %{
      cve: cve,
      scopes: items,
      teams: teams,
      descriptions:
        items
        |> Enum.map(& &1.finding.description)
        |> Enum.reject(&(&1 in [nil, ""]))
        |> Enum.uniq(),
      risk: Risk.aggregate(Enum.map(items, & &1.risk)),
      first_seen:
        items
        |> Enum.map(& &1.finding.first_seen)
        |> Enum.reject(&is_nil/1)
        |> Enum.min(DateTime, fn -> nil end)
    }
  end

  defp decorate_scope(item, exposure, decisions, known_exploited?) do
    exposed = Map.get(exposure, item.placement.id, "unknown")

    Map.merge(item, %{
      exposure: exposed,
      covered?:
        not is_nil(Decisions.covering_decision(decisions, item.finding.cve, item.placement.id)),
      risk:
        Risk.classify(%{
          severity: item.finding.severity,
          exposure: exposed,
          known_exploited: known_exploited?,
          fix_available: not is_nil(item.finding.fix)
        })
    })
  end

  defp current_requests(rows) do
    keys = Enum.flat_map(rows, fn row -> Enum.map(row.teams, & &1.scope_key) end)
    cves = Enum.map(rows, & &1.cve)

    from(r in Request, where: r.cve in ^cves and r.scope_key in ^keys)
    |> Repo.all()
    |> Map.new(&{{&1.cve, &1.owner, &1.scope_key}, &1})
  end

  defp with_requests(row, requests) do
    teams =
      Enum.map(row.teams, fn team ->
        %{team | request: Map.get(requests, {row.cve, team.owner, team.scope_key})}
      end)

    row
    |> Map.put(:teams, teams)
    |> Map.put(:pending, Enum.reject(teams, &(&1.request && &1.request.status == "created")))
  end

  defp scope_key(items) do
    items
    |> Enum.map(&{&1.finding.id, &1.finding.reopen_count, &1.placement.id, &1.finding.first_seen})
    |> Enum.sort()
    |> :erlang.term_to_binary()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end
end
