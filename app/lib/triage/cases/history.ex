defmodule Triage.Cases.History do
  @moduledoc "Bounded, batched history previews; full records remain available through Cases.get_case/1."
  import Ecto.Query
  alias Triage.Cases.{CaseEvent, EvidenceSnapshot, Review}
  alias Triage.Repo

  @stream_limit 25
  @review_fields ~w(id case_id snapshot_id inserted_at actor applicability priority next_action rationale)a
  @event_fields ~w(id case_id inserted_at kind actor case_revision snapshot_id review_id detail)a

  @spec stream_limit() :: pos_integer()
  def stream_limit, do: @stream_limit

  @doc "Up to 25 recent assessments and 25 audit events per already-scoped case; no evidence payloads or tokens."
  @spec previews([map()]) :: map()
  def previews([]), do: %{}

  def previews(cases) do
    ids = Enum.map(cases, & &1.id)
    reviews = latest(Review, @review_fields, ids)
    events = latest(CaseEvent, @event_fields, ids)
    snapshot_ids = reviews |> Enum.map(& &1.snapshot_id) |> Enum.uniq()

    snapshots =
      from(s in EvidenceSnapshot,
        where: s.id in ^snapshot_ids,
        select: %{id: s.id, case_id: s.case_id, version: s.version}
      )
      |> Repo.all()
      |> Enum.group_by(& &1.case_id)

    reviews = Enum.group_by(reviews, & &1.case_id)
    events = Enum.group_by(events, & &1.case_id)

    Map.new(cases, fn cse ->
      case_reviews = Map.get(reviews, cse.id, [])
      case_events = Map.get(events, cse.id, [])

      {cse.id,
       %{
         case: cse,
         snapshots: Map.get(snapshots, cse.id, []),
         reviews: Enum.take(case_reviews, @stream_limit),
         events: Enum.take(case_events, @stream_limit),
         history_truncated?:
           length(case_reviews) > @stream_limit or length(case_events) > @stream_limit
       }}
    end)
  end

  # Rank in SQL, not after loading all histories. The textual id tiebreak
  # preserves CaseLive.Format.timeline_entries/1 ordering within each stream.
  defp latest(schema, fields, ids) do
    ranked =
      from(r in schema,
        where: r.case_id in ^ids,
        windows: [
          per_case: [
            partition_by: r.case_id,
            order_by: [desc: r.inserted_at, asc: fragment("?::text", r.id)]
          ]
        ],
        select: %{id: r.id, position: over(row_number(), :per_case)}
      )

    fetch_limit = @stream_limit + 1

    from(r in schema,
      join: rank in subquery(ranked),
      on: rank.id == r.id,
      where: rank.position <= ^fetch_limit,
      order_by: [desc: r.inserted_at, asc: fragment("?::text", r.id)],
      select: map(r, ^fields)
    )
    |> Repo.all()
  end
end
