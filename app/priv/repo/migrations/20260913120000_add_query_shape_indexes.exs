defmodule Triage.Repo.Migrations.AddQueryShapeIndexes do
  @moduledoc """
  Indexes for the predicates and orders the read paths actually use, plus the
  removal of two single-column indexes that a wider index now covers.

  This migration changes no query result. Each index only lets the planner
  satisfy an existing predicate or sort from the index instead of reading the
  table; the predicates and orders named below are the ones in
  `Triage.Inventory`, `Triage.Exposure` and `Triage.Intel`, so the index list
  and the query list can be compared side by side.
  """

  use Ecto.Migration

  def change do
    # `Triage.Inventory.filtered_findings/1` (advisory groups) and the
    # same-CVE occurrence lookups in `occurrence_base/3` and `fetch_finding/2`
    # all read the open set only, so this index is partial on exactly that
    # predicate: it stays proportional to open findings, not to all history.
    create index(:findings, [:cve], where: "resolved_at IS NULL", name: :findings_open_cve_index)

    # Placement listings order by [owner, namespace, environment, id]
    # (`Triage.Inventory.fetch_finding/2`, `Triage.Activity.placements/1`).
    create index(:image_placements, [:owner, :namespace, :environment, :id])

    # The What's New rail orders by published_at DESC, fetched_at DESC, id DESC
    # (`Triage.Intel.recent_news/1`): an all-descending order that a plain
    # ascending index still serves by backward scan.
    create index(:news_items, [:published_at, :fetched_at, :id])

    # `Triage.Intel.latest_receipts/0` reads DISTINCT ON (source) ORDER BY
    # source, attempted_at DESC. The wider index serves every source-only
    # lookup the narrower one served, so this replaces a duplicate path to the
    # same rows instead of adding one.
    drop index(:intel_refresh_receipts, [:source])
    create index(:intel_refresh_receipts, [:source, :attempted_at])

    # `Triage.Exposure.current_by_placement/2` reads DISTINCT ON (placement_id)
    # ORDER BY placement_id, observed_at DESC, id DESC. Same replacement: the
    # placement_id prefix covers reads that only selected the placement.
    drop index(:exposure_evidences, [:placement_id])
    create index(:exposure_evidences, [:placement_id, :observed_at, :id])
  end
end
