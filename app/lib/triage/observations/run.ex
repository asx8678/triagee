defmodule Triage.Observations.Run do
  @moduledoc """
  One immutable offline ingestion of a normalized collection report.

  `identity_kind` is only `content_fallback`. `status_marker` is observational
  and is never a scan id or a source time. Fetch time and ingest time are
  distinct columns.
  """

  use Ecto.Schema
  import Ecto.Changeset

  schema "source_runs" do
    field :source, :string
    field :scope_key, :string
    field :identity_kind, :string
    field :identity, :string
    field :status_marker, :string
    field :source_observed_at, :utc_datetime
    field :fetched_at, :utc_datetime
    field :ingested_at, :utc_datetime
    field :paging_contract, :string
    field :complete, :boolean, default: false
    field :blockers, {:array, :string}, default: []
    field :counts, :map, default: %{}
    field :content_hash, :string
    field :query_version, :string
    field :environment, :string
    field :engine, :string

    timestamps(type: :utc_datetime)
  end

  def changeset(run, attrs) do
    run
    |> cast(attrs, [
      :source,
      :scope_key,
      :identity_kind,
      :identity,
      :status_marker,
      :source_observed_at,
      :fetched_at,
      :ingested_at,
      :paging_contract,
      :complete,
      :blockers,
      :counts,
      :content_hash,
      :query_version,
      :environment,
      :engine
    ])
    |> validate_required([
      :source,
      :scope_key,
      :identity_kind,
      :identity,
      :fetched_at,
      :ingested_at,
      :paging_contract,
      :complete,
      :blockers,
      :counts,
      :content_hash,
      :query_version,
      :environment,
      :engine
    ])
    |> unique_constraint([:source, :scope_key, :identity], name: :source_runs_identity_index)
  end
end
