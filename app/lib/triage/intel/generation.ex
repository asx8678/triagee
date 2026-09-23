defmodule Triage.Intel.Generation do
  @moduledoc """
  One immutable, validated snapshot of a public-intelligence source (W01b).

  A generation is written once and never edited. The rows of every generation
  remain readable as cited history; only the generation named by
  `intel_current_generations` serves current reads. Failure paths never reach
  this table — they append a refresh receipt and leave the pointer alone.

  `complete` is true only when the refresh validated the source's own
  completeness contract (for KEV: the declared catalogue count matched the
  entries actually parsed). A generation written through the low-level
  compatibility API is `complete: false` — stored, but never reported as a
  certified refresh.

  `started_at` is when the refresh attempt began, not when it finished: an
  older attempt that completes last cannot displace a newer valid generation.
  """

  use Ecto.Schema
  import Ecto.Changeset

  schema "intel_generations" do
    field :source, :string
    field :content_hash, :string
    field :row_count, :integer
    field :declared_count, :integer
    field :complete, :boolean, default: false
    field :catalog_version, :string
    field :metadata, :map, default: %{}
    field :started_at, :utc_datetime
    field :fetched_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  @type t :: %__MODULE__{}

  def changeset(generation, attrs) do
    generation
    |> cast(attrs, [
      :source,
      :content_hash,
      :row_count,
      :declared_count,
      :complete,
      :catalog_version,
      :metadata,
      :started_at,
      :fetched_at
    ])
    |> validate_required([:source, :content_hash, :row_count, :started_at, :fetched_at])
    |> validate_number(:row_count, greater_than_or_equal_to: 0)
  end
end
