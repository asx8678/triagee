defmodule Triage.Intel.CurrentGeneration do
  @moduledoc """
  The single validated generation each source currently serves (W01b).

  A pointer row is created on the first committed generation for a source and
  moved only by a strictly newer attempt (`started_at`). Sources without a
  pointer still read their pre-generation (legacy) rows, which is what keeps an
  existing installation working across the upgrade without re-certifying
  anything.
  """

  use Ecto.Schema

  schema "intel_current_generations" do
    field :source, :string, primary_key: true
    belongs_to :generation, Triage.Intel.Generation

    timestamps(type: :utc_datetime)
  end

  @type t :: %__MODULE__{}
end
