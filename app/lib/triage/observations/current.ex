defmodule Triage.Observations.Current do
  @moduledoc """
  Current pointer for one fixture source and scope. Moves only for a strictly
  newer explicit source time. A replay or a nil/older time cannot rewind it.
  """

  use Ecto.Schema
  import Ecto.Changeset

  schema "source_run_currents" do
    field :source, :string
    field :scope_key, :string
    belongs_to :source_run, Triage.Observations.Run
    field :source_observed_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  def changeset(current, attrs) do
    current
    |> cast(attrs, [:source, :scope_key, :source_run_id, :source_observed_at])
    |> validate_required([:source, :scope_key, :source_run_id])
    |> unique_constraint([:source, :scope_key], name: :source_run_currents_scope_index)
  end
end
