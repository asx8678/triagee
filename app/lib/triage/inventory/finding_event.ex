defmodule Triage.Inventory.FindingEvent do
  use Ecto.Schema
  import Ecto.Changeset

  # No association back to Finding on purpose: lifecycle events are queried
  # explicitly so the event log stays append-only and independent.
  schema "finding_events" do
    field :finding_id, :integer
    field :event, :string
    field :occurred_at, :utc_datetime
    field :note, :string

    timestamps(type: :utc_datetime)
  end

  def changeset(event, attrs) do
    event
    |> cast(attrs, [:finding_id, :event, :occurred_at, :note])
    |> validate_required([:finding_id, :event, :occurred_at])
    |> validate_inclusion(:event, ~w(appeared resolved reopened))
  end
end
