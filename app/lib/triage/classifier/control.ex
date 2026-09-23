defmodule Triage.Classifier.Control do
  @moduledoc "Persistent fail-closed experiment pause. Revision invalidates in-flight publication."
  use Ecto.Schema

  schema "classifier_controls" do
    field :paused, :boolean
    field :revision, :integer
    field :reason, :string
    timestamps(type: :utc_datetime)
  end
end
