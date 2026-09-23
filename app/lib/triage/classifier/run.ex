defmodule Triage.Classifier.Run do
  @moduledoc "A durable analysis intent and its immutable terminal result; not an approval."
  use Ecto.Schema

  schema "classifier_runs" do
    belongs_to :evidence, Triage.Classifier.Evidence
    field :profile, :string
    field :model, :string
    field :state, :string, default: "queued"
    field :control_revision, :integer
    field :input, :map, default: %{}
    field :prompt_version, :string
    field :policy_version, :string
    field :raw, :map, default: %{}
    field :suggestion, :string
    field :guard_reasons, {:array, :string}, default: []
    field :unsafe, :boolean, default: false
    field :started_at, :utc_datetime
    field :finished_at, :utc_datetime
    timestamps(type: :utc_datetime)
  end
end
