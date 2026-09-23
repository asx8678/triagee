defmodule Triage.Classifier.Feedback do
  @moduledoc "Human experiment feedback and self-reported active effort, never a final security action."
  use Ecto.Schema

  schema "classifier_feedback" do
    field :evidence_id, :integer
    field :run_id, :integer
    field :reviewer_id, :integer
    field :mode, :string
    field :rating, :string
    field :classification, :string
    field :reason, :string
    field :effort_seconds, :integer
    field :dangerous, :boolean, default: false
    timestamps(type: :utc_datetime)
  end
end
