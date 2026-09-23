defmodule Triage.Classifier.Event do
  @moduledoc "Append-only classifier pause/resume and safety incident audit."
  use Ecto.Schema

  schema "classifier_events" do
    field :action, :string
    field :actor_id, :integer
    field :run_id, :integer
    field :reason, :string
    timestamps(type: :utc_datetime)
  end
end
