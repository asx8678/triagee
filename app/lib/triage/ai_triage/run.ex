defmodule Triage.AiTriage.Run do
  @moduledoc "Persisted Kiro input and classification, independent of a browser connection."
  use Ecto.Schema

  schema "review_classifications" do
    field :cve, :string
    field :scope, :map
    field :scope_key, :string
    field :identity, :string
    field :evidence_hash, :string
    field :profile, :string
    field :requested_by, :integer
    field :state, :string, default: "queued"
    field :input, :map
    field :result, :map, default: %{}
    field :error, :string
    field :started_at, :utc_datetime
    field :finished_at, :utc_datetime
    timestamps(type: :utc_datetime)
  end
end
