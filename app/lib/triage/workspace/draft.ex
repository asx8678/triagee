defmodule Triage.Workspace.Draft do
  use Ecto.Schema

  schema "workspace_drafts" do
    belongs_to :user, Triage.Accounts.User
    field :cve, :string
    field :fields, :map
    field :targets, {:array, :integer}
    field :versions, :map
    field :operation_id, Ecto.UUID
    field :revision, :integer, default: 0
    timestamps(type: :utc_datetime_usec)
  end
end
