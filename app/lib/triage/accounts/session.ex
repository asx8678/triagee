defmodule Triage.Accounts.Session do
  use Ecto.Schema

  @primary_key {:token_hash, :binary, autogenerate: false}
  schema "account_sessions" do
    belongs_to :user, Triage.Accounts.User
    field :expires_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end
end
