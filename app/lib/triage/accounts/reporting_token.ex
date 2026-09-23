defmodule Triage.Accounts.ReportingToken do
  use Ecto.Schema
  import Ecto.Changeset

  @derive {Inspect, except: [:token_hash]}
  schema "reporting_api_tokens" do
    field :token_hash, :binary, redact: true
    field :label, :string
    field :all_scopes, :boolean, default: false
    field :expires_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec
    belongs_to :user, Triage.Accounts.User
    has_many :scopes, Triage.Accounts.ReportingTokenScope, foreign_key: :token_id
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(token, attrs) do
    token
    |> cast(attrs, [:user_id, :token_hash, :label, :all_scopes, :expires_at, :revoked_at])
    |> update_change(:label, &String.trim/1)
    |> validate_required([:user_id, :token_hash, :label, :all_scopes, :expires_at])
    |> validate_length(:label, min: 1, max: 120)
    |> foreign_key_constraint(:user_id)
    |> unique_constraint(:token_hash)
    |> check_constraint(:label, name: :reporting_token_label_not_blank)
  end
end
