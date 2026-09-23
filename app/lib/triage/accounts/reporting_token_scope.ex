defmodule Triage.Accounts.ReportingTokenScope do
  use Ecto.Schema
  import Ecto.Changeset

  schema "reporting_api_token_scopes" do
    field :team, :string
    field :environment, :string
    belongs_to :token, Triage.Accounts.ReportingToken
    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(scope, attrs) do
    scope
    |> cast(attrs, [:token_id, :team, :environment])
    |> update_change(:team, &String.trim/1)
    |> update_change(:environment, &String.trim/1)
    |> validate_required([:token_id, :team, :environment])
    |> validate_length(:team, min: 1, max: 120)
    |> validate_length(:environment, min: 1, max: 120)
    |> foreign_key_constraint(:token_id)
    |> unique_constraint([:token_id, :team, :environment],
      name: :reporting_api_token_scope_identity
    )
    |> check_constraint(:team, name: :reporting_scope_team_not_blank)
    |> check_constraint(:environment, name: :reporting_scope_environment_not_blank)
  end
end
