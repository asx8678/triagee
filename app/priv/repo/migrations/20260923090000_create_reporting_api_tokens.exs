defmodule Triage.Repo.Migrations.CreateReportingApiTokens do
  use Ecto.Migration

  def change do
    create table(:reporting_api_tokens) do
      add :token_hash, :binary, null: false
      add :user_id, references(:account_users, on_delete: :delete_all), null: false
      add :label, :string, size: 120, null: false
      add :all_scopes, :boolean, default: false, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :revoked_at, :utc_datetime_usec
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create unique_index(:reporting_api_tokens, [:token_hash])
    create index(:reporting_api_tokens, [:user_id])
    create index(:reporting_api_tokens, [:expires_at])

    create constraint(:reporting_api_tokens, :reporting_token_label_not_blank,
             check: "btrim(label) <> ''"
           )

    create table(:reporting_api_token_scopes) do
      add :token_id, references(:reporting_api_tokens, on_delete: :delete_all), null: false
      add :team, :string, size: 120, null: false
      add :environment, :string, size: 120, null: false
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create unique_index(:reporting_api_token_scopes, [:token_id, :team, :environment],
             name: :reporting_api_token_scope_identity
           )

    create constraint(:reporting_api_token_scopes, :reporting_scope_team_not_blank,
             check: "btrim(team) <> ''"
           )

    create constraint(:reporting_api_token_scopes, :reporting_scope_environment_not_blank,
             check: "btrim(environment) <> ''"
           )
  end
end
