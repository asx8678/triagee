defmodule Triage.Repo.Migrations.CreateAccountsSessionsAndWorkspaceDrafts do
  use Ecto.Migration

  def change do
    create table(:account_users) do
      add :email, :string, size: 120, null: false
      add :role, :string, null: false
      add :enabled, :boolean, default: true, null: false
      add :password_hash, :binary, null: false
      add :password_salt, :binary, null: false
      add :password_rounds, :integer, null: false
      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:account_users, [:email])

    create constraint(:account_users, :account_role,
             check: "role IN ('viewer', 'reviewer', 'admin')"
           )

    create constraint(:account_users, :password_cost, check: "password_rounds >= 600000")

    create table(:account_sessions, primary_key: false) do
      add :token_hash, :binary, primary_key: true
      add :user_id, references(:account_users, on_delete: :delete_all), null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :revoked_at, :utc_datetime_usec
      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:account_sessions, [:user_id])
    create index(:account_sessions, [:expires_at])

    create table(:account_login_attempts, primary_key: false) do
      add :key, :string, primary_key: true
      add :window, :bigint, primary_key: true
      add :attempts, :integer, null: false
    end

    create index(:account_login_attempts, [:window])

    create table(:workspace_drafts) do
      add :user_id, references(:account_users, on_delete: :delete_all), null: false
      add :cve, :string, size: 40, null: false
      add :fields, :map, null: false
      add :targets, {:array, :bigint}, null: false
      add :versions, :map, null: false
      add :operation_id, :uuid, null: false
      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:workspace_drafts, [:user_id, :cve])
  end
end
