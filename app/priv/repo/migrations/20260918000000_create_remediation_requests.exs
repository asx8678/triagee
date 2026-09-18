defmodule Triage.Repo.Migrations.CreateRemediationRequests do
  use Ecto.Migration

  def change do
    create table(:remediation_requests) do
      add :cve, :text, null: false
      add :owner, :text, null: false
      add :scope_key, :text, null: false
      add :status, :text, null: false, default: "planned"
      add :payload, :map, null: false
      add :ticket_id, :integer
      add :ticket_url, :text
      add :error, :text
      add :actor, :text, null: false
      timestamps(type: :utc_datetime)
    end

    create unique_index(:remediation_requests, [:cve, :owner, :scope_key])

    create constraint(:remediation_requests, :remediation_status,
             check: "status IN ('planned', 'sending', 'created', 'failed', 'unknown')"
           )
  end
end
