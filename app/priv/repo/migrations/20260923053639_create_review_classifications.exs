defmodule Triage.Repo.Migrations.CreateReviewClassifications do
  use Ecto.Migration

  def change do
    create table(:review_classifications) do
      add :cve, :text, null: false
      add :scope, :map, null: false
      add :scope_key, :text, null: false
      add :identity, :text, null: false
      add :evidence_hash, :text, null: false
      add :profile, :text, null: false
      add :requested_by, references(:account_users, on_delete: :restrict), null: false
      add :state, :text, null: false, default: "queued"
      add :input, :map, null: false
      add :result, :map, null: false, default: %{}
      add :error, :text
      add :started_at, :utc_datetime
      add :finished_at, :utc_datetime
      timestamps(type: :utc_datetime)
    end

    create index(:review_classifications, [:cve, :scope_key, :id])

    create unique_index(:review_classifications, [:identity],
             where: "state IN ('queued', 'running')",
             name: :review_classifications_pending_identity
           )

    create constraint(:review_classifications, :review_classification_state,
             check: "state IN ('queued', 'running', 'completed', 'failed', 'stale')"
           )
  end
end
