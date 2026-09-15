defmodule Triage.Repo.Migrations.AddDecisionsAndImpactEvidence do
  use Ecto.Migration

  def change do
    create table(:advisory_decisions) do
      add :cve, :text, null: false
      add :placement_id, references(:image_placements, on_delete: :delete_all)
      add :decision, :text, null: false
      add :reason, :text, null: false
      add :actor, :text, null: false
      add :decided_at, :utc_datetime, null: false
      add :expires_at, :utc_datetime
      add :supersedes_id, references(:advisory_decisions, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create index(:advisory_decisions, [:cve, :decided_at])
    create index(:advisory_decisions, [:placement_id])
    create index(:advisory_decisions, [:supersedes_id])

    create table(:placement_impact_evidences) do
      add :placement_id, references(:image_placements, on_delete: :delete_all), null: false
      add :impact, :text, null: false
      add :source, :text, null: false
      add :observed_at, :utc_datetime, null: false
      add :expires_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:placement_impact_evidences, [:placement_id])
  end
end
