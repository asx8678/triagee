defmodule Triage.Repo.Migrations.AddAiClassificationExperiment do
  use Ecto.Migration

  def up do
    Oban.Migration.up(version: 12)

    create table(:classifier_evidence) do
      add :identity, :text, null: false
      add :cve, :text, null: false
      add :placement_id, :bigint, null: false
      add :packet_hash, :text, null: false
      add :workload_uid, :text, null: false
      add :snapshot, :map, null: false
      add :approved_by, references(:account_users), null: false
      add :observed_at, :utc_datetime, null: false
      add :expires_at, :utc_datetime, null: false
      timestamps(type: :utc_datetime)
    end

    create unique_index(:classifier_evidence, [:identity])

    create table(:classifier_runs) do
      add :evidence_id, references(:classifier_evidence), null: false
      add :profile, :text, null: false
      add :model, :text, null: false
      add :state, :text, null: false, default: "queued"
      add :control_revision, :integer
      add :input, :map, null: false, default: %{}
      add :prompt_version, :text
      add :policy_version, :text
      add :raw, :map, null: false, default: %{}
      add :suggestion, :text
      add :guard_reasons, {:array, :text}, null: false, default: []
      add :unsafe, :boolean, null: false, default: false
      add :started_at, :utc_datetime
      add :finished_at, :utc_datetime
      timestamps(type: :utc_datetime)
    end

    create unique_index(:classifier_runs, [:evidence_id, :profile])
    create index(:classifier_runs, [:state])

    create table(:classifier_feedback) do
      add :evidence_id, references(:classifier_evidence), null: false
      add :run_id, references(:classifier_runs)
      add :reviewer_id, references(:account_users), null: false
      add :mode, :text, null: false
      add :rating, :text
      add :classification, :text, null: false
      add :reason, :text, null: false
      add :effort_seconds, :integer, null: false
      add :dangerous, :boolean, null: false, default: false
      timestamps(type: :utc_datetime)
    end

    create unique_index(:classifier_feedback, [:run_id], where: "run_id IS NOT NULL")
    create unique_index(:classifier_feedback, [:evidence_id, :reviewer_id, :mode])

    create constraint(:classifier_feedback, :positive_effort,
             check: "effort_seconds BETWEEN 1 AND 14400"
           )

    create table(:classifier_controls) do
      add :paused, :boolean, null: false, default: false
      add :revision, :integer, null: false, default: 1
      add :reason, :text, null: false
      timestamps(type: :utc_datetime)
    end

    execute "INSERT INTO classifier_controls (id, paused, revision, reason, inserted_at, updated_at) VALUES (1, false, 1, 'Initial state; runtime remains default-off', now(), now())"

    create table(:classifier_events) do
      add :action, :text, null: false
      add :actor_id, references(:account_users)
      add :run_id, references(:classifier_runs)
      add :reason, :text, null: false
      timestamps(type: :utc_datetime)
    end
  end

  def down do
    drop table(:classifier_events)
    drop table(:classifier_feedback)
    drop table(:classifier_runs)
    drop table(:classifier_evidence)
    drop table(:classifier_controls)
    Oban.Migration.down(version: 1)
  end
end
