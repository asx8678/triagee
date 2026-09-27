defmodule Triage.Repo.Migrations.SourceRunsAndObservations do
  use Ecto.Migration

  def change do
    create table(:source_runs) do
      add :source, :text, null: false
      add :scope_key, :text, null: false
      add :identity_kind, :text, null: false
      add :identity, :text, null: false
      add :status_marker, :text
      add :source_observed_at, :utc_datetime
      add :fetched_at, :utc_datetime, null: false
      add :ingested_at, :utc_datetime, null: false
      add :paging_contract, :text, null: false
      add :complete, :boolean, null: false, default: false
      add :blockers, {:array, :text}, null: false, default: []
      add :counts, :map, null: false, default: %{}
      add :content_hash, :text, null: false
      add :query_version, :text, null: false
      add :environment, :text, null: false
      add :engine, :text, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:source_runs, [:source, :scope_key, :identity],
             name: :source_runs_identity_index
           )

    create constraint(:source_runs, :source_runs_identity_kind,
             check: "identity_kind = 'content_fallback'"
           )

    create constraint(:source_runs, :source_runs_paging, check: "paging_contract = 'none'")

    create constraint(:source_runs, :source_runs_hashes,
             check:
               "identity ~ '^[0-9a-f]{64}$' AND content_hash = identity AND scope_key ~ '^[0-9a-f]{64}$'"
           )

    create constraint(:source_runs, :source_runs_times,
             check: """
             fetched_at <= ingested_at AND
             (source_observed_at IS NULL OR source_observed_at <= fetched_at)
             """
           )

    create constraint(:source_runs, :source_runs_text,
             check: """
             char_length(source) BETWEEN 1 AND 64 AND
             char_length(query_version) BETWEEN 1 AND 64 AND
             char_length(environment) BETWEEN 1 AND 64 AND
             char_length(engine) BETWEEN 1 AND 64 AND
             (status_marker IS NULL OR char_length(status_marker) BETWEEN 1 AND 256) AND
             cardinality(blockers) <= 64
             """
           )

    create table(:source_observations) do
      add :source_run_id, references(:source_runs, on_delete: :restrict), null: false
      add :digest, :text, null: false
      add :cve, :text, null: false
      add :package_name, :text, null: false
      add :package_version, :text, null: false
      add :severity, :text
      add :suppressed, :boolean, null: false, default: false
      add :quarantine, :boolean, null: false, default: false
      add :attention_eligible, :boolean, null: false, default: false
      add :source_finding_identity, :text, null: false
      add :attention_identity, :text, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:source_observations, [:source_run_id, :source_finding_identity],
             name: :source_observations_identity_index
           )

    create index(:source_observations, [:attention_eligible, :source_run_id])

    create constraint(:source_observations, :source_observations_eligibility,
             check: """
             (attention_eligible = false) OR
             (quarantine = false AND suppressed = false)
             """
           )

    create index(:source_observations, [:attention_identity],
             where: "attention_eligible",
             name: :source_observations_attention_index
           )

    create constraint(:source_observations, :source_observations_identity,
             check:
               "source_finding_identity ~ '^[0-9a-f]{64}$' AND attention_identity ~ '^[0-9a-f]{64}$'"
           )

    create constraint(:source_observations, :source_observations_text,
             check: """
             char_length(digest) BETWEEN 1 AND 256 AND
             char_length(cve) BETWEEN 1 AND 64 AND
             char_length(package_name) BETWEEN 1 AND 256 AND
             char_length(package_version) BETWEEN 1 AND 256 AND
             (severity IS NULL OR char_length(severity) BETWEEN 1 AND 64)
             """
           )

    create table(:source_run_currents) do
      add :source, :text, null: false
      add :scope_key, :text, null: false
      add :source_run_id, references(:source_runs, on_delete: :restrict), null: false
      add :source_observed_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create unique_index(:source_run_currents, [:source, :scope_key],
             name: :source_run_currents_scope_index
           )

    create constraint(:source_run_currents, :source_run_currents_text,
             check: "char_length(source) BETWEEN 1 AND 64 AND scope_key ~ '^[0-9a-f]{64}$'"
           )
  end
end
