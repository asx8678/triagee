defmodule Triage.Repo.Migrations.IntelGenerationsAndExposurePolicy do
  use Ecto.Migration

  def change do
    create table(:intel_generations) do
      add :source, :text, null: false
      add :content_hash, :text, null: false
      add :row_count, :integer, null: false
      add :declared_count, :integer
      add :complete, :boolean, null: false, default: false
      add :catalog_version, :text
      add :metadata, :map, null: false, default: %{}
      add :started_at, :utc_datetime, null: false
      add :fetched_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create index(:intel_generations, [:source, :inserted_at])

    # The source itself is the key: one current generation per source. The table
    # must be declared without the default `id` so `source` really is the primary
    # key and `ON CONFLICT (source)` has a constraint to match.
    create table(:intel_current_generations, primary_key: false) do
      add :source, :text, primary_key: true
      add :generation_id, references(:intel_generations, on_delete: :delete_all), null: false

      timestamps(type: :utc_datetime)
    end

    alter table(:intel_advisories) do
      add :generation_id, references(:intel_generations, on_delete: :delete_all)
    end

    create index(:intel_advisories, [:generation_id])

    # The original constraint assumed one live row per (source, external_id).
    # Generations keep history, so identity is now scoped per generation; legacy
    # NULL-generation rows keep their original uniqueness through a partial index.
    drop unique_index(:intel_advisories, [:source, :external_id])

    create unique_index(:intel_advisories, [:source, :external_id],
             where: "generation_id IS NULL",
             name: :intel_advisories_legacy_identity_index
           )

    create unique_index(:intel_advisories, [:source, :generation_id, :external_id],
             name: :intel_advisories_generation_identity_index
           )
  end
end
