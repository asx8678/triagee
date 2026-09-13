defmodule Triage.Repo.Migrations.CreateInventory do
  use Ecto.Migration

  def change do
    create table(:images) do
      add :digest, :text, null: false
      add :repository, :text
      add :tag, :text
      add :description, :text

      timestamps(type: :utc_datetime)
    end

    create unique_index(:images, [:digest])

    create table(:image_placements) do
      add :image_id, references(:images, on_delete: :delete_all), null: false
      add :namespace, :text, null: false
      add :owner, :text, null: false
      add :environment, :text, null: false
      add :active, :boolean, null: false, default: true
      add :first_seen, :utc_datetime, null: false
      add :last_seen, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:image_placements, [:image_id, :namespace, :owner, :environment])
    create index(:image_placements, [:owner])

    create table(:findings) do
      add :image_id, references(:images, on_delete: :delete_all), null: false
      add :cve, :text, null: false
      add :package_name, :text, null: false
      add :package_version, :text, null: false
      add :severity, :text
      add :fix, :text
      add :url, :text
      add :description, :text
      add :suppressed, :boolean, null: false, default: false
      add :first_seen, :utc_datetime, null: false
      add :last_seen, :utc_datetime, null: false
      add :resolved_at, :utc_datetime
      add :reopen_count, :integer, null: false, default: 0

      timestamps(type: :utc_datetime)
    end

    create unique_index(:findings, [:image_id, :cve, :package_name, :package_version])
    create index(:findings, [:cve])

    create table(:finding_events) do
      add :finding_id, references(:findings, on_delete: :delete_all), null: false
      add :event, :text, null: false
      add :occurred_at, :utc_datetime, null: false
      add :note, :text

      timestamps(type: :utc_datetime)
    end

    create index(:finding_events, [:finding_id])
  end
end
