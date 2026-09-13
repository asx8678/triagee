defmodule Triage.Repo.Migrations.ExposureAndIntel do
  use Ecto.Migration

  def change do
    create table(:exposure_evidences) do
      add :placement_id, references(:image_placements, on_delete: :delete_all), null: false
      add :exposure, :text, null: false
      add :source, :text, null: false
      add :observed_at, :utc_datetime, null: false
      add :expires_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:exposure_evidences, [:placement_id])

    create table(:intel_advisories) do
      add :source, :text, null: false
      add :external_id, :text, null: false
      add :summary, :text
      add :published_at, :utc_datetime
      add :fetched_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:intel_advisories, [:source, :external_id])
    create index(:intel_advisories, [:external_id])

    create table(:news_items) do
      add :source, :text, null: false
      add :item_id, :text, null: false
      add :title, :text, null: false
      add :summary, :text
      add :link, :text
      add :published_at, :utc_datetime
      add :fetched_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:news_items, [:source, :item_id])

    create table(:intel_refresh_receipts) do
      add :source, :text, null: false
      add :attempted_at, :utc_datetime, null: false
      add :succeeded, :boolean, null: false, default: false
      add :item_count, :integer
      add :message, :text

      timestamps(type: :utc_datetime)
    end

    create index(:intel_refresh_receipts, [:source])
  end
end
