defmodule Triage.Repo.Migrations.CreateReviewProgress do
  use Ecto.Migration

  def change do
    create table(:review_progress, primary_key: false) do
      add :cve, :text, primary_key: true
      add :fingerprint, :text, null: false
      add :step, :integer, null: false
      timestamps(type: :utc_datetime)
    end

    create constraint(:review_progress, :valid_review_step, check: "step BETWEEN 1 AND 4")
  end
end
