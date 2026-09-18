defmodule Triage.Repo.Migrations.AddKevActionabilityToIntelAdvisories do
  use Ecto.Migration

  # CISA's KEV feed carries the part of the intelligence that says what to do and
  # by when. These columns are nullable: NVD rows and rows cached before this
  # migration simply have no value, which is displayed as "not captured" rather
  # than as a reassuring blank.
  def change do
    alter table(:intel_advisories) do
      add :required_action, :text
      add :due_date, :utc_datetime
      add :known_ransomware, :boolean
    end
  end
end
