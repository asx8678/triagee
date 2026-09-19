defmodule Triage.Repo.Migrations.ExtendScopedWorkspaceDecisions do
  use Ecto.Migration

  def change do
    alter table(:advisory_decisions) do
      add :work_owner, :text
      add :due_on, :date
      add :operation_id, :text
      add :metadata, :map, default: %{}, null: false
    end

    create unique_index(:advisory_decisions, [:operation_id, :placement_id])
  end
end
