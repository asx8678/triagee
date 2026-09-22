defmodule Triage.Repo.Migrations.AddWorkspaceDraftRevisions do
  use Ecto.Migration

  def change do
    # Optimistic concurrency for draft saves: every successful write bumps the
    # revision, so a tab holding an older revision cannot silently overwrite
    # or discard a draft saved by another tab or device.
    alter table(:workspace_drafts) do
      add :revision, :bigint, null: false, default: 0
    end
  end
end
