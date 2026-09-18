defmodule Triage.Repo.Migrations.CreateLocalExceptions do
  use Ecto.Migration

  def change do
    create table(:local_exception_decisions) do
      add :case_id, references(:review_cases, on_delete: :restrict), null: false
      add :snapshot_id, :bigint, null: false
      add :expected_revision, :bigint, null: false
      add :idempotency_token, :text, null: false
      add :request_hash, :text, null: false
      add :actor, :text, null: false
      add :kind, :text, null: false
      add :reason, :text, null: false
      add :evidence, :text
      add :review_by, :date
      timestamps(type: :utc_datetime, updated_at: false)
    end

    create unique_index(:local_exception_decisions, [:case_id, :idempotency_token])
    create index(:local_exception_decisions, [:case_id, :id])

    create constraint(:local_exception_decisions, :exception_revision_positive,
             check: "expected_revision > 0"
           )

    create constraint(:local_exception_decisions, :exception_actor,
             check: "actor = 'local-operator'"
           )

    create constraint(:local_exception_decisions, :exception_reason,
             check: "char_length(btrim(reason)) BETWEEN 1 AND 2000"
           )

    create constraint(:local_exception_decisions, :exception_details,
             check: """
             (kind = 'reopened' AND review_by IS NULL AND evidence IS NULL) OR
             (kind = 'accepted_risk' AND review_by IS NOT NULL) OR
             (kind = 'not_affected' AND review_by IS NOT NULL AND evidence IS NOT NULL
               AND char_length(btrim(evidence)) BETWEEN 1 AND 2000)
             """
           )

    create constraint(:local_exception_decisions, :exception_review_window,
             check:
               "review_by IS NULL OR (review_by > inserted_at::date AND review_by <= inserted_at::date + 90)"
           )

    execute(
      """
      ALTER TABLE local_exception_decisions ADD CONSTRAINT local_exception_snapshot_fkey
        FOREIGN KEY (snapshot_id, case_id) REFERENCES review_evidence_snapshots (id, case_id)
        ON DELETE RESTRICT
      """,
      "ALTER TABLE local_exception_decisions DROP CONSTRAINT local_exception_snapshot_fkey"
    )

    for operation <- ~w(UPDATE DELETE) do
      trigger = "local_exception_decisions_no_#{String.downcase(operation)}"

      execute(
        """
        CREATE TRIGGER #{trigger} BEFORE #{operation} ON local_exception_decisions
          FOR EACH ROW EXECUTE FUNCTION triage_reject_append_only_mutation()
        """,
        "DROP TRIGGER IF EXISTS #{trigger} ON local_exception_decisions"
      )
    end
  end
end
