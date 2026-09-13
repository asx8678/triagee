defmodule Triage.Repo.Migrations.CreateReviewCases do
  @moduledoc """
  Local review cases, frozen evidence snapshots, manual reviews and the
  append-only audit trail. Additive only: the PR 1 inventory schema is never
  touched. Down migration drops everything this file created, in reverse.

  Append-only enforcement: narrow BEFORE UPDATE / BEFORE DELETE rejection
  triggers on review_evidence_snapshots, review_reviews and review_case_events.
  review_cases itself is deliberately NOT trigger-guarded: its revision and
  current_snapshot_id pointer are allowed to move transactionally while its
  identity (finding_id, owner, environment) stays fixed.
  """

  use Ecto.Migration

  @scope_max 120

  @append_only_tables ~w(review_evidence_snapshots review_reviews review_case_events)

  def change do
    create table(:review_cases) do
      add :finding_id, references(:findings, on_delete: :restrict), null: false
      add :owner, :text, null: false
      add :environment, :text, null: false
      add :revision, :bigint, null: false, default: 1

      # current_snapshot_id is added after review_evidence_snapshots exists: a
      # circular relationship is not a reason to leave an unconstrained bigint.

      timestamps(type: :utc_datetime)
    end

    create unique_index(:review_cases, [:finding_id, :owner, :environment],
             name: :review_cases_finding_scope_index
           )

    create constraint(:review_cases, :scope_not_blank, check: "owner <> '' AND environment <> ''")

    create constraint(:review_cases, :scope_trimmed,
             check: "btrim(owner) = owner AND btrim(environment) = environment"
           )

    create constraint(:review_cases, :scope_length,
             check:
               "char_length(owner) <= #{@scope_max} AND char_length(environment) <= #{@scope_max}"
           )

    create constraint(:review_cases, :revision_positive, check: "revision >= 1")

    create table(:review_evidence_snapshots) do
      add :case_id, references(:review_cases, on_delete: :restrict), null: false
      add :version, :bigint, null: false
      add :payload, :jsonb, null: false
      add :payload_hash, :text, null: false
      add :captured_at, :utc_datetime, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:review_evidence_snapshots, [:case_id, :version])

    # Composite unique key so reviews/events can hold a same-case snapshot
    # foreign key instead of an unconstrained cross-case integer pointer.
    create unique_index(:review_evidence_snapshots, [:id, :case_id],
             name: :review_evidence_snapshots_id_case_index
           )

    create constraint(:review_evidence_snapshots, :version_positive, check: "version >= 1")

    alter table(:review_cases) do
      add :current_snapshot_id, :bigint
    end

    # Same-case pointer enforcement at the DATABASE level, not just the
    # application: the composite foreign key (current_snapshot_id, id) ->
    # (id, case_id) means a case's current snapshot must both exist AND
    # belong to that very case (its own id equals the snapshot's case_id),
    # so `UPDATE review_cases SET current_snapshot_id = <other case's
    # snapshot>` can never commit. The referenced key is the composite
    # unique index review_evidence_snapshots_id_case_index created above.
    execute(
      """
      ALTER TABLE review_cases
        ADD CONSTRAINT review_cases_current_snapshot_fkey
        FOREIGN KEY (current_snapshot_id, id)
        REFERENCES review_evidence_snapshots (id, case_id)
        ON DELETE RESTRICT
      """,
      "ALTER TABLE review_cases DROP CONSTRAINT review_cases_current_snapshot_fkey"
    )

    create table(:review_reviews) do
      add :case_id, references(:review_cases, on_delete: :restrict), null: false
      # snapshot_id carries a composite (snapshot_id, case_id) foreign key
      # below, so a review can never point at another case's snapshot.
      add :snapshot_id, :bigint, null: false
      add :expected_revision, :bigint, null: false
      add :idempotency_token, :text, null: false
      add :request_hash, :text, null: false
      add :actor, :text, null: false
      add :applicability, :text, null: false
      add :priority, :text, null: false
      add :next_action, :text, null: false
      add :rationale, :text, null: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:review_reviews, [:case_id, :idempotency_token])
    create index(:review_reviews, [:case_id])

    create unique_index(:review_reviews, [:id, :case_id], name: :review_reviews_id_case_index)

    create constraint(:review_reviews, :expected_revision_positive,
             check: "expected_revision >= 1"
           )

    create constraint(:review_reviews, :review_actor_not_blank, check: "actor <> ''")

    create constraint(:review_reviews, :review_enums, check: "
               applicability IN ('affected', 'not_affected_with_evidence', 'unknown')
               AND priority IN ('expedited_review', 'normal_review', 'insufficient_context')
               AND next_action IN
                 ('investigation', 'dependency_update', 'base_image_update',
                  'rebuild_deploy', 'mitigation_review', 'exception_proposal')
             ")

    execute(
      """
      ALTER TABLE review_reviews
        ADD CONSTRAINT review_reviews_snapshot_fkey
        FOREIGN KEY (snapshot_id, case_id)
        REFERENCES review_evidence_snapshots (id, case_id)
        ON DELETE RESTRICT
      """,
      "ALTER TABLE review_reviews DROP CONSTRAINT review_reviews_snapshot_fkey"
    )

    create table(:review_case_events) do
      add :case_id, references(:review_cases, on_delete: :restrict), null: false
      add :kind, :text, null: false
      add :case_revision, :bigint, null: false
      add :snapshot_id, :bigint
      add :review_id, :bigint
      add :actor, :text, null: false
      add :detail, :jsonb, null: false, default: "{}"

      timestamps(type: :utc_datetime)
    end

    create index(:review_case_events, [:case_id])

    create constraint(:review_case_events, :kind_included,
             check: "kind IN ('case_opened', 'evidence_captured', 'review_saved')"
           )

    create constraint(:review_case_events, :case_revision_positive, check: "case_revision >= 1")

    execute(
      """
      ALTER TABLE review_case_events
        ADD CONSTRAINT review_case_events_snapshot_fkey
        FOREIGN KEY (snapshot_id, case_id)
        REFERENCES review_evidence_snapshots (id, case_id)
        ON DELETE RESTRICT
      """,
      "ALTER TABLE review_case_events DROP CONSTRAINT review_case_events_snapshot_fkey"
    )

    execute(
      """
      ALTER TABLE review_case_events
        ADD CONSTRAINT review_case_events_review_fkey
        FOREIGN KEY (review_id, case_id)
        REFERENCES review_reviews (id, case_id)
        ON DELETE RESTRICT
      """,
      "ALTER TABLE review_case_events DROP CONSTRAINT review_case_events_review_fkey"
    )

    # Shared rejection function for the three append-only tables.
    execute(
      """
      CREATE FUNCTION triage_reject_append_only_mutation() RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION '% on % is forbidden: table is append-only', TG_OP, TG_TABLE_NAME
          USING ERRCODE = 'integrity_constraint_violation';
      END;
      $$ LANGUAGE plpgsql
      """,
      "DROP FUNCTION IF EXISTS triage_reject_append_only_mutation()"
    )

    for table <- @append_only_tables do
      execute(
        "
          CREATE TRIGGER #{table}_no_update
          BEFORE UPDATE ON #{table}
          FOR EACH ROW EXECUTE FUNCTION triage_reject_append_only_mutation()",
        "DROP TRIGGER IF EXISTS #{table}_no_update ON #{table}"
      )

      execute(
        "
          CREATE TRIGGER #{table}_no_delete
          BEFORE DELETE ON #{table}
          FOR EACH ROW EXECUTE FUNCTION triage_reject_append_only_mutation()",
        "DROP TRIGGER IF EXISTS #{table}_no_delete ON #{table}"
      )
    end
  end
end
