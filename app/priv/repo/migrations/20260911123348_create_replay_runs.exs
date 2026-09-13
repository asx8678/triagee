defmodule Triage.Repo.Migrations.CreateReplayRuns do
  use Ecto.Migration

  def change do
    create table(:replay_runs) do
      add :key_hash, :text, null: false
      add :input_sha256, :text, null: false
      add :summary, :map, null: false
      add :outcome, :text, null: false
      add :received_at, :utc_datetime_usec, null: false
      add :expires_at, :utc_datetime_usec, null: false
    end

    create unique_index(:replay_runs, [:key_hash])
    create index(:replay_runs, [:expires_at, :id])

    create constraint(:replay_runs, :replay_runs_hashes,
             check: "key_hash ~ '^[0-9a-f]{64}$' AND input_sha256 ~ '^[0-9a-f]{64}$'"
           )

    create constraint(:replay_runs, :replay_runs_summary_bytes,
             check: "octet_length(summary::text) <= 65536"
           )

    create constraint(:replay_runs, :replay_runs_expiry,
             check: "expires_at = received_at + interval '30 days'"
           )

    create constraint(:replay_runs, :replay_runs_safe_outcome,
             check: """
             (jsonb_typeof(summary) = 'object'
              AND summary->>'format' = 'triage.replay.result'
              AND summary->'version' = '1'::jsonb
              AND summary->>'origin' = 'synthetic'
              AND summary->'actionable' = 'false'::jsonb
              AND summary->'inventory_changed' = 'false'::jsonb
              AND summary->'historical_provenance' = 'false'::jsonb
              AND summary->>'input_sha256' = input_sha256
              AND jsonb_typeof(summary->'counts') = 'object'
              AND ((outcome = 'complete' AND summary->'complete' = 'true'::jsonb)
                OR (outcome = 'incomplete' AND summary->'complete' = 'false'::jsonb))) IS TRUE
             """
           )

    execute(
      """
      CREATE FUNCTION triage_replay_runs_no_update() RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION 'replay result is immutable'
          USING ERRCODE = 'integrity_constraint_violation';
      END;
      $$ LANGUAGE plpgsql
      """,
      "DROP FUNCTION triage_replay_runs_no_update()"
    )

    execute(
      """
      CREATE TRIGGER replay_runs_no_update BEFORE UPDATE ON replay_runs
      FOR EACH ROW EXECUTE FUNCTION triage_replay_runs_no_update()
      """,
      "DROP TRIGGER replay_runs_no_update ON replay_runs"
    )
  end
end
