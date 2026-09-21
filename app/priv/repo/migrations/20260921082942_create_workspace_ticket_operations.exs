defmodule Triage.Repo.Migrations.CreateWorkspaceTicketOperations do
  use Ecto.Migration

  def up do
    create table(:workspace_ticket_operations, primary_key: false) do
      add :id, :string, primary_key: true
      add :cve, :string, null: false
      add :target_ids, {:array, :bigint}, null: false
      add :versions, :map, null: false
      add :fields, :map, null: false
      add :identity, :map, null: false
      add :request_hash, :string, null: false
      add :payload_hash, :string, null: false
      add :payload, {:array, :map}, null: false
      add :destination, :map, null: false
      add :marker, :string, null: false
      add :state, :string, null: false, default: "pending"
      add :ticket_url, :text
      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:workspace_ticket_operations, [:marker])
    create index(:workspace_ticket_operations, [:cve], where: "state <> 'completed'")

    create index(:workspace_ticket_operations, [:target_ids],
             using: :gin,
             where: "state <> 'completed'"
           )

    create constraint(:workspace_ticket_operations, :workspace_ticket_operation_state,
             check: "state IN ('pending', 'unknown', 'remote_created', 'completed')"
           )

    create constraint(:workspace_ticket_operations, :workspace_ticket_operation_result,
             check:
               "(state IN ('pending', 'unknown') AND ticket_url IS NULL) OR (state IN ('remote_created', 'completed') AND ticket_url IS NOT NULL)"
           )

    create constraint(:workspace_ticket_operations, :workspace_ticket_operation_targets,
             check: "cardinality(target_ids) BETWEEN 1 AND 200"
           )

    execute """
    CREATE FUNCTION protect_workspace_ticket_operation() RETURNS trigger AS $$
    BEGIN
      IF ROW(NEW.id, NEW.cve, NEW.target_ids, NEW.versions, NEW.fields, NEW.identity,
             NEW.request_hash, NEW.payload_hash, NEW.payload, NEW.destination, NEW.marker, NEW.inserted_at)
         IS DISTINCT FROM
         ROW(OLD.id, OLD.cve, OLD.target_ids, OLD.versions, OLD.fields, OLD.identity,
             OLD.request_hash, OLD.payload_hash, OLD.payload, OLD.destination, OLD.marker, OLD.inserted_at) THEN
        RAISE EXCEPTION 'workspace ticket operation intent is immutable';
      END IF;
      IF NEW.state <> OLD.state AND NOT (
           (OLD.state = 'pending' AND NEW.state IN ('unknown', 'remote_created')) OR
           (OLD.state = 'unknown' AND NEW.state = 'remote_created') OR
           (OLD.state = 'remote_created' AND NEW.state = 'completed')) THEN
        RAISE EXCEPTION 'workspace ticket operation cannot be reset or retried';
      END IF;
      IF OLD.ticket_url IS NOT NULL AND NEW.ticket_url IS DISTINCT FROM OLD.ticket_url THEN
        RAISE EXCEPTION 'workspace ticket operation remote result is immutable';
      END IF;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """

    execute """
    CREATE TRIGGER protect_workspace_ticket_operation
    BEFORE UPDATE ON workspace_ticket_operations
    FOR EACH ROW EXECUTE FUNCTION protect_workspace_ticket_operation();
    """
  end

  def down do
    drop table(:workspace_ticket_operations)
    execute "DROP FUNCTION protect_workspace_ticket_operation()"
  end
end
