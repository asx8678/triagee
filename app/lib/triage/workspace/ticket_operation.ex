defmodule Triage.Workspace.TicketOperation do
  @moduledoc """
  Durable, single-attempt Azure creation claim. Pending/unknown claims never expire
  and are never automatically retried, including under a new operation ID.

  Only mutable outcome fields are updated after insert. Payload, actor, scope and
  original evidence fingerprints are retained for audit and reconciliation.
  No credentials or raw HTTP errors are stored here.
  """
  use Ecto.Schema
  import Ecto.Query
  alias Triage.Repo

  @primary_key {:id, :string, autogenerate: false}
  schema "workspace_ticket_operations" do
    field :cve, :string
    field :target_ids, {:array, :integer}
    field :versions, :map
    field :fields, :map
    field :identity, :map
    field :request_hash, :string
    field :payload_hash, :string
    field :payload, {:array, :map}
    field :destination, :map
    field :marker, :string
    field :state, :string, default: "pending"
    field :ticket_url, :string
    timestamps(type: :utc_datetime_usec)
  end

  def pending_for_scope(cve, ids) do
    Repo.one(
      from o in __MODULE__,
        where:
          o.cve == ^cve and o.state != "completed" and fragment("? && ?", o.target_ids, ^ids),
        order_by: [asc: o.inserted_at, asc: o.id],
        limit: 1
    )
  end

  def versions(operation),
    do: Map.new(operation.versions, fn {id, version} -> {String.to_integer(id), version} end)

  def fields(operation), do: %{action: "create_ticket", actor: operation.fields["actor"]}

  def remember_remote(operation, url) do
    # Monotonic transition: an overlapping reconcile or a late timeout must not
    # downgrade a remote success or overwrite an already committed operation.
    Repo.update_all(
      from(o in __MODULE__, where: o.id == ^operation.id and o.state in ["pending", "unknown"]),
      set: [state: "remote_created", ticket_url: url, updated_at: DateTime.utc_now()]
    )

    {:ok, Repo.get!(__MODULE__, operation.id)}
  rescue
    _ -> {:error, {:reconciliation_required, operation.id}}
  end

  def unknown(operation) do
    Repo.update_all(from(o in __MODULE__, where: o.id == ^operation.id and o.state == "pending"),
      set: [state: "unknown", updated_at: DateTime.utc_now()]
    )

    {:error, {:reconciliation_required, operation.id}}
  rescue
    _ -> {:error, {:reconciliation_required, operation.id}}
  end
end
