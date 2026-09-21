defmodule Triage.Workspace.Drafts do
  @moduledoc "User-scoped durable assessment drafts. Evidence fingerprints and operation identity are never regenerated on load."
  import Ecto.Query
  alias Triage.{Accounts, Repo}
  alias Triage.Workspace.Draft

  def get(principal, cve) do
    with {:ok, user} <- Accounts.authorize(principal, :read) do
      case Repo.get_by(Draft, user_id: user.id, cve: cve) do
        nil -> {:ok, nil}
        row -> {:ok, decode(row)}
      end
    end
  end

  def put(principal, cve, draft) do
    with {:ok, user} <- Accounts.authorize(principal, :review) do
      attrs = %{
        cve: cve,
        fields: Map.take(draft.fields, ~w(action owner reason due_on)),
        targets: draft.targets,
        versions: Map.new(draft.versions, fn {id, version} -> {to_string(id), version} end),
        operation_id: draft.operation
      }

      %Draft{user_id: user.id}
      |> Ecto.Changeset.cast(attrs, [:cve, :fields, :targets, :versions, :operation_id])
      |> Ecto.Changeset.validate_required([:cve, :fields, :versions, :operation_id])
      |> Ecto.Changeset.validate_change(:fields, &validate_fields/2)
      |> Ecto.Changeset.validate_length(:cve, max: 40)
      |> Repo.insert(
        on_conflict: {:replace, [:fields, :targets, :versions, :operation_id, :updated_at]},
        conflict_target: [:user_id, :cve]
      )
    end
  rescue
    _error in [DBConnection.ConnectionError, Postgrex.Error] -> {:error, :unavailable}
  end

  def delete(principal, cve) do
    with {:ok, user} <- Accounts.authorize(principal, :review) do
      Repo.delete_all(from d in Draft, where: d.user_id == ^user.id and d.cve == ^cve)
      :ok
    end
  rescue
    _error in [DBConnection.ConnectionError, Postgrex.Error] -> {:error, :unavailable}
  end

  defp validate_fields(:fields, fields) do
    if Enum.all?(fields, &bounded_field?/1),
      do: [],
      else: [fields: "must contain bounded text values"]
  end

  defp bounded_field?({_key, value}), do: is_binary(value) and byte_size(value) <= 2000

  defp decode(row) do
    %{
      fields: row.fields,
      targets: row.targets,
      versions: Map.new(row.versions, fn {id, version} -> {String.to_integer(id), version} end),
      operation: row.operation_id,
      dirty: true,
      saved: false,
      stale: false
    }
  end
end
