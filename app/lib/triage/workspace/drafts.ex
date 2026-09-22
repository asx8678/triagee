defmodule Triage.Workspace.Drafts do
  @moduledoc """
  User-scoped durable assessment drafts with optimistic concurrency.

  Evidence fingerprints and operation identity are never regenerated on load.
  Every successful store bumps the row revision, so a tab holding an older
  revision — or one that never loaded the stored draft — cannot silently
  overwrite another tab's newer work: `put/3` returns `{:conflict, stored}`.
  `delete/4` removes only the caller's own operation at the revision it last
  saw, so discarding or committing in one tab never deletes a newer draft
  another tab saved under the same key.
  """
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

  @doc """
  Stores `draft` under optimistic concurrency and returns the new revision.

  `draft.revision` is the stored revision this writer last observed; `nil`
  means it has seen no stored draft, in which case a row written by another
  tab or device is returned as `{:conflict, stored}` instead of overwritten.
  """
  def put(principal, cve, draft) do
    with {:ok, user} <- Accounts.authorize(principal, :review) do
      attrs = %{
        cve: cve,
        fields: Map.take(draft.fields, ~w(action owner reason due_on)),
        targets: draft.targets,
        versions: Map.new(draft.versions, fn {id, version} -> {to_string(id), version} end),
        operation_id: draft.operation
      }

      store(user.id, cve, attrs, draft[:revision])
    end
  rescue
    _error in [DBConnection.ConnectionError, Postgrex.Error] -> {:error, :unavailable}
  end

  defp store(user_id, cve, attrs, expected) do
    case Repo.transaction(fn -> store!(user_id, cve, attrs, expected) end) do
      {:ok, revision} -> {:ok, revision}
      {:error, {:conflict, stored}} -> {:conflict, stored}
      {:error, %Ecto.Changeset{} = changeset} -> {:error, changeset}
      {:error, _other} -> {:error, :unavailable}
    end
  end

  @doc """
  Deletes the stored draft only when it still carries `expected_operation`
  at `expected_revision` — the snapshot the caller last saw. A newer draft
  saved by another tab or device survives; a missing row is still `:ok`.
  """
  def delete(principal, cve, expected_operation, expected_revision \\ nil) do
    with {:ok, user} <- Accounts.authorize(principal, :review) do
      from(d in Draft, where: d.user_id == ^user.id and d.cve == ^cve)
      |> operation_gate(expected_operation, expected_revision)
      |> Repo.delete_all()

      :ok
    end
  rescue
    _error in [DBConnection.ConnectionError, Postgrex.Error] -> {:error, :unavailable}
  end

  # Ecto forbids `field == ^nil`, so the operation/revision gate is built in
  # explicit branches instead of `is_nil(^value) or ...` chains.
  defp operation_gate(query, nil, _expected_revision), do: query

  defp operation_gate(query, expected_operation, nil),
    do: where(query, [d], d.operation_id == ^expected_operation)

  defp operation_gate(query, expected_operation, expected_revision),
    do:
      where(
        query,
        [d],
        d.operation_id == ^expected_operation and d.revision == ^expected_revision
      )

  defp store!(user_id, cve, attrs, expected) do
    # Serialize each draft's read-modify-write; without this, two first saves
    # of a never-stored draft could both observe no row and race the insert.
    Repo.query!("SELECT pg_advisory_xact_lock(hashtext($1))", [
      "draft:" <> Integer.to_string(user_id) <> ":" <> cve
    ])

    case Repo.one(from d in Draft, where: d.user_id == ^user_id and d.cve == ^cve) do
      nil -> insert!(user_id, attrs, expected)
      %Draft{} = row -> update!(row, attrs, expected)
    end
  end

  defp insert!(user_id, attrs, expected) do
    if not is_nil(expected), do: Repo.rollback({:conflict, nil})

    case Repo.insert(changeset(%Draft{user_id: user_id}, Map.put(attrs, :revision, 0))) do
      {:ok, _row} -> 0
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp update!(row, attrs, expected) do
    unless row.revision == expected, do: Repo.rollback({:conflict, decode(row)})

    case Repo.update(changeset(row, Map.put(attrs, :revision, row.revision + 1))) do
      {:ok, _row} -> row.revision + 1
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp changeset(draft, attrs) do
    draft
    |> Ecto.Changeset.cast(attrs, [:cve, :fields, :targets, :versions, :operation_id, :revision])
    |> Ecto.Changeset.validate_required([:cve, :fields, :versions, :operation_id])
    |> Ecto.Changeset.validate_change(:fields, &validate_fields/2)
    |> Ecto.Changeset.validate_length(:cve, max: 40)
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
      revision: row.revision,
      dirty: true,
      saved: false,
      stale: false
    }
  end
end
