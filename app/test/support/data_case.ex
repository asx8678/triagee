defmodule Triage.DataCase do
  @moduledoc """
  This module defines the setup for tests requiring
  access to the application's data layer.

  You may define functions here to be used as helpers in
  your tests.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use Triage.DataCase, async: true`, although
  this option is not recommended for other databases.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      @moduletag :db

      alias Triage.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import Triage.DataCase
    end
  end

  setup tags do
    Triage.DataCase.setup_sandbox(tags)
    :ok
  end

  @doc """
  Sets up the sandbox based on the test tags.
  """
  def setup_sandbox(tags) do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Triage.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end

  # Row-level deletes, children first, in one fixed order.
  #
  # `TRUNCATE` takes ACCESS EXCLUSIVE locks on the inventory tables, which
  # deadlocks against the windowed reads other tests run concurrently: a reset
  # holding ACCESS EXCLUSIVE on one table and waiting for another deadlocks with
  # a read that holds the first and wants the second. DELETE takes only row
  # locks, which never conflict with a reader, and a fixed delete order stops two
  # concurrent resets from locking rows in opposite orders.
  #
  # `review_cases` and `review_evidence_snapshots` reference each other, so the
  # cycle is broken first: clearing `current_snapshot_id` lets the snapshots be
  # deleted before the cases that own them. A self-referencing
  # `advisory_decisions` needs no such help: its foreign key is an AFTER trigger
  # checked at the end of the statement, so deleting the whole table at once is
  # valid.
  @reset_statements [
    "DELETE FROM remediation_requests",
    "DELETE FROM review_case_events",
    "UPDATE review_cases SET current_snapshot_id = NULL",
    "DELETE FROM review_reviews",
    "DELETE FROM review_evidence_snapshots",
    "DELETE FROM review_cases",
    "DELETE FROM advisory_decisions",
    "DELETE FROM placement_impact_evidences",
    "DELETE FROM exposure_evidences",
    "DELETE FROM finding_events",
    "DELETE FROM image_placements",
    "DELETE FROM findings",
    "DELETE FROM images"
  ]

  @doc """
  Empties the inventory tables inside the caller's sandbox transaction.

  The Activity feed and the What's New LiveView list inventory-wide, so rows
  that already exist in the test database are visible to them even though the
  sandbox rolls back writes made by tests. A database seeded before
  `ecto.setup` stopped chaining `run priv/repo/seeds.exs` (or a development
  database reused as a test database) would otherwise break count- and
  ordering-dependent assertions with unrelated data. Case tables that reference
  findings with `on_delete: :restrict` are cleared first; the sandbox
  transaction restores everything when the test finishes.
  """
  def reset_inventory! do
    Enum.each(@reset_statements, &Triage.Repo.query!/1)
  end

  @doc """
  A helper that transforms changeset errors into a map of messages.

      assert {:error, changeset} = Accounts.create_user(%{password: "short"})
      assert "password is too short" in errors_on(changeset).password
      assert %{password: ["password is too short"]} = errors_on(changeset)

  """
  def errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
