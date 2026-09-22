defmodule Triage.Workspace.DraftsTest do
  use Triage.DataCase, async: true
  import TriageWeb.ConnCase, only: [account_fixture: 1]
  alias Triage.Accounts
  alias Triage.Workspace.Drafts

  defp principal(role) do
    {:ok, token} = Accounts.create_session(account_fixture(role))
    Accounts.principal(token)
  end

  test "draft reload preserves fingerprints, operation identity and revision and is user-scoped" do
    one = principal(:reviewer)
    two = principal(:reviewer)

    draft = %{
      fields: %{"action" => "accepted_risk", "reason" => "original text", "actor" => "forged"},
      targets: [123],
      versions: %{123 => "original-fingerprint"},
      operation: Ecto.UUID.generate(),
      revision: nil
    }

    assert {:ok, 0} = Drafts.put(one, "CVE-2099-7777", draft)
    assert {:ok, loaded} = Drafts.get(one, "CVE-2099-7777")
    assert loaded.versions == draft.versions
    assert loaded.targets == draft.targets
    assert loaded.operation == draft.operation
    assert loaded.revision == 0
    assert loaded.dirty
    refute Map.has_key?(loaded.fields, "actor")
    assert {:ok, nil} = Drafts.get(two, "CVE-2099-7777")

    # A writer that never observed the stored revision cannot overwrite it.
    assert {:conflict, stored} = Drafts.put(one, "CVE-2099-7777", %{draft | targets: []})
    assert stored.revision == 0

    # With the observed revision the writer proceeds and bumps the revision.
    assert {:ok, 1} = Drafts.put(one, "CVE-2099-7777", %{draft | targets: [], revision: 0})

    assert {:ok, %{targets: [], operation: operation, revision: 1}} =
             Drafts.get(one, "CVE-2099-7777")

    assert operation == draft.operation

    # Deletes gate on the operation snapshot the caller last saw.
    assert :ok = Drafts.delete(one, "CVE-2099-7777", Ecto.UUID.generate(), nil)
    assert {:ok, %{revision: 1}} = Drafts.get(one, "CVE-2099-7777")

    assert :ok = Drafts.delete(one, "CVE-2099-7777", draft.operation, 1)
    assert {:ok, nil} = Drafts.get(one, "CVE-2099-7777")
  end

  test "another tab's newer revision survives a stale tab's discard" do
    one = principal(:reviewer)

    first = %{
      fields: %{"action" => "fixed"},
      targets: [1],
      versions: %{1 => "v"},
      operation: Ecto.UUID.generate(),
      revision: nil
    }

    assert {:ok, 0} = Drafts.put(one, "CVE-2099-7778", first)

    newer = %{first | operation: Ecto.UUID.generate(), fields: %{"action" => "accepted_risk"}}
    assert {:ok, 1} = Drafts.put(one, "CVE-2099-7778", %{newer | revision: 0})

    # The first tab discards the snapshot it knew; the newer row survives.
    assert :ok = Drafts.delete(one, "CVE-2099-7778", first.operation, 0)
    assert {:ok, stored} = Drafts.get(one, "CVE-2099-7778")
    assert stored.operation == newer.operation
    assert stored.revision == 1

    assert :ok = Drafts.delete(one, "CVE-2099-7778", newer.operation, 1)
    assert {:ok, nil} = Drafts.get(one, "CVE-2099-7778")
  end

  test "viewer and revoked sessions cannot mutate drafts" do
    viewer = principal(:viewer)
    assert {:error, :forbidden} = Drafts.put(viewer, "CVE-2099-7777", %{})
    assert {:error, :forbidden} = Drafts.delete(viewer, "CVE-2099-7777", nil)

    reviewer = principal(:reviewer)
    Accounts.revoke_session(reviewer.token)
    assert {:error, :unauthenticated} = Drafts.get(reviewer, "CVE-2099-7777")
    assert {:error, :unauthenticated} = Drafts.put(reviewer, "CVE-2099-7777", %{})
  end
end
