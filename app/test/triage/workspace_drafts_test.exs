defmodule Triage.Workspace.DraftsTest do
  use Triage.DataCase, async: true
  import TriageWeb.ConnCase, only: [account_fixture: 1]
  alias Triage.Accounts
  alias Triage.Workspace.Drafts

  defp principal(role) do
    {:ok, token} = Accounts.create_session(account_fixture(role))
    Accounts.principal(token)
  end

  test "draft reload preserves original fingerprints and operation identity and is user-scoped" do
    one = principal(:reviewer)
    two = principal(:reviewer)

    draft = %{
      fields: %{"action" => "accepted_risk", "reason" => "original text", "actor" => "forged"},
      targets: [123],
      versions: %{123 => "original-fingerprint"},
      operation: Ecto.UUID.generate()
    }

    assert {:ok, _} = Drafts.put(one, "CVE-2099-7777", draft)
    assert {:ok, loaded} = Drafts.get(one, "CVE-2099-7777")
    assert loaded.versions == draft.versions
    assert loaded.targets == draft.targets
    assert loaded.operation == draft.operation
    assert loaded.dirty
    refute Map.has_key?(loaded.fields, "actor")
    assert {:ok, nil} = Drafts.get(two, "CVE-2099-7777")
    assert :ok = Drafts.delete(two, "CVE-2099-7777")
    assert {:ok, ^loaded} = Drafts.get(one, "CVE-2099-7777")
    assert {:ok, _} = Drafts.put(one, "CVE-2099-7777", %{draft | targets: []})
    assert {:ok, %{targets: [], operation: operation}} = Drafts.get(one, "CVE-2099-7777")
    assert operation == draft.operation
    assert :ok = Drafts.delete(one, "CVE-2099-7777")
    assert {:ok, nil} = Drafts.get(one, "CVE-2099-7777")
  end

  test "viewer and revoked sessions cannot mutate drafts" do
    viewer = principal(:viewer)
    assert {:error, :forbidden} = Drafts.put(viewer, "CVE-2099-7777", %{})
    assert {:error, :forbidden} = Drafts.delete(viewer, "CVE-2099-7777")
    reviewer = principal(:reviewer)
    Accounts.revoke_session(reviewer.token)
    assert {:error, :unauthenticated} = Drafts.get(reviewer, "CVE-2099-7777")
    assert {:error, :unauthenticated} = Drafts.put(reviewer, "CVE-2099-7777", %{})
  end
end
