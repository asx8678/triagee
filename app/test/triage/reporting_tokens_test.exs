defmodule Triage.ReportingTokensTest do
  use Triage.DataCase, async: true

  import TriageWeb.ConnCase, only: [account_fixture: 1]
  alias Triage.Accounts.ReportingTokens
  alias Triage.Accounts.{ReportingToken, ReportingTokenScope, User}

  test "tokens are hashed, expiring, revocable and preserve exact scope pairs" do
    user = account_fixture(:viewer)
    expires_at = DateTime.add(DateTime.utc_now(), 3_600, :second)

    assert {:ok, %{token: raw, record: record}} =
             ReportingTokens.issue(user, %{
               label: "Grafana",
               expires_at: expires_at,
               scopes: [{"alpha", "prod"}, {"beta", "staging"}]
             })

    assert String.starts_with?(raw, "trg_")
    refute inspect(record) =~ raw
    stored = Repo.get!(ReportingToken, record.id)
    assert stored.token_hash == :crypto.hash(:sha256, raw)
    assert Repo.aggregate(ReportingTokenScope, :count) == 2

    assert {:ok, access} = ReportingTokens.authenticate(raw)
    assert access.grants == [{"alpha", "prod"}, {"beta", "staging"}]
    assert :ok = ReportingTokens.revoke(record.id)
    assert {:error, :unauthenticated} = ReportingTokens.authenticate(raw)
  end

  test "empty grants, excessive lifetime, disabled parent identity and malformed secrets fail closed" do
    user = account_fixture(:viewer)
    soon = DateTime.add(DateTime.utc_now(), 3_600, :second)

    assert {:error, :invalid_scopes} =
             ReportingTokens.issue(user, %{label: "empty", expires_at: soon, scopes: []})

    assert {:error, :invalid_expiry} =
             ReportingTokens.issue(user, %{
               label: "too long",
               expires_at: DateTime.add(DateTime.utc_now(), 91, :day),
               scopes: :all
             })

    assert {:ok, %{token: raw}} =
             ReportingTokens.issue(user, %{label: "global", expires_at: soon, scopes: :all})

    Repo.update_all(from(u in User, where: u.id == ^user.id), set: [enabled: false])
    assert {:error, :unauthenticated} = ReportingTokens.authenticate(raw)
    assert {:error, :unauthenticated} = ReportingTokens.authenticate("not-a-token")
  end

  test "rotation revokes the old secret and returns a new one once" do
    user = account_fixture(:viewer)
    first_expiry = DateTime.add(DateTime.utc_now(), 3_600, :second)

    {:ok, %{token: old, record: record}} =
      ReportingTokens.issue(user, %{label: "rotate", expires_at: first_expiry, scopes: :all})

    assert {:ok, %{token: new, record: replacement}} =
             ReportingTokens.rotate(record.id, DateTime.add(DateTime.utc_now(), 7_200, :second))

    refute old == new
    refute record.id == replacement.id
    assert {:error, :unauthenticated} = ReportingTokens.authenticate(old)
    assert {:ok, %{token_id: id, grants: :all}} = ReportingTokens.authenticate(new)
    assert id == replacement.id
  end
end
