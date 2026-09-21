defmodule Triage.AccountsTest do
  use Triage.DataCase, async: true
  import TriageWeb.ConnCase, only: [account_fixture: 1]
  alias Triage.Accounts
  alias Triage.Accounts.{Password, Session, User}

  test "PBKDF2 has random salts, minimum work factor and constant-time credential verification" do
    {:ok, first} = Password.hash("a-strong-test-password")
    {:ok, second} = Password.hash("a-strong-test-password")
    assert first.password_rounds >= 600_000
    assert byte_size(first.password_salt) == 32
    refute first.password_salt == second.password_salt
    refute first.password_hash == second.password_hash
    assert Password.valid?("a-strong-test-password", first)
    refute Password.valid?("wrong-password", first)
    refute Password.valid?("a-strong-test-password", nil)
    assert {:error, :invalid_password} = Password.hash("short")
  end

  test "sessions are opaque, hashed at rest, expiring and revocable" do
    user = account_fixture(:reviewer)
    {:ok, token} = Accounts.create_session(user)
    principal = Accounts.principal(token)
    assert byte_size(token) == 43
    assert {:ok, %{id: id}} = Accounts.authorize(principal, :review)
    assert id == user.id
    session = Repo.get_by!(Session, user_id: user.id)
    assert session.token_hash == :crypto.hash(:sha256, token)
    assert DateTime.diff(session.expires_at, session.inserted_at) in 28_799..28_800
    Accounts.revoke_session(token)
    assert {:error, :unauthenticated} = Accounts.authorize(principal, :read)
    {:ok, token} = Accounts.create_session(user)

    Repo.update_all(from(s in Session, where: s.user_id == ^user.id),
      set: [expires_at: DateTime.add(DateTime.utc_now(), -1)]
    )

    assert {:error, :unauthenticated} = Accounts.authorize(Accounts.principal(token), :read)
  end

  test "roles and disabled identity always reload from the server; forged user maps are not principals" do
    user = account_fixture(:reviewer)
    {:ok, token} = Accounts.create_session(user)
    principal = Accounts.principal(token)
    assert {:error, :unauthenticated} = Accounts.authorize(%{id: user.id, role: "admin"}, :review)
    Repo.update_all(from(u in User, where: u.id == ^user.id), set: [role: "viewer"])
    assert {:ok, %{role: "viewer"}} = Accounts.authorize(principal, :read)
    assert {:error, :forbidden} = Accounts.authorize(principal, :review)
    assert {:error, :forbidden} = Accounts.authorize(principal, :admin)
    Repo.update_all(from(u in User, where: u.id == ^user.id), set: [enabled: false])
    assert {:error, :unauthenticated} = Accounts.authorize(principal, :read)
  end

  test "administrator role/password changes revoke every session" do
    admin = account_fixture(:admin)
    {:ok, token} = Accounts.create_session(admin)
    user = account_fixture(:reviewer)
    {:ok, old} = Accounts.create_session(user)

    assert {:ok, %{role: "viewer"}} =
             Accounts.update_user(Accounts.principal(token), user.id, %{role: "viewer"})

    assert {:error, :unauthenticated} = Accounts.authorize(Accounts.principal(old), :read)

    assert {:ok, %{role: "viewer"}} =
             Accounts.authenticate(user.email, "test-only-password-long", "test-admin-peer")
  end

  test "login attempts are bounded independently by account and direct peer" do
    alias Triage.Accounts.LoginThrottle
    email = "throttle-#{System.unique_integer([:positive])}@example.test"
    for _ <- 1..10, do: assert(LoginThrottle.allow?(email, "peer-one"))
    refute LoginThrottle.allow?(email, "new-peer-does-not-bypass-account-limit")
    for n <- 1..50, do: assert(LoginThrottle.allow?("other-#{n}-#{email}", "peer-two"))
    refute LoginThrottle.allow?("brand-new-#{email}", "peer-two")
  end

  test "provisioning normalizes identity and does not overwrite accounts" do
    attrs = %{
      email: "  Unique-#{System.unique_integer([:positive])}@Example.Test ",
      password: "long-test-password",
      role: "admin"
    }

    assert {:ok, user} = Accounts.create_user(attrs)
    assert user.email == attrs.email |> String.trim() |> String.downcase()
    assert {:error, %Ecto.Changeset{}} = Accounts.create_user(attrs)

    assert {:error, %Ecto.Changeset{}} =
             Accounts.create_user(%{attrs | email: "invalid", role: "superuser"})
  end
end
