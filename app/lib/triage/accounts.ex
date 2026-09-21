defmodule Triage.Accounts do
  @moduledoc "Provisioned accounts, authoritative roles, and revocable eight-hour sessions. No public registration."
  import Ecto.Query
  alias Triage.Accounts.{LoginThrottle, Password, Principal, Session, User}
  alias Triage.Repo
  @session_seconds 28_800

  @doc "Trusted operator API; not exposed through HTTP."
  def create_user(attrs) when is_map(attrs) do
    password = Map.get(attrs, :password) || Map.get(attrs, "password")

    with {:ok, secret} <- Password.hash(password) do
      %User{}
      |> User.changeset(Map.drop(attrs, [:password, "password"]))
      |> Ecto.Changeset.change(secret)
      |> Repo.insert()
    end
  end

  def authenticate(email, password, peer) do
    email = normalize_email(email)

    if LoginThrottle.allow?(email, peer) do
      user = Repo.get_by(User, email: email)

      if Password.valid?(password, user) and user.enabled,
        do: {:ok, user},
        else: {:error, :invalid_credentials}
    else
      {:error, :throttled}
    end
  end

  def create_session(%User{id: id}) do
    case Repo.get(User, id) do
      %User{enabled: true} ->
        token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

        session = %Session{
          token_hash: token_hash(token),
          user_id: id,
          expires_at: DateTime.add(DateTime.utc_now(), @session_seconds, :second)
        }

        with {:ok, _} <- Repo.insert(session), do: {:ok, token}

      _ ->
        {:error, :unauthenticated}
    end
  end

  def principal(token), do: %Principal{token: token}

  def authorize(%Principal{token: token}, permission)
      when is_binary(token) and byte_size(token) == 43 do
    hash = token_hash(token)
    now = DateTime.utc_now()

    user =
      Repo.one(
        from s in Session,
          join: u in User,
          on: u.id == s.user_id,
          where:
            s.token_hash == ^hash and is_nil(s.revoked_at) and s.expires_at > ^now and u.enabled,
          select: u
      )

    case user do
      nil -> {:error, :unauthenticated}
      user -> if permitted?(user, permission), do: {:ok, user}, else: {:error, :forbidden}
    end
  end

  def authorize(_, _), do: {:error, :unauthenticated}

  def permitted?(%User{role: role}, :read), do: role in ~w(viewer reviewer admin)
  def permitted?(%User{role: role}, :review), do: role in ~w(reviewer admin)
  def permitted?(%User{role: "admin"}, :admin), do: true
  def permitted?(_, _), do: false

  def revoke_session(token) when is_binary(token) do
    hash = token_hash(token)

    Repo.update_all(from(s in Session, where: s.token_hash == ^hash and is_nil(s.revoked_at)),
      set: [revoked_at: DateTime.utc_now()]
    )

    disconnect(hash)
    :ok
  end

  def revoke_session(_), do: :ok

  @doc "Admin-only role/disable/password change; invalidates and disconnects all existing sessions."
  def update_user(principal, user_id, attrs) do
    with {:ok, _} <- authorize(principal, :admin),
         %User{} = user <- Repo.get(User, user_id) do
      change_user(user, attrs)
    else
      nil -> {:error, :not_found}
      error -> error
    end
  end

  defp change_user(user, attrs) do
    changeset = User.changeset(user, Map.drop(attrs, [:password, "password"]))
    password = Map.get(attrs, :password) || Map.get(attrs, "password")

    with {:ok, changeset} <- password_change(changeset, password),
         {:ok, {user, hashes}} <-
           Repo.transaction(fn ->
             user = Repo.update!(changeset)

             {_, hashes} =
               Repo.update_all(
                 from(s in Session,
                   where: s.user_id == ^user.id and is_nil(s.revoked_at),
                   select: s.token_hash
                 ),
                 set: [revoked_at: DateTime.utc_now()]
               )

             {user, hashes}
           end) do
      Enum.each(hashes, &disconnect/1)
      {:ok, user}
    end
  end

  defp password_change(changeset, nil), do: {:ok, changeset}

  defp password_change(changeset, password) do
    with {:ok, secret} <- Password.hash(password),
         do: {:ok, Ecto.Changeset.change(changeset, secret)}
  end

  def socket_id(token),
    do: "account_sessions:" <> Base.url_encode64(token_hash(token), padding: false)

  defp disconnect(hash) do
    TriageWeb.Endpoint.broadcast(
      "account_sessions:" <> Base.url_encode64(hash, padding: false),
      "disconnect",
      %{}
    )
  end

  defp token_hash(token), do: :crypto.hash(:sha256, token)

  defp normalize_email(email) when is_binary(email) and byte_size(email) <= 320,
    do: email |> String.trim() |> String.downcase()

  defp normalize_email(_), do: "invalid"

  @doc "Release bootstrap: TRIAGE_ACCOUNT_EMAIL, TRIAGE_ACCOUNT_PASSWORD, TRIAGE_ACCOUNT_ROLE. Never overwrites an existing account."
  def bootstrap! do
    Application.load(:triage)

    attrs = %{
      email: System.fetch_env!("TRIAGE_ACCOUNT_EMAIL"),
      password: System.fetch_env!("TRIAGE_ACCOUNT_PASSWORD"),
      role: System.fetch_env!("TRIAGE_ACCOUNT_ROLE")
    }

    {:ok, result, _} = Ecto.Migrator.with_repo(Repo, fn _ -> create_user(attrs) end)

    case result do
      {:ok, user} ->
        %{id: user.id, email: user.email, role: user.role}

      {:error, _} ->
        raise "Account provisioning failed: check unique email, role, and password length (12–1024 bytes)"
    end
  end
end
