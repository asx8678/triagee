defmodule Triage.Accounts.ReportingTokens do
  @moduledoc "Read-only machine credentials for the reporting API. Raw tokens are returned once."

  import Ecto.Query
  alias Triage.Accounts.{ReportingToken, ReportingTokenScope, User}
  alias Triage.Repo

  @prefix "trg_"
  @secret_bytes 32
  @max_lifetime_seconds 90 * 24 * 60 * 60

  @type access :: %{
          token_id: pos_integer(),
          user_id: pos_integer(),
          label: String.t(),
          grants: :all | [{String.t(), String.t()}]
        }

  @doc "Trusted operator API. Issues one read-only token and returns its secret once."
  def issue(%User{} = user, attrs) when is_map(attrs) do
    now = DateTime.utc_now()

    with %User{enabled: true} = current <- Repo.get(User, user.id),
         true <- current.role in ~w(viewer reviewer admin),
         {:ok, label} <- label(attrs),
         {:ok, expires_at} <- expiry(attrs, now),
         {:ok, grants} <- grants(attrs) do
      raw =
        @prefix <> (:crypto.strong_rand_bytes(@secret_bytes) |> Base.url_encode64(padding: false))

      Repo.transaction(fn ->
        token =
          %ReportingToken{}
          |> ReportingToken.changeset(%{
            user_id: current.id,
            token_hash: hash(raw),
            label: label,
            all_scopes: grants == :all,
            expires_at: expires_at
          })
          |> Repo.insert!()

        insert_scopes!(token.id, grants)
        %{token: raw, record: Repo.preload(token, :scopes)}
      end)
    else
      nil -> {:error, :unauthenticated}
      false -> {:error, :unauthenticated}
      {:error, _} = error -> error
    end
  end

  def issue(_user, _attrs), do: {:error, :invalid_token}

  @doc "Authenticates a bearer secret and reloads its user and exact scope grants."
  @spec authenticate(String.t()) :: {:ok, access()} | {:error, :unauthenticated}
  def authenticate(@prefix <> secret = raw) when byte_size(secret) == 43 do
    now = DateTime.utc_now()

    token =
      Repo.one(
        from t in ReportingToken,
          join: u in User,
          on: u.id == t.user_id,
          where:
            t.token_hash == ^hash(raw) and is_nil(t.revoked_at) and t.expires_at > ^now and
              u.enabled and u.role in ["viewer", "reviewer", "admin"],
          preload: [:scopes]
      )

    case token do
      %ReportingToken{all_scopes: true} = token -> {:ok, access(token, :all)}
      %ReportingToken{scopes: []} -> {:error, :unauthenticated}
      %ReportingToken{} = token -> {:ok, access(token, scope_pairs(token.scopes))}
      nil -> {:error, :unauthenticated}
    end
  end

  def authenticate(_token), do: {:error, :unauthenticated}

  @doc "Revokes a token by its operator-visible database identifier."
  def revoke(token_id) when is_integer(token_id) and token_id > 0 do
    {count, _} =
      Repo.update_all(
        from(t in ReportingToken, where: t.id == ^token_id and is_nil(t.revoked_at)),
        set: [revoked_at: DateTime.utc_now()]
      )

    if count == 1, do: :ok, else: {:error, :not_found}
  end

  def revoke(_token_id), do: {:error, :not_found}

  @doc "Atomically replaces one active token with a new secret and the same identity/grants."
  def rotate(token_id, expires_at) when is_integer(token_id) and token_id > 0 do
    Repo.transaction(fn ->
      old =
        Repo.one(
          from t in ReportingToken,
            where: t.id == ^token_id and is_nil(t.revoked_at),
            lock: "FOR UPDATE",
            preload: [:user, :scopes]
        ) || Repo.rollback(:not_found)

      attrs = %{
        label: old.label <> " (rotated)",
        expires_at: expires_at,
        scopes: if(old.all_scopes, do: :all, else: scope_pairs(old.scopes))
      }

      case issue(old.user, attrs) do
        {:ok, issued} ->
          old |> Ecto.Changeset.change(revoked_at: DateTime.utc_now()) |> Repo.update!()
          issued

        {:error, reason} ->
          Repo.rollback(reason)
      end
    end)
  end

  def rotate(_token_id, _expires_at), do: {:error, :not_found}

  defp access(token, grants),
    do: %{token_id: token.id, user_id: token.user_id, label: token.label, grants: grants}

  defp insert_scopes!(_token_id, :all), do: :ok

  defp insert_scopes!(token_id, scopes) do
    Enum.each(scopes, fn {team, environment} ->
      %ReportingTokenScope{}
      |> ReportingTokenScope.changeset(%{
        token_id: token_id,
        team: team,
        environment: environment
      })
      |> Repo.insert!()
    end)
  end

  defp scope_pairs(scopes),
    do: scopes |> Enum.map(&{&1.team, &1.environment}) |> Enum.uniq() |> Enum.sort()

  defp label(attrs) do
    case value(attrs, :label) do
      label when is_binary(label) ->
        label = String.trim(label)

        if label != "" and byte_size(label) <= 120,
          do: {:ok, label},
          else: {:error, :invalid_label}

      _ ->
        {:error, :invalid_label}
    end
  end

  defp expiry(attrs, now) do
    case value(attrs, :expires_at) do
      %DateTime{} = expires_at ->
        seconds = DateTime.diff(expires_at, now)

        if seconds > 0 and seconds <= @max_lifetime_seconds,
          do: {:ok, DateTime.truncate(expires_at, :microsecond)},
          else: {:error, :invalid_expiry}

      _ ->
        {:error, :invalid_expiry}
    end
  end

  defp grants(attrs) do
    case value(attrs, :scopes) do
      :all -> {:ok, :all}
      "all" -> {:ok, :all}
      scopes when is_list(scopes) -> normalize_scopes(scopes)
      _ -> {:error, :invalid_scopes}
    end
  end

  defp normalize_scopes(scopes) do
    normalized =
      Enum.map(scopes, fn
        {team, environment} -> normalize_scope(team, environment)
        %{"team" => team, "environment" => environment} -> normalize_scope(team, environment)
        %{team: team, environment: environment} -> normalize_scope(team, environment)
        _ -> :error
      end)

    if normalized != [] and :error not in normalized,
      do: {:ok, Enum.uniq(normalized)},
      else: {:error, :invalid_scopes}
  end

  defp normalize_scope(team, environment)
       when is_binary(team) and is_binary(environment) do
    team = String.trim(team)
    environment = String.trim(environment)

    if team != "" and environment != "" and byte_size(team) <= 120 and
         byte_size(environment) <= 120,
       do: {team, environment},
       else: :error
  end

  defp normalize_scope(_team, _environment), do: :error
  defp value(attrs, key), do: Map.get(attrs, key) || Map.get(attrs, Atom.to_string(key))
  defp hash(raw), do: :crypto.hash(:sha256, raw)
end
