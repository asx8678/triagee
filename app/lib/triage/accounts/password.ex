defmodule Triage.Accounts.Password do
  @moduledoc false
  @rounds 600_000

  def hash(password) when is_binary(password) and byte_size(password) in 12..1024 do
    salt = :crypto.strong_rand_bytes(32)

    {:ok,
     %{
       password_hash: derive(password, salt, @rounds),
       password_salt: salt,
       password_rounds: @rounds
     }}
  end

  def hash(_), do: {:error, :invalid_password}

  def valid?(password, %{password_hash: hash, password_salt: salt, password_rounds: rounds})
      when is_binary(password) and byte_size(password) <= 1024 and
             is_binary(hash) and byte_size(hash) == 32 and is_binary(salt) and
             is_integer(rounds) and rounds >= @rounds and rounds <= 2_000_000 do
    Plug.Crypto.secure_compare(derive(password, salt, rounds), hash)
  end

  def valid?(password, _) do
    # Equal-cost failure for unknown, disabled and malformed accounts.
    password =
      if is_binary(password) and byte_size(password) <= 1024, do: password, else: "invalid"

    _ = derive(password, <<0::256>>, @rounds)
    false
  end

  defp derive(password, salt, rounds),
    do: :crypto.pbkdf2_hmac(:sha256, password, salt, rounds, 32)
end
