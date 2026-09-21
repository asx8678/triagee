defmodule Triage.Accounts.User do
  use Ecto.Schema
  import Ecto.Changeset

  @derive {Inspect, except: [:password_hash, :password_salt]}
  schema "account_users" do
    field :email, :string
    field :role, :string, default: "viewer"
    field :enabled, :boolean, default: true
    field :password_hash, :binary, redact: true
    field :password_salt, :binary, redact: true
    field :password_rounds, :integer
    timestamps(type: :utc_datetime_usec)
  end

  def changeset(user, attrs) do
    user
    |> cast(attrs, [:email, :role, :enabled])
    |> update_change(:email, &String.downcase(String.trim(&1)))
    |> validate_required([:email, :role, :enabled])
    |> validate_length(:email, max: 120)
    |> validate_format(:email, ~r/^[^\s@]+@[^\s@]+$/)
    |> validate_inclusion(:role, ~w(viewer reviewer admin))
    |> unique_constraint(:email)
  end
end
