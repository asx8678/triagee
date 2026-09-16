defmodule Triage.Inventory.Image do
  use Ecto.Schema
  import Ecto.Changeset

  schema "images" do
    field :digest, :string
    field :repository, :string
    field :tag, :string
    field :description, :string

    timestamps(type: :utc_datetime)
  end

  def changeset(image, attrs) do
    image
    |> cast(attrs, [:digest, :repository, :tag, :description])
    |> validate_required([:digest])
    |> unique_constraint(:digest)
  end
end
