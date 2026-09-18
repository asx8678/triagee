defmodule Triage.Inventory.ImagePlacement do
  use Ecto.Schema
  import Ecto.Changeset

  schema "image_placements" do
    belongs_to :image, Triage.Inventory.Image
    field :namespace, :string
    field :owner, :string
    field :environment, :string
    field :active, :boolean, default: true
    field :first_seen, :utc_datetime
    field :last_seen, :utc_datetime

    timestamps(type: :utc_datetime)
  end

  def changeset(placement, attrs) do
    placement
    |> cast(attrs, [
      :image_id,
      :namespace,
      :owner,
      :environment,
      :active,
      :first_seen,
      :last_seen
    ])
    |> validate_required([:image_id, :namespace, :owner, :environment, :first_seen, :last_seen])
    |> unique_constraint([:image_id, :namespace, :owner, :environment])
  end
end
