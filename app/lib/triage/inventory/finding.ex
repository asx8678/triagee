defmodule Triage.Inventory.Finding do
  use Ecto.Schema
  import Ecto.Changeset

  schema "findings" do
    belongs_to :image, Triage.Inventory.Image
    field :cve, :string
    field :package_name, :string
    field :package_version, :string
    field :severity, :string
    field :fix, :string
    field :url, :string
    field :description, :string
    field :suppressed, :boolean, default: false
    field :first_seen, :utc_datetime
    field :last_seen, :utc_datetime
    field :resolved_at, :utc_datetime
    field :reopen_count, :integer, default: 0

    timestamps(type: :utc_datetime)
  end

  def changeset(finding, attrs) do
    finding
    |> cast(attrs, [
      :image_id,
      :cve,
      :package_name,
      :package_version,
      :severity,
      :fix,
      :url,
      :description,
      :suppressed,
      :first_seen,
      :last_seen,
      :resolved_at,
      :reopen_count
    ])
    |> validate_required([
      :image_id,
      :cve,
      :package_name,
      :package_version,
      :first_seen,
      :last_seen
    ])
    |> foreign_key_constraint(:image_id)
    |> unique_constraint([:image_id, :cve, :package_name, :package_version])
  end
end
