defmodule Triage.Classifier.Evidence do
  @moduledoc "Immutable, administrator-attested input for one workload and CVE. Not a live register receipt."
  use Ecto.Schema

  schema "classifier_evidence" do
    field :identity, :string
    field :cve, :string
    field :placement_id, :integer
    field :packet_hash, :string
    field :workload_uid, :string
    field :snapshot, :map
    field :approved_by, :integer
    field :observed_at, :utc_datetime
    field :expires_at, :utc_datetime
    timestamps(type: :utc_datetime)
  end
end
