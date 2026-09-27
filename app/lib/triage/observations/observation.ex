defmodule Triage.Observations.Observation do
  @moduledoc """
  One finding observed by a source run. Quarantine is decided by the server
  contract, not by a payload `in_scope` flag. Attention eligibility is a
  context-query fact, not a workspace UI binding.
  """

  use Ecto.Schema
  import Ecto.Changeset

  schema "source_observations" do
    belongs_to :source_run, Triage.Observations.Run
    field :digest, :string
    field :cve, :string
    field :package_name, :string
    field :package_version, :string
    field :severity, :string
    field :suppressed, :boolean, default: false
    field :quarantine, :boolean, default: false
    field :attention_eligible, :boolean, default: false
    field :source_finding_identity, :string
    field :attention_identity, :string

    timestamps(type: :utc_datetime)
  end

  def changeset(observation, attrs) do
    observation
    |> cast(attrs, [
      :source_run_id,
      :digest,
      :cve,
      :package_name,
      :package_version,
      :severity,
      :suppressed,
      :quarantine,
      :attention_eligible,
      :source_finding_identity,
      :attention_identity
    ])
    |> validate_required([
      :source_run_id,
      :digest,
      :cve,
      :package_name,
      :package_version,
      :suppressed,
      :quarantine,
      :attention_eligible,
      :source_finding_identity,
      :attention_identity
    ])
    |> unique_constraint([:source_run_id, :source_finding_identity],
      name: :source_observations_identity_index
    )
  end
end
