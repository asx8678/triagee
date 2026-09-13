defmodule Triage.Cases.EvidenceSnapshot do
  @moduledoc """
  Frozen evidence captured from the local inventory at one point in time.

  `payload` is a plain string-keyed map (`schema_version` 1, source
  `synthetic_local_inventory`). `payload_hash` covers the canonical payload
  content — real source timestamps included, capture time and ORM timestamps
  excluded — so an unchanged source is detectable without duplicating or
  mutating snapshots.

  Append-only: there is deliberately no update/delete changeset; narrow
  PostgreSQL UPDATE/DELETE rejection triggers back this up.
  """

  use Ecto.Schema

  schema "review_evidence_snapshots" do
    field :case_id, :integer
    field :version, :integer
    field :payload, :map
    field :payload_hash, :string
    field :captured_at, :utc_datetime

    timestamps(type: :utc_datetime)
  end
end
