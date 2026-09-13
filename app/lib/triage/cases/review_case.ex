defmodule Triage.Cases.ReviewCase do
  @moduledoc """
  One stable review case per finding occurrence and explicit scope.

  Identity is `(finding_id, owner, environment)`: a case belongs to one team
  and environment occurrence, never to a global advisory. Scope and finding
  are server-set and never change; only `revision` and `current_snapshot_id`
  move, transactionally. There is deliberately no castable changeset: every
  field is set programmatically by `Triage.Cases` and must not be
  mass-assignable from review attrs.
  """

  use Ecto.Schema

  schema "review_cases" do
    field :finding_id, :integer
    field :owner, :string
    field :environment, :string
    field :revision, :integer, default: 1
    field :current_snapshot_id, :integer

    # No has_many associations: the children hold explicit case_id integers
    # (set only by the context), which Ecto cannot derive associations from;
    # history is queried explicitly in Triage.Cases.

    timestamps(type: :utc_datetime)
  end
end
