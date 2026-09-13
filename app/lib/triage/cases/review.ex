defmodule Triage.Cases.Review do
  @moduledoc """
  A manual human assessment of one case against one frozen evidence snapshot.

  Only the four manual fields (`applicability`, `priority`, `next_action`,
  `rationale`) are castable. `actor`, case/snapshot binding, expected revision,
  idempotency token and request hash are set by the server from
  `Triage.Cases.submit_review/5` and can never be mass-assigned: forged keys in
  form params are dropped by `cast/4`, not read.

  There is deliberately no update/delete changeset — reviews are append-only,
  backed by PostgreSQL rejection triggers.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @applicabilities ~w(affected not_affected_with_evidence unknown)
  @priorities ~w(expedited_review normal_review insufficient_context)

  @next_actions ~w(
    investigation
    dependency_update
    base_image_update
    rebuild_deploy
    mitigation_review
    exception_proposal
  )

  @rationale_max 2000

  # Control characters except ordinary tab (\t), newline (\n) and carriage
  # return (\r), which a textarea produces legitimately. NUL, other C0 bytes
  # and DEL are rejected. Validated on the trimmed value.
  @unsafe_rationale ~r/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/

  schema "review_reviews" do
    field :case_id, :integer
    field :snapshot_id, :integer
    field :expected_revision, :integer
    field :idempotency_token, :string
    field :request_hash, :string
    field :actor, :string
    field :applicability, :string
    field :priority, :string
    field :next_action, :string
    field :rationale, :string

    timestamps(type: :utc_datetime)
  end

  @doc """
  Validation changeset for the four manual fields only.

  Rationale is trimmed, required, nonblank, at most #{@rationale_max}
  characters, valid UTF-8 and NUL/control-free. Enum fields are restricted to
  the fixed manual-assessment vocabularies; there is intentionally no
  accepted/rejected outcome field in this slice.
  """
  def changeset(review, attrs) do
    review
    |> cast(attrs, [:applicability, :priority, :next_action, :rationale])
    |> update_change(:rationale, &trim_rationale/1)
    |> validate_required([:applicability, :priority, :next_action, :rationale])
    |> validate_inclusion(:applicability, @applicabilities)
    |> validate_inclusion(:priority, @priorities)
    |> validate_inclusion(:next_action, @next_actions)
    |> validate_rationale()
  end

  defp trim_rationale(rationale) when is_binary(rationale), do: String.trim(rationale)
  defp trim_rationale(other), do: other

  defp validate_rationale(changeset) do
    case get_field(changeset, :rationale) do
      nil ->
        changeset

      rationale when not is_binary(rationale) ->
        add_error(changeset, :rationale, "must be a string")

      rationale ->
        cond do
          not String.valid?(rationale) ->
            add_error(changeset, :rationale, "must be valid UTF-8")

          Regex.match?(@unsafe_rationale, rationale) ->
            add_error(changeset, :rationale, "must not contain NUL or control characters")

          true ->
            validate_length(changeset, :rationale, max: @rationale_max)
        end
    end
  end
end
