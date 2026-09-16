defmodule Triage.Exceptions.Decision do
  @moduledoc """
  An append-only local disposition of one scoped case and evidence snapshot.
  Identity, actor, revision and token are server-bound, never form-castable.
  A review date expires at 00:00 UTC that day; it is not an automatic renewal.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @kinds ~w(accepted_risk not_affected reopened)
  @unsafe ~r/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/

  schema "local_exception_decisions" do
    field :case_id, :integer
    field :snapshot_id, :integer
    field :expected_revision, :integer
    field :idempotency_token, :string
    field :request_hash, :string
    field :actor, :string
    field :kind, :string
    field :reason, :string
    field :evidence, :string
    field :review_by, :date
    timestamps(type: :utc_datetime, updated_at: false)
  end

  def changeset(attrs) do
    if is_map(attrs) and not is_struct(attrs) and Enum.all?(Map.keys(attrs), &is_binary/1) do
      %__MODULE__{}
      |> cast(attrs, [:kind, :reason, :evidence, :review_by])
      |> validate_required([:kind, :reason])
      |> validate_inclusion(:kind, @kinds)
      |> validate_text(:reason)
      |> validate_text(:evidence)
      |> validate_details()
    else
      %__MODULE__{}
      |> change()
      |> add_error(:reason, "must be a form with text fields")
    end
  end

  def validate_review_date(changeset, today \\ Date.utc_today()) do
    case get_field(changeset, :review_by) do
      %Date{} = date ->
        if Date.compare(date, today) == :gt and Date.diff(date, today) <= 90,
          do: changeset,
          else:
            add_error(changeset, :review_by, "must be tomorrow through 90 days from today (UTC)")

      _ ->
        changeset
    end
  end

  defp validate_details(changeset) do
    case get_field(changeset, :kind) do
      "reopened" -> changeset |> put_change(:review_by, nil) |> put_change(:evidence, nil)
      "not_affected" -> validate_required(changeset, [:review_by, :evidence])
      "accepted_risk" -> validate_required(changeset, [:review_by])
      _ -> changeset
    end
  end

  defp validate_text(changeset, field) do
    case get_field(changeset, field) do
      value when is_binary(value) ->
        if String.valid?(value) and not Regex.match?(@unsafe, value) do
          changeset
          |> put_change(field, String.trim(value))
          |> validate_length(field, max: 2000)
          |> validate_required(if(field == :reason, do: [field], else: []))
        else
          add_error(changeset, field, "must be valid text without control characters")
        end

      _ ->
        changeset
    end
  end
end
