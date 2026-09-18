defmodule Triage.ReviewProgress do
  @moduledoc "Durable navigation only for the local operator; never an approval or ticket preview."
  use Ecto.Schema
  alias Triage.Repo

  @primary_key {:cve, :string, autogenerate: false}
  schema "review_progress" do
    field :fingerprint, :string
    field :step, :integer
    timestamps(type: :utc_datetime)
  end

  def step(nil), do: 1

  def step(row) do
    fingerprint = Triage.GuidedReview.review_fingerprint(row)

    case Repo.get(__MODULE__, row.cve) do
      %{fingerprint: ^fingerprint, step: step} when step in 1..4 -> step
      _ -> 1
    end
  end

  def save(row, step) when not is_nil(row) and step in 1..4 do
    %__MODULE__{
      cve: row.cve,
      fingerprint: Triage.GuidedReview.review_fingerprint(row),
      step: step
    }
    |> Repo.insert(
      on_conflict: {:replace, [:fingerprint, :step, :updated_at]},
      conflict_target: :cve
    )
  rescue
    DBConnection.ConnectionError -> {:error, :database_unavailable}
  end
end
