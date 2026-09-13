defmodule Triage.Exposure do
  @moduledoc """
  Operator-declared exposure evidence for image placements.

  Exposure is an explicit fact with a source and observation time — never an
  inference from repository names or environments. Missing evidence stays
  `unknown`. Records are append-only history; the current value is the
  evidence with the latest `observed_at`.
  """

  import Ecto.Query
  alias Triage.Repo
  alias Triage.Inventory.ImagePlacement

  @exposures ~w(internet_exposed internal unknown)

  defmodule Evidence do
    use Ecto.Schema
    import Ecto.Changeset

    schema "exposure_evidences" do
      belongs_to :placement, ImagePlacement
      field :exposure, :string
      field :source, :string
      field :observed_at, :utc_datetime
      field :expires_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    def changeset(evidence, attrs) do
      evidence
      |> cast(attrs, [:placement_id, :exposure, :source, :observed_at, :expires_at])
      |> validate_required([:placement_id, :exposure, :source, :observed_at])
      |> validate_inclusion(:exposure, Triage.Exposure.exposures())
    end
  end

  def exposures, do: @exposures

  @doc "Records new exposure evidence for a placement. History is never rewritten."
  def record(placement_id, exposure, source, observed_at, expires_at \\ nil)

  def record(placement_id, exposure, source, observed_at, expires_at)
      when is_integer(placement_id) and exposure in @exposures and is_binary(source) do
    %Evidence{}
    |> Evidence.changeset(%{
      placement_id: placement_id,
      exposure: exposure,
      source: source,
      observed_at: observed_at,
      expires_at: expires_at
    })
    |> Repo.insert()
  end

  def record(_placement_id, _exposure, _source, _observed_at, _expires_at),
    do: {:error, :invalid_exposure_evidence}

  @doc """
  Latest (and unexpired) evidence per placement id, as `%{placement_id => exposure}`.

  Expired evidence becomes `unknown` — staleness never silently keeps trust.
  """
  def current_by_placement(placement_ids, now \\ DateTime.utc_now())
      when is_list(placement_ids) do
    from(e in Evidence,
      where: e.placement_id in ^placement_ids,
      order_by: [asc: e.placement_id, desc: e.observed_at, desc: e.id],
      select: {e.placement_id, e.exposure, e.expires_at}
    )
    |> Repo.all()
    |> Enum.group_by(&elem(&1, 0))
    |> Map.new(fn {placement_id, rows} ->
      {_pid, exposure, expires_at} = hd(rows)

      exposure =
        if not is_nil(expires_at) and DateTime.compare(expires_at, now) == :lt,
          do: "unknown",
          else: exposure

      {placement_id, exposure}
    end)
  end
end
