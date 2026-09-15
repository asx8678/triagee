defmodule Triage.Impact do
  @moduledoc """
  Operator-declared business impact evidence for image placements.

  Impact is a judgement about *this* estate — what a compromise of that
  placement would cost — so it is never derived from scanner severity,
  repository names, namespaces or exposure. It is always an explicit statement
  with a source and an observation time, and records are append-only history:
  the current value is the evidence with the latest `observed_at` and `id`.

  Expired evidence stops being a judgement: it reports `state: :expired` with
  the impact cleared, so an old "no impact" call never keeps claiming safety.
  Missing evidence stays unrecorded — this module never invents a value.

  `none` is a real judgement ("assessed: no business impact"), not the absence
  of one; absence is the absence of a key in `current_by_placement/2`.
  """

  import Ecto.Query
  alias Triage.Inventory.ImagePlacement
  alias Triage.Repo

  @impacts ~w(critical high moderate low none)

  @labels %{
    "critical" => "Critical",
    "high" => "High",
    "moderate" => "Moderate",
    "low" => "Low",
    "none" => "None"
  }

  defmodule Evidence do
    use Ecto.Schema
    import Ecto.Changeset

    schema "placement_impact_evidences" do
      belongs_to :placement, ImagePlacement
      field :impact, :string
      field :source, :string
      field :observed_at, :utc_datetime
      field :expires_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    @type t :: %__MODULE__{}

    def changeset(evidence, attrs) do
      evidence
      |> cast(attrs, [:placement_id, :impact, :source, :observed_at, :expires_at])
      |> validate_required([:placement_id, :impact, :source, :observed_at])
      |> validate_inclusion(:impact, Triage.Impact.impacts())
    end
  end

  @doc "The impact vocabulary."
  @spec impacts() :: [String.t()]
  def impacts, do: @impacts

  @doc "Human label for an impact value."
  @spec label(String.t()) :: String.t()
  def label(impact), do: Map.get(@labels, impact, "Unknown impact")

  @doc "Records new impact evidence for a placement. History is never rewritten."
  @spec record(pos_integer(), String.t(), String.t(), DateTime.t(), DateTime.t() | nil) ::
          {:ok, Evidence.t()} | {:error, Ecto.Changeset.t() | :invalid_impact_evidence}
  def record(placement_id, impact, source, observed_at, expires_at \\ nil)

  def record(placement_id, impact, source, observed_at, expires_at)
      when is_integer(placement_id) and impact in @impacts and is_binary(source) do
    %Evidence{}
    |> Evidence.changeset(%{
      placement_id: placement_id,
      impact: impact,
      source: source,
      observed_at: observed_at,
      expires_at: expires_at
    })
    |> Repo.insert()
  end

  def record(_placement_id, _impact, _source, _observed_at, _expires_at),
    do: {:error, :invalid_impact_evidence}

  @doc """
  Latest evidence per placement id, as `%{placement_id => evidence map}`.

  Each entry carries the impact, its source and observation time. An expired row
  reports `state: :expired` and `impact: nil`. A placement with no evidence has
  no entry at all — never an implied "none".
  """
  @spec current_by_placement([pos_integer()], DateTime.t()) ::
          %{optional(pos_integer()) => map()}
  def current_by_placement(placement_ids, now \\ DateTime.utc_now())
      when is_list(placement_ids) do
    from(e in Evidence,
      where: e.placement_id in ^placement_ids,
      distinct: e.placement_id,
      order_by: [asc: e.placement_id, desc: e.observed_at, desc: e.id],
      select: {e.placement_id, e.impact, e.source, e.observed_at, e.expires_at}
    )
    |> Repo.all()
    |> Map.new(fn {placement_id, impact, source, observed_at, expires_at} ->
      expired = expired?(expires_at, now)

      {placement_id,
       %{
         impact: if(expired, do: nil, else: impact),
         label: if(expired, do: nil, else: label(impact)),
         state: if(expired, do: :expired, else: :active),
         source: source,
         observed_at: observed_at,
         expires_at: expires_at
       }}
    end)
  end

  defp expired?(nil, _now), do: false
  defp expired?(expires_at, now), do: DateTime.compare(expires_at, now) == :lt
end
