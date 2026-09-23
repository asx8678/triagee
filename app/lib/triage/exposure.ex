defmodule Triage.Exposure do
  @moduledoc """
  Operator-declared exposure evidence for image placements.

  Exposure is an explicit fact with a source and observation time — never an
  inference from repository names or environments. Missing evidence stays
  `unknown`. Records are append-only history; the current value is the evidence
  with the latest `observed_at`.

  Two questions are kept apart (W01b/A08): what to *display* and what may be
  *trusted*. Display uses the latest observation and renders expired,
  future-dated or conflicting evidence as `unknown`. Trust — whether evidence
  may support a dismissal — additionally requires an approved, bounded source
  policy (`Triage.Exposure.Policy`); an unknown or unbounded source never
  supports dismissal, and equal-time conflicting assertions are never silently
  resolved by the highest row id.
  """

  import Ecto.Query
  alias Triage.Exposure.Policy
  alias Triage.Inventory.ImagePlacement
  alias Triage.Repo

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

    @type t :: %__MODULE__{}

    def changeset(evidence, attrs) do
      evidence
      |> cast(attrs, [:placement_id, :exposure, :source, :observed_at, :expires_at])
      |> validate_required([:placement_id, :exposure, :source, :observed_at])
      |> validate_inclusion(:exposure, Triage.Exposure.exposures())
    end
  end

  @spec exposures() :: [String.t()]
  def exposures, do: @exposures

  @doc """
  Records new exposure evidence for a placement. History is never rewritten.

  Two consistency rules are enforced at the effect boundary (A08): an
  observation time beyond the approved clock tolerance has not happened yet, and
  an expiry that precedes its own observation is not a valid window. Both are
  refused rather than stored and later trusted. A zero-length window
  (`expires_at == observed_at`) is allowed and is already treated as expired
  once the clock passes its instant by the display rules. The optional clock is
  the reference for the observation-time rule and defaults to the real clock.
  """
  @spec record(
          pos_integer(),
          String.t(),
          String.t(),
          DateTime.t(),
          DateTime.t() | nil,
          DateTime.t()
        ) ::
          {:ok, Evidence.t()}
          | {:error,
             Ecto.Changeset.t()
             | :invalid_exposure_evidence
             | :future_observation
             | :expiry_before_observation}
  def record(
        placement_id,
        exposure,
        source,
        observed_at,
        expires_at_marker \\ nil,
        now \\ DateTime.utc_now()
      )

  def record(placement_id, exposure, source, observed_at, expires_at, now)
      when is_integer(placement_id) and exposure in @exposures and is_binary(source) do
    with :ok <- validate_source(source),
         :ok <- validate_observed_at(observed_at, now),
         :ok <- validate_expiry(observed_at, expires_at) do
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
  end

  def record(_placement_id, _exposure, _source, _observed_at, _expires_at, _now),
    do: {:error, :invalid_exposure_evidence}

  defp validate_source(source) do
    if String.trim(source) == "", do: {:error, :invalid_exposure_evidence}, else: :ok
  end

  # Judged against the caller's clock, which defaults to the real one. A caller
  # that runs on its own clock (a fixture, an import replay) states it rather
  # than having its observation times falsified.
  defp validate_observed_at(%DateTime{} = observed_at, now) do
    cutoff = DateTime.add(now, Policy.clock_tolerance_seconds(), :second)

    if DateTime.compare(observed_at, cutoff) == :gt,
      do: {:error, :future_observation},
      else: :ok
  end

  defp validate_observed_at(_other, _now), do: {:error, :invalid_exposure_evidence}

  defp validate_expiry(_observed_at, nil), do: :ok

  defp validate_expiry(%DateTime{} = observed_at, %DateTime{} = expires_at) do
    if DateTime.compare(expires_at, observed_at) == :lt,
      do: {:error, :expiry_before_observation},
      else: :ok
  end

  defp validate_expiry(_observed_at, _other), do: {:error, :invalid_exposure_evidence}

  @doc """
  Structured current evidence per placement id (A08).

  The latest observation time decides; ties are broken only when the tied rows
  agree. A tie with conflicting exposures is `:conflicting` — never silently
  resolved by the highest row id. States are `:current`, `:expired`,
  `:future_dated` and `:conflicting`; `usable?` is the separate, fail-closed
  dismissal-support flag from `Triage.Exposure.Policy`.
  """
  @spec current_evidence([pos_integer()], DateTime.t()) :: %{optional(pos_integer()) => map()}
  def current_evidence(placement_ids, now \\ DateTime.utc_now()) when is_list(placement_ids) do
    placement_ids
    |> Enum.filter(&is_integer/1)
    |> Enum.uniq()
    |> latest_rows()
    |> Enum.group_by(& &1.placement_id)
    |> Map.new(fn {placement_id, rows} -> {placement_id, evidence_state(rows, now)} end)
  end

  @doc """
  Latest (and unexpired) evidence per placement id, as `%{placement_id => exposure}`.

  Display projection of `current_evidence/2`: expired, future-dated and
  conflicting records display as `unknown`, exactly as the SQL projection
  renders them. Expiry never silently keeps trust.
  """
  @spec current_by_placement([pos_integer()], DateTime.t()) ::
          %{optional(pos_integer()) => String.t()}
  def current_by_placement(placement_ids, now \\ DateTime.utc_now())
      when is_list(placement_ids) do
    placement_ids
    |> current_evidence(now)
    |> Map.new(fn {placement_id, evidence} -> {placement_id, evidence.exposure} end)
  end

  # One bounded read: only rows whose observation time is the maximum for their
  # placement, so ties are visible without shipping the whole evidence history.
  defp latest_rows([]), do: []

  defp latest_rows(placement_ids) do
    from(e in Evidence,
      where: e.placement_id in ^placement_ids,
      where:
        fragment(
          "? = (SELECT max(x.observed_at) FROM exposure_evidences x WHERE x.placement_id = ?)",
          e.observed_at,
          e.placement_id
        ),
      order_by: [asc: e.placement_id, desc: e.id],
      select: %{
        placement_id: e.placement_id,
        exposure: e.exposure,
        source: e.source,
        observed_at: e.observed_at,
        expires_at: e.expires_at,
        id: e.id
      }
    )
    |> Repo.all()
  end

  defp evidence_state(rows, now) do
    latest = hd(rows)
    exposures = rows |> Enum.map(& &1.exposure) |> Enum.uniq()

    cond do
      length(exposures) > 1 ->
        state(
          latest,
          :conflicting,
          "unknown",
          "Conflicting exposure evidence at the same observation time"
        )

      expired?(latest.expires_at, now) ->
        state(latest, :expired, "unknown", "Exposure evidence expired")

      future_dated?(latest.observed_at, now) ->
        state(
          latest,
          :future_dated,
          "unknown",
          "Observation time is beyond the approved clock tolerance"
        )

      Policy.usable?(latest, now) ->
        state(latest, :current, latest.exposure, nil, true)

      true ->
        state(
          latest,
          :current,
          latest.exposure,
          "No approved bounded-age policy for this source"
        )
    end
  end

  defp state(row, state, exposure, reason, usable? \\ false) do
    %{
      placement_id: row.placement_id,
      exposure: exposure,
      state: state,
      source: row.source,
      observed_at: row.observed_at,
      expires_at: row.expires_at,
      usable?: usable?,
      reason: reason
    }
  end

  defp future_dated?(observed_at, now) do
    DateTime.compare(observed_at, DateTime.add(now, Policy.clock_tolerance_seconds(), :second)) ==
      :gt
  end

  defp expired?(nil, _now), do: false

  defp expired?(expires_at, now), do: DateTime.compare(expires_at, now) == :lt
end
