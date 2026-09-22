defmodule Triage.Decisions do
  @moduledoc """
  Operator decisions that take an advisory out of the triage work list without
  rewriting the inventory.

  A decision is an auditable claim: it names an actor, carries a reason, and an
  `accepted_risk` decision must carry an expiry — an accepted risk without an
  end date is forever, and forever is not a triage state. History is
  append-only: recording a new decision for the same scope links the previous
  one through `supersedes_id` and keeps both rows.

  A decision is deliberately **not** any of these:

    * not resolution — `findings.resolved_at` is untouched;
    * not scanner suppression — `findings.suppressed` is untouched;
    * not a human assessment — no `review_reviews` row is written.

  The finding keeps its severity, keeps its place in Findings, on `/cves/:id`
  and in the lifecycle events. Only Triage changes, and it says which decision
  removed the row and when that decision expires.

  An expired decision covers nothing: the advisory returns to the work list with
  the expiry shown, never silently.

  The scope is the whole advisory by default. A decision may name one placement
  (`placement_id`), which makes the claim narrower and never stronger: it does
  not cover that placement's siblings.
  """

  import Ecto.Query

  alias Triage.Inventory.Finding
  alias Triage.Inventory.ImagePlacement
  alias Triage.Repo

  @decisions ~w(accepted_risk not_affected mitigated fixed)
  @expiry_required ~w(accepted_risk)
  @work_actions ~w(request_remediation investigate request_verification create_ticket)

  @labels %{
    "fixed" => "Fixed",
    "create_ticket" => "Ticket created",
    "accepted_risk" => "Whitelisted",
    "not_affected" => "Not affected",
    "mitigated" => "Mitigated by a control",
    "request_remediation" => "Remediation requested",
    "investigate" => "Investigation requested",
    "request_verification" => "Verification requested (not verified)"
  }

  defmodule Decision do
    use Ecto.Schema
    import Ecto.Changeset

    schema "advisory_decisions" do
      field :cve, :string
      field :decision, :string
      field :reason, :string
      field :actor, :string
      field :decided_at, :utc_datetime
      field :expires_at, :utc_datetime
      field :work_owner, :string
      field :due_on, :date
      field :operation_id, :string
      field :metadata, :map, default: %{}
      belongs_to :placement, ImagePlacement
      belongs_to :supersedes, __MODULE__

      timestamps(type: :utc_datetime)
    end

    @type t :: %__MODULE__{}

    def changeset(decision, attrs) do
      decision
      |> cast(
        attrs,
        [
          :cve,
          :placement_id,
          :decision,
          :reason,
          :actor,
          :decided_at,
          :expires_at,
          :work_owner,
          :due_on,
          :operation_id,
          :metadata
        ],
        empty_values: []
      )
      |> validate_required([:cve, :decision, :actor, :decided_at])
      |> validate_comment()
      |> validate_inclusion(
        :decision,
        Triage.Decisions.decisions() ++ Triage.Decisions.work_actions()
      )
      |> validate_expiry()
      |> validate_work()
    end

    defp validate_comment(changeset) do
      if get_field(changeset, :decision) in ["fixed", "accepted_risk", "create_ticket"],
        do: changeset,
        else: changeset |> validate_required([:reason]) |> validate_length(:reason, min: 3)
    end

    defp validate_work(changeset) do
      if get_field(changeset, :decision) == "create_ticket" do
        validate_required(changeset, [:placement_id])
      else
        validate_legacy_work(changeset)
      end
    end

    defp validate_legacy_work(changeset) do
      if get_field(changeset, :decision) in Triage.Decisions.work_actions() do
        validate_required(changeset, [:placement_id, :work_owner, :due_on, :expires_at])
      else
        changeset
      end
    end

    # An accepted risk without an end date never expires, so it is refused at
    # write time rather than becoming permanent by omission.
    defp validate_expiry(changeset) do
      if get_field(changeset, :decision) in Triage.Decisions.expiry_required() do
        validate_required(changeset, [:expires_at],
          message:
            "is required for accepted risk: an acceptance without an end date never expires"
        )
      else
        changeset
      end
    end
  end

  @doc "The decision vocabulary."
  @spec decisions() :: [String.t()]
  def decisions, do: @decisions

  def work_actions, do: @work_actions

  @doc "The decisions that must carry an expiry."
  @spec expiry_required() :: [String.t()]
  def expiry_required, do: @expiry_required

  @doc "Human label for a decision value."
  @spec label(String.t()) :: String.t()
  def label(decision), do: Map.get(@labels, decision, "Unknown decision")

  @doc """
  Records a decision. `:decided_at` defaults to the current time; pass it
  explicitly to record a retrospective decision.

  Returns `{:ok, Decision.t()}`, `{:error, changeset}`, or
  `{:error, :unknown_cve}` when no finding in this estate carries that CVE — a
  decision for an advisory nothing recorded is a typo, not a risk acceptance.
  """
  @spec record(map()) :: {:ok, Decision.t()} | {:error, Ecto.Changeset.t() | :unknown_cve}
  def record(attrs) when is_map(attrs) do
    attrs =
      attrs
      |> Map.put_new(:decided_at, DateTime.utc_now())
      |> Map.put_new(:placement_id, nil)

    with {:ok, cve} <- normalize_cve(Map.get(attrs, :cve)),
         :ok <- ensure_cve_known(cve) do
      previous = latest_for_scope(cve, attrs.placement_id)

      %Decision{supersedes_id: previous && previous.id}
      |> Decision.changeset(Map.put(attrs, :cve, cve))
      |> Repo.insert()
    end
  end

  def record(_other), do: {:error, :invalid_decision}

  @doc """
  Latest effective whole-advisory decision per CVE. Placement decisions never
  masquerade as advisory-wide coverage. Future decisions do not supersede an
  effective row; an expired replacement never resurrects an older acceptance.
  """
  @spec latest_by_cve([String.t()], DateTime.t()) :: %{optional(String.t()) => map()}
  def latest_by_cve(cves, now \\ DateTime.utc_now()) do
    cves
    |> latest_by_scope(now)
    |> Enum.flat_map(fn
      {{cve, nil}, decision} -> [{cve, decision}]
      _ -> []
    end)
    |> Map.new()
  end

  @doc "Latest effective decision for each exact `{cve, placement_id}` scope."
  def latest_by_scope(cves, now \\ DateTime.utc_now())
  def latest_by_scope([], _now), do: %{}

  def latest_by_scope(cves, now) when is_list(cves) do
    from(d in Decision,
      where: d.cve in ^cves and d.decided_at <= ^now,
      distinct: [d.cve, d.placement_id],
      order_by: [asc: d.cve, asc: d.placement_id, desc: d.decided_at, desc: d.id]
    )
    |> Repo.all()
    |> Map.new(&{{&1.cve, &1.placement_id}, decorate(&1, now)})
  end

  @doc """
  The later of two decisions by recorded chronology — `decided_at` at
  microsecond precision, with the row id as tie-breaker. This is the shared
  precedence between a scoped and a whole-advisory decision that both claim a
  placement: the newest effective record wins, never the narrower or wider
  scope. A `nil` passes through unchanged.
  """
  @spec effective(map() | nil, map() | nil) :: map() | nil
  def effective(nil, other), do: other
  def effective(other, nil), do: other

  def effective(a, b) do
    if chronology(a) >= chronology(b), do: a, else: b
  end

  defp chronology(%{decided_at: decided_at, id: id}),
    do: {DateTime.to_unix(decided_at, :microsecond), id}

  @doc """
  Active coverage for one placement from the latest effective scoped or global
  decision, chosen by `effective/2` chronology. A newer scoped replacement
  takes precedence over an older global claim; if it expires, that older claim
  must not silently become active again. Call with `latest_by_scope/2`, which
  already excludes future decisions.
  """
  def covering_decision(decisions, cve, placement_id) do
    latest = effective(decisions[{cve, nil}], decisions[{cve, placement_id}])

    if active?(latest), do: latest
  end

  @doc "Append-only decision history for one advisory, newest first."
  @spec history_for_cve(String.t(), DateTime.t()) :: [map()]
  def history_for_cve(cve, now \\ DateTime.utc_now()) when is_binary(cve) do
    from(d in Decision, where: d.cve == ^cve, order_by: [desc: d.decided_at, desc: d.id])
    |> Repo.all()
    |> Enum.map(&decorate(&1, now))
  end

  @doc "Every decision decided in `[from, to)`, newest first."
  @spec list_between(DateTime.t(), DateTime.t()) :: [map()]
  def list_between(from, to) when is_struct(from, DateTime) and is_struct(to, DateTime) do
    from(d in Decision,
      where: d.decided_at >= ^from and d.decided_at < ^to,
      order_by: [desc: d.decided_at, desc: d.id]
    )
    |> Repo.all()
    |> Enum.map(&decorate(&1, DateTime.utc_now()))
  end

  @doc "`true` only when the decision still covers its advisory."
  @spec active?(map()) :: boolean()
  def active?(%{state: :active}), do: true
  def active?(_other), do: false

  @doc "State at `now`; future decisions are pending and cover nothing."
  @spec state(Decision.t(), DateTime.t()) :: :pending | :active | :expired
  def state(%Decision{} = decision, now) do
    cond do
      DateTime.compare(decision.decided_at, now) == :gt ->
        :pending

      is_nil(decision.expires_at) ->
        :active

      DateTime.compare(decision.expires_at, now) == :lt ->
        :expired

      DateTime.compare(decision.expires_at, now) == :eq and
          decision.metadata["expiry_boundary"] == "exclusive" ->
        :expired

      true ->
        :active
    end
  end

  defp decorate(decision, now) do
    %{
      id: decision.id,
      cve: decision.cve,
      decision: decision.decision,
      label: label(decision.decision),
      state: state(decision, now),
      reason: decision.reason,
      actor: decision.actor,
      decided_at: decision.decided_at,
      expires_at: decision.expires_at,
      placement_id: decision.placement_id,
      supersedes_id: decision.supersedes_id,
      work_owner: decision.work_owner,
      due_on: decision.due_on,
      metadata: decision.metadata,
      operation_id: decision.operation_id
    }
  end

  defp normalize_cve(cve) when is_binary(cve) do
    case cve |> String.trim() |> String.upcase() do
      "" -> {:error, :invalid_decision}
      normalized -> {:ok, normalized}
    end
  end

  defp normalize_cve(_other), do: {:error, :invalid_decision}

  defp ensure_cve_known(cve) do
    if Repo.exists?(from(f in Finding, where: f.cve == ^cve)),
      do: :ok,
      else: {:error, :unknown_cve}
  end

  defp latest_for_scope(cve, nil) do
    Repo.one(
      from(d in Decision,
        where: d.cve == ^cve and is_nil(d.placement_id),
        order_by: [desc: d.decided_at, desc: d.id],
        limit: 1
      )
    )
  end

  defp latest_for_scope(cve, placement_id) do
    Repo.one(
      from(d in Decision,
        where: d.cve == ^cve and d.placement_id == ^placement_id,
        order_by: [desc: d.decided_at, desc: d.id],
        limit: 1
      )
    )
  end
end
