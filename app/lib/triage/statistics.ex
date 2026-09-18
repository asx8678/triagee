defmodule Triage.Statistics do
  @moduledoc """
  Per-advisory observation timing over the local finding history, for the
  read-only Statistics view.

  For each advisory (CVE) this reports when an occurrence was first recorded
  locally (`first_seen`), the most recent recorded disappearance
  (`resolved_at` = "no longer observed in an eligible local collection"),
  and how many days elapsed in between — or, when occurrences remain open,
  how many days the advisory has been continuously observed.

  Durations are compared with LOCAL review targets keyed by the highest
  scanner severity recorded for the advisory. A target is management review
  discipline only: disappearance from a collection is not verified
  remediation, first observation is not CVE publication or scan completion,
  and these comparisons say nothing about exposure, approval, or a clean
  estate.
  """

  import Ecto.Query

  alias Triage.Decisions
  alias Triage.Decisions.Decision
  alias Triage.Inventory.{Finding, ImagePlacement}
  alias Triage.Repo

  # Local review targets in days from first local observation, by the highest
  # scanner severity recorded for the advisory.
  @target_days %{"CRITICAL" => 7, "HIGH" => 14, "MEDIUM" => 30, "LOW" => 60}
  @default_target_days 90
  @severity_names %{4 => "CRITICAL", 3 => "HIGH", 2 => "MEDIUM", 1 => "LOW"}

  # Order of presentation in the view: open advisories past their local
  # target first, then other open advisories, then cleared history.
  @status_rank %{
    open_past_target: 0,
    open_within_target: 1,
    cleared_past_target: 2,
    cleared_within_target: 3
  }

  @typedoc """
  One observational-timing row per advisory. `days` is an elapsed-day count
  (truncated to whole days). `status` is one of `:open_within_target`,
  `:open_past_target`, `:cleared_within_target` or `:cleared_past_target`.
  """
  @type lifecycle :: %{
          cve: String.t(),
          severity: String.t() | nil,
          environments: [String.t()],
          images: non_neg_integer(),
          packages: non_neg_integer(),
          occurrences: non_neg_integer(),
          open_count: non_neg_integer(),
          suppressed_count: non_neg_integer(),
          reopened_count: non_neg_integer(),
          first_seen: DateTime.t() | nil,
          resolved_at: DateTime.t() | nil,
          open?: boolean(),
          days: non_neg_integer(),
          target: pos_integer(),
          on_target?: boolean(),
          status:
            :open_within_target
            | :open_past_target
            | :cleared_within_target
            | :cleared_past_target
        }

  @doc """
  The local review target in days for one highest-recorded severity value.

  Unreported or unrecognized severities receive the most permissive target
  (#{@default_target_days} days); the comparison never invents a stricter
  policy than the recorded scanner data supports.
  """
  def target_days(nil), do: @default_target_days
  def target_days(severity), do: Map.get(@target_days, severity, @default_target_days)

  @doc """
  Returns one timing row per advisory ever recorded in local inventory,
  ordered for the statistics view: open advisories past their local target
  first, then open advisories within target, then cleared advisories (past
  target before within target); ties break on longer duration, then
  advisory id.

  `now` anchors "days still observed" for advisories with open occurrences;
  callers pass an explicit value for deterministic testing.
  """
  @spec advisory_lifecycles(DateTime.t()) :: [lifecycle()]
  def advisory_lifecycles(now \\ DateTime.utc_now()) do
    environments = environments_by_cve()
    now = DateTime.truncate(now, :second)
    decisions = decisions_by_cve(now)

    Finding
    |> group_by([f], f.cve)
    |> select([f], %{
      cve: f.cve,
      severity_rank:
        fragment(
          "max(case ? when 'CRITICAL' then 4 when 'HIGH' then 3 when 'MEDIUM' then 2 when 'LOW' then 1 else 0 end)",
          f.severity
        ),
      images: count(f.image_id, :distinct),
      packages: count(f.package_name, :distinct),
      occurrences: count(f.id),
      open_count: filter(count(f.id), is_nil(f.resolved_at)),
      suppressed_count: filter(count(f.id), f.suppressed),
      reopened_count: filter(count(f.id), f.reopen_count > 0),
      first_seen: min(f.first_seen),
      resolved_at: max(f.resolved_at)
    })
    |> Repo.all()
    |> Enum.map(&decorate(&1, environments, now))
    |> Enum.map(&with_decision_timing(&1, decisions))
    |> Enum.sort_by(fn row ->
      {Map.fetch!(@status_rank, row.status), -row.days, row.cve}
    end)
  end

  @doc """
  Headline counts for the statistics view. `median_clear_days` is the median
  of the observed durations of advisories whose occurrences are all cleared
  (`nil` when none have cleared yet); it is an observation statistic, not a
  measured remediation time.
  """
  @spec summarize([lifecycle()]) :: %{
          total: non_neg_integer(),
          open: non_neg_integer(),
          past_target: non_neg_integer(),
          median_clear_days: number() | nil,
          median_decision_days: number() | nil,
          decisions_recorded: non_neg_integer()
        }
  def summarize(rows) when is_list(rows) do
    %{
      total: length(rows),
      open: Enum.count(rows, & &1.open?),
      past_target: Enum.count(rows, &(not &1.on_target?)),
      median_decision_days:
        rows
        |> Enum.map(& &1.first_advisory_decision_seconds)
        |> Enum.reject(&is_nil/1)
        |> Enum.map(&(&1 / 86_400))
        |> median(),
      decisions_recorded: Enum.count(rows, &(&1.decision_timings != [])),
      median_clear_days:
        rows
        |> Enum.reject(& &1.open?)
        |> Enum.map(& &1.days)
        |> median()
    }
  end

  # All recorded placement environments for images carrying the advisory,
  # including inactive placements — display context only, never attribution
  # of a past event to an environment.
  defp environments_by_cve do
    Finding
    |> join(:inner, [f], p in ImagePlacement, on: p.image_id == f.image_id)
    |> group_by([f], f.cve)
    |> select([f, p], {f.cve, fragment("array_agg(distinct ?)", p.environment)})
    |> Repo.all()
    |> Map.new()
  end

  defp decorate(row, environments, now) do
    severity = Map.get(@severity_names, row.severity_rank)
    open? = row.open_count > 0
    end_at = if open?, do: now, else: row.resolved_at
    days = days_between(row.first_seen, end_at)
    target = target_days(severity)
    on_target? = days <= target

    status =
      case {open?, on_target?} do
        {true, true} -> :open_within_target
        {true, false} -> :open_past_target
        {false, true} -> :cleared_within_target
        {false, false} -> :cleared_past_target
      end

    row
    |> Map.delete(:severity_rank)
    |> Map.merge(%{
      severity: severity,
      environments: environments |> Map.get(row.cve, []) |> Enum.sort(),
      open?: open?,
      days: days,
      elapsed_seconds: elapsed_seconds(row.first_seen, end_at),
      target: target,
      on_target?: on_target?,
      status: status
    })
  end

  # Read the append-only history in one batch, not one query per advisory.
  # A historical decision time is not evidence of current whole-CVE coverage.
  defp decisions_by_cve(now) do
    from(d in Decision, order_by: [asc: d.decided_at, asc: d.id])
    |> Repo.all()
    |> Enum.group_by(& &1.cve)
    |> Map.new(fn {cve, history} ->
      superseded = MapSet.new(history, & &1.supersedes_id)

      timings =
        Enum.map(history, fn decision ->
          state = decision_state(decision, superseded, now)

          %{
            id: decision.id,
            label: Decisions.label(decision.decision),
            decided_at: decision.decided_at,
            expires_at: decision.expires_at,
            placement_id: decision.placement_id,
            state: state
          }
        end)

      {cve, timings}
    end)
  end

  defp decision_state(decision, superseded, now) do
    cond do
      MapSet.member?(superseded, decision.id) -> :superseded
      DateTime.compare(decision.decided_at, now) == :gt -> :scheduled
      true -> Decisions.state(decision, now)
    end
  end

  defp with_decision_timing(row, decisions) do
    timings =
      decisions
      |> Map.get(row.cve, [])
      |> Enum.map(&Map.put(&1, :elapsed_seconds, elapsed_seconds(row.first_seen, &1.decided_at)))

    first_advisory_decision =
      Enum.find(timings, &(is_nil(&1.placement_id) and &1.state != :scheduled))

    Map.merge(row, %{
      decision_timings: timings,
      first_advisory_decision_seconds:
        first_advisory_decision && first_advisory_decision.elapsed_seconds
    })
  end

  @doc "Elapsed seconds when both dates exist and are chronological; otherwise unknown."
  def elapsed_seconds(nil, _end_at), do: nil
  def elapsed_seconds(_start_at, nil), do: nil

  def elapsed_seconds(start_at, end_at) do
    case DateTime.diff(end_at, start_at, :second) do
      seconds when seconds >= 0 -> seconds
      _ -> nil
    end
  end

  defp days_between(nil, _end_at), do: 0
  defp days_between(_start, nil), do: 0
  defp days_between(start_at, end_at), do: max(DateTime.diff(end_at, start_at, :day), 0)

  defp median([]), do: nil

  defp median(values) do
    sorted = Enum.sort(values)
    n = length(sorted)
    mid = div(n, 2)

    if rem(n, 2) == 1 do
      Enum.at(sorted, mid)
    else
      (Enum.at(sorted, mid - 1) + Enum.at(sorted, mid)) / 2
    end
  end
end
