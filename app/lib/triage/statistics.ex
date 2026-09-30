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
  alias Triage.Inventory.{Finding, FindingEvent, ImagePlacement}
  alias Triage.Repo
  alias Triage.Workspace

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

  ## Handling statistics: the Statistics page and its CSV export

  @periods %{"30d" => 30, "90d" => 90, "12m" => 365, "all" => nil}
  @severity_rank %{"CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1}

  @doc "Statistics periods by URL value, with their length in days (`nil` is all time)."
  def periods, do: @periods

  @doc """
  One row per CVE and deployment, for the Statistics page and its CSV export.

    * `observed_at` - when the scanner first recorded the CVE on the
      deployment's image: the earlier of the finding's `first_seen` and its
      first `appeared` event, as the Timeline counts detections.
    * `first_action` - the first decision for this deployment, or for every
      deployment of the CVE, made at or after `observed_at`: whitelist, marked
      fixed or ticket, with who made it.
    * `gone_at` - when the scanner stopped reporting it: the latest
      `resolved_at` once every occurrence is resolved, or the deployment's
      `last_seen` once it is retired. `nil` while it is still observed.
    * `outcome` - how it was handled: the first action, or "Disappeared on its
      own" when it stopped being observed before any action. A fix the scanner
      then stopped reporting is "Fixed, confirmed by scan".

  Filters are the Triage team/environment filters; reference data is excluded
  exactly as in Triage.
  """
  def deployment_rows(filters \\ %{}, now \\ DateTime.utc_now()) do
    targets = Workspace.targets(Map.take(filters, ["team", "environment"]), now)
    decisions = targets |> Enum.map(& &1.cve) |> Enum.uniq() |> decisions_for(now)
    appeared = first_appearances(targets)

    targets
    |> Enum.map(&deployment_row(&1, Map.get(decisions, &1.cve, []), appeared, now))
    |> Enum.sort_by(&{&1.cve, &1.team || "", &1.environment || "", &1.namespace || ""})
  end

  @doc """
  Groups `deployment_rows/2` into one row per CVE. A CVE counts as handled only
  once every deployment is (`handled_at` is the last of them), and it is open
  while any deployment still needs a decision.
  """
  def cve_rows(rows, now \\ DateTime.utc_now()) do
    rows
    |> Enum.group_by(& &1.cve)
    |> Enum.map(fn {cve, deployments} -> cve_row(cve, deployments, now) end)
  end

  @doc """
  The Statistics page: CVEs open now, CVEs handled since the period start, and
  headline numbers for the period. Open CVEs are never filtered by period.
  """
  def report(filters, period, now \\ DateTime.utc_now()) do
    since = period_start(period, now)
    rows = deployment_rows(filters, now)
    cves = cve_rows(rows, now)

    open =
      cves
      |> Enum.filter(&(&1.status == :open))
      |> Enum.sort_by(&{-(&1.days_open || 0), &1.cve})

    handled =
      cves
      |> Enum.filter(&in_period?(&1.handled_at, since))
      |> Enum.sort_by(& &1.handled_at, {:desc, DateTime})

    %{
      since: since,
      open: open,
      handled: handled,
      summary: %{
        open: length(open),
        oldest_open_days: open |> Enum.map(& &1.days_open) |> Enum.max(fn -> nil end),
        handled: length(handled),
        median_days_to_first_action:
          cves
          |> Enum.filter(&(&1.first_action && in_period?(&1.first_action.at, since)))
          |> Enum.map(& &1.days_to_first_action)
          |> median(),
        median_days_to_handle: handled |> Enum.map(& &1.days_to_handle) |> median(),
        outcomes:
          rows
          |> Enum.filter(&in_period?(&1.handled_at, since))
          |> Enum.frequencies_by(& &1.outcome)
      }
    }
  end

  @doc "Deployment rows of the CVEs the Statistics page lists: open now or handled in the period."
  def export_rows(filters, period, now \\ DateTime.utc_now()) do
    since = period_start(period, now)
    rows = deployment_rows(filters, now)

    listed =
      rows
      |> cve_rows(now)
      |> Enum.filter(&(&1.status == :open or in_period?(&1.handled_at, since)))
      |> MapSet.new(& &1.cve)

    Enum.filter(rows, &MapSet.member?(listed, &1.cve))
  end

  defp deployment_row(target, decisions, appeared, now) do
    observed_at =
      target.findings
      |> Enum.map(&earliest([&1.first_seen, Map.get(appeared, &1.id)]))
      |> earliest()

    gone? = not target.active?
    gone_at = gone_at(target)
    action = first_action(decisions, target.id, observed_at)

    %{
      cve: target.cve,
      severity: target.findings |> Enum.map(& &1.severity) |> highest(),
      packages:
        target.findings
        |> Enum.map(&"#{&1.package_name} #{&1.package_version}")
        |> Enum.uniq()
        |> Enum.sort(),
      team: target.placement.owner,
      environment: target.placement.environment,
      namespace: target.placement.namespace,
      image: image_label(target.image),
      observed_at: observed_at,
      first_action: action,
      days_to_first_action: action && whole_days(observed_at, action.at),
      gone?: gone?,
      gone_at: gone_at,
      days_until_gone: if(gone?, do: whole_days(observed_at, gone_at)),
      days_open: if(not gone?, do: whole_days(observed_at, now)),
      handled_at: earliest([action && action.at, gone_at]),
      outcome: outcome(action, gone?, gone_at),
      current_state: current_state(target),
      whitelisted_until: whitelisted_until(target)
    }
  end

  defp cve_row(cve, deployments, now) do
    observed_at = deployments |> Enum.map(& &1.observed_at) |> earliest()

    first_action =
      deployments
      |> Enum.map(& &1.first_action)
      |> Enum.reject(&is_nil/1)
      |> Enum.min_by(& &1.at, DateTime, fn -> nil end)

    handled = Enum.map(deployments, & &1.handled_at)
    handled_at = if Enum.all?(handled), do: latest(handled)
    gone? = Enum.all?(deployments, & &1.gone?)
    open = Enum.count(deployments, &(&1.current_state == "Needs decision"))

    %{
      cve: cve,
      severity: deployments |> Enum.map(& &1.severity) |> highest(),
      packages: deployments |> Enum.flat_map(& &1.packages) |> Enum.uniq() |> Enum.sort(),
      deployments: length(deployments),
      open_deployments: open,
      observed_at: observed_at,
      first_action: first_action,
      days_to_first_action: first_action && whole_days(observed_at, first_action.at),
      handled_at: handled_at,
      days_to_handle: handled_at && whole_days(observed_at, handled_at),
      gone_at: if(gone?, do: deployments |> Enum.map(& &1.gone_at) |> latest()),
      outcome: combined(deployments, & &1.outcome),
      current_state: combined(deployments, & &1.current_state),
      status: cve_status(open, gone?),
      days_open: if(open > 0, do: whole_days(observed_at, now))
    }
  end

  defp cve_status(open, _gone?) when open > 0, do: :open
  defp cve_status(_open, true), do: :gone
  defp cve_status(_open, false), do: :handled

  # One label when every deployment agrees, otherwise each label with its count.
  defp combined(deployments, label) do
    case deployments |> Enum.frequencies_by(label) |> Enum.sort_by(fn {l, n} -> {-n, l} end) do
      [{only, _count}] -> only
      counts -> Enum.map_join(counts, ", ", fn {l, n} -> "#{l} (#{n})" end)
    end
  end

  defp gone_at(%{active?: true}), do: nil

  defp gone_at(%{findings: findings, placement: placement}) do
    resolved = Enum.map(findings, & &1.resolved_at)

    earliest([
      if(findings != [] and Enum.all?(resolved), do: latest(resolved)),
      if(not placement.active, do: placement.last_seen)
    ])
  end

  # Decisions arrive oldest first; a decision without a placement covers every
  # deployment of its CVE. Only decisions at or after observation count, as in
  # the Timeline's response timing.
  defp first_action(decisions, placement_id, observed_at) do
    Enum.find_value(decisions, fn d ->
      if (is_nil(d.placement_id) or d.placement_id == placement_id) and
           (is_nil(observed_at) or DateTime.compare(d.decided_at, observed_at) != :lt) do
        %{
          kind: d.decision,
          label: action_label(d.decision),
          at: d.decided_at,
          by: d.actor,
          reason: d.reason,
          ticket_url: (d.metadata || %{})["ticket_url"]
        }
      end
    end)
  end

  defp action_label("accepted_risk"), do: "Whitelisted"
  defp action_label("fixed"), do: "Marked fixed"
  defp action_label("create_ticket"), do: "Ticket created"
  defp action_label(other), do: Decisions.label(other)

  defp outcome(nil, true, _gone_at), do: "Disappeared on its own"
  defp outcome(nil, false, _gone_at), do: "Open"

  defp outcome(action, gone?, gone_at) do
    if gone? and gone_before?(gone_at, action.at),
      do: "Disappeared on its own",
      else: action_outcome(action.kind, gone?, action.label)
  end

  defp gone_before?(nil, _at), do: false
  defp gone_before?(gone_at, at), do: DateTime.compare(gone_at, at) == :lt

  defp action_outcome("fixed", true, _label), do: "Fixed, confirmed by scan"
  defp action_outcome("fixed", false, _label), do: "Fixed, not yet confirmed"
  defp action_outcome("accepted_risk", _gone?, _label), do: "Whitelisted"
  defp action_outcome("create_ticket", _gone?, _label), do: "Ticket created"
  defp action_outcome(_kind, _gone?, label), do: label

  defp current_state(%{active?: false}), do: "No longer observed"
  defp current_state(%{covered?: true, decision: %{decision: "accepted_risk"}}), do: "Whitelisted"
  defp current_state(%{covered?: true, decision: %{decision: "fixed"}}), do: "Fix reported"
  defp current_state(%{covered?: true, decision: %{decision: "create_ticket"}}), do: "Ticket open"
  defp current_state(%{covered?: true, decision: %{decision: other}}), do: Decisions.label(other)
  defp current_state(_target), do: "Needs decision"

  # The last day an active whitelist still applies (it expires at the start of `expires_at`).
  defp whitelisted_until(%{
         active?: true,
         covered?: true,
         decision: %{decision: "accepted_risk", expires_at: %DateTime{} = expires_at}
       }),
       do: expires_at |> DateTime.add(-1, :second) |> DateTime.to_date()

  defp whitelisted_until(_target), do: nil

  defp decisions_for([], _now), do: %{}

  defp decisions_for(cves, now) do
    from(d in Decision,
      where: d.cve in ^cves and d.decided_at <= ^now,
      order_by: [asc: d.decided_at, asc: d.id]
    )
    |> Repo.all()
    |> Enum.group_by(& &1.cve)
  end

  defp first_appearances(targets) do
    case targets |> Enum.flat_map(& &1.findings) |> Enum.map(& &1.id) |> Enum.uniq() do
      [] ->
        %{}

      ids ->
        from(e in FindingEvent,
          where: e.finding_id in ^ids and e.event == "appeared",
          group_by: e.finding_id,
          select: {e.finding_id, min(e.occurred_at)}
        )
        |> Repo.all()
        |> Map.new()
    end
  end

  defp image_label(%{repository: repository, tag: tag})
       when is_binary(repository) and is_binary(tag) and tag != "",
       do: "#{repository}:#{tag}"

  defp image_label(%{repository: repository}) when is_binary(repository), do: repository
  defp image_label(%{digest: digest}), do: digest

  defp highest(severities) do
    severities
    |> Enum.map(&(&1 && String.upcase(&1)))
    |> Enum.filter(&Map.has_key?(@severity_rank, &1))
    |> Enum.max_by(&Map.fetch!(@severity_rank, &1), fn -> nil end)
  end

  defp period_start(period, now) do
    case Map.fetch(@periods, period) do
      {:ok, nil} -> nil
      {:ok, days} -> DateTime.add(now, -days, :day)
      :error -> DateTime.add(now, -90, :day)
    end
  end

  defp in_period?(nil, _since), do: false
  defp in_period?(_at, nil), do: true
  defp in_period?(at, since), do: DateTime.compare(at, since) != :lt

  defp whole_days(nil, _to), do: nil
  defp whole_days(_from, nil), do: nil
  defp whole_days(from, to), do: max(div(DateTime.diff(to, from, :second), 86_400), 0)

  defp earliest(dates), do: dates |> Enum.reject(&is_nil/1) |> Enum.min(DateTime, fn -> nil end)
  defp latest(dates), do: dates |> Enum.reject(&is_nil/1) |> Enum.max(DateTime, fn -> nil end)
end
