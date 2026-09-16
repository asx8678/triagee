defmodule Triage.Timeline do
  @default_weeks 8
  @min_weeks 1
  @max_weeks 12
  @day_row_limit Triage.Timeline.Days.row_limit()
  @event_limit 2_000
  @lane_limit 50
  @chart_lane_limit 12
  @case_limit Triage.Timeline.History.case_page_size()
  @scope_max 120
  @unsafe_text ~r/[\x00-\x1F\x7F]/
  @window_opt_keys [:weeks, :owner, :environment, :cve]
  @opt_keys @window_opt_keys ++ [:events_after, :cases_after]
  @weekdays ~w(Mon Tue Wed Thu Fri Sat Sun)

  @moduledoc """
  Read-only CVE timeline over the append-only local records.

  Two axes become one picture: recorded observation days stack vertically
  (newest first) and each CVE reads as an arrow across the days it was
  recorded on, joined where two adjacent days both have a recorded
  observation.

    * One row per recorded `finding_events` entry, grouped into an explicit
      day band. A day with no recorded event is rendered as an empty band:
      absence of an event is no recorded observation, never a clean day.
    * `appeared` is a first recorded observation, `resolved` is "no longer
      observed in an eligible collection" and `reopened` is "observed again".
      None of these is verified remediation, and a disappearance is not a fix.
    * `suppressed` is the CURRENT imported scanner flag. There is no recorded
      suppression date, author or event, and the interface must not imply one.
    * A vertical connector between adjacent day bands means the same CVE has a
      recorded observation on both days. It renders recorded observations; it
      is never a claim of continuous presence.
    * The connected chart draws one line per CVE across the window's days: a
      solid segment for two adjacent recorded days and a dashed segment for two
      recorded days with none recorded in between. It is decorative by
      construction - every marker it draws is already listed as text in the day
      bands and the lane table - and a line is never a claim of presence between
      observations.
    * A judged marker means a saved assessment row exists. It never means
      approved, accepted, mitigated, fixed or resolved.
    * Event rows carry the CURRENT local finding and image metadata joined to
      an existing event, not the facts captured when the event happened.
    * Recorded observation times come from the imported snapshot and can be
      backdated. They are not scan completion times, and import runs are not
      persisted, so no true scan time exists to display.

  The window projection is bounded: a #{@min_weeks}-#{@max_weeks} week window (default
  #{@default_weeks}), at most #{@day_row_limit} rows per day band,
  #{@event_limit} events, #{@lane_limit} lanes, #{@case_limit} cases per CVE and
  #{@chart_lane_limit} chart tracks, each with an explicit truncation flag. Invalid input is rejected before any
  query and nothing here writes. Drawer events use chronological keyset pages;
  case histories are bounded previews with links to the complete case record.
  """

  import Ecto.Query

  alias Triage.Activity
  alias Triage.Cases.{Review, ReviewCase}
  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}
  alias Triage.Repo
  alias Triage.Timeline.History

  @doc """
  Loads the windowed timeline.

  `opts` must be a keyword list accepting only `:weeks`, `:owner`,
  `:environment` and `:cve`. Any other request shape - non-lists,
  non-keyword lists, maps, structs, and lists with unknown or duplicate keys -
  returns `{:error, :invalid_request}` before any query. `:weeks` is `nil`
  (default #{@default_weeks}) or an integer in #{@min_weeks}..#{@max_weeks},
  otherwise `{:error, :invalid_window}`. `:owner`/`:environment` are `nil` or a
  plain valid-UTF-8 binary with no raw NUL/C0/DEL, at most #{@scope_max}
  characters after trimming; blank is the intentional All choice and any other
  value is `{:error, :invalid_scope}`. `:cve` is `nil` or a nonblank value
  under the same text contract, otherwise `{:error, :invalid_cve}`.

  Returns `{:ok, view}` with `:window`, `:days` (newest first), `:grid`,
  `:lanes`, `:chart` and `:summary`.
  """
  @spec list_timeline(keyword()) :: {:ok, map()} | {:error, atom()}
  def list_timeline(opts \\ []) do
    with {:ok, req} <- validate(opts, @window_opt_keys) do
      {:ok, load(req)}
    end
  end

  @doc """
  Loads one CVE with full-history aggregate counts and a chronological page of
  lifecycle events, each with an `in_window?` marker. `:events_after` resumes
  after a scoped event id; `:cases_after` resumes after a scoped case id. Both
  cursors must be positive bigint integers (or nil). The detail lane reports
  `:observed_day_count` rather than retaining every historical observation date.

  Returns `{:error, :not_found}` when no finding records that CVE, and
  `{:error, :invalid_cve}` before any query for a malformed or missing value
  (including `nil`). Case histories use batched, bounded projections of the same
  stored records and formatter as the full case page. No snapshot payloads or
  idempotency tokens are loaded for these previews.
  """
  @spec cve_detail(String.t() | nil, keyword()) :: {:ok, map()} | {:error, atom()}
  def cve_detail(cve, opts \\ [])

  def cve_detail(nil, _opts), do: {:error, :invalid_cve}

  def cve_detail(cve, opts) do
    with true <- is_list(opts) and Keyword.keyword?(opts),
         {:ok, req} <- validate(Keyword.put(opts, :cve, cve), @opt_keys) do
      load_cve(req)
    else
      false -> {:error, :invalid_request}
      error -> error
    end
  end

  @doc """
  Sorted distinct nonblank owner and environment values from every recorded
  placement, active and inactive. Delegates to `Triage.Activity`, which already
  defines exactly this query, so the two feeds cannot drift apart.
  """
  def filter_options, do: Activity.event_filter_options()

  @doc "The supported window sizes, as `{label, weeks}`."
  def window_options do
    [
      {"Last 4 weeks", 4},
      {"Last 8 weeks", 8},
      {"Last 12 weeks", 12}
    ]
  end

  @doc "The default window size in weeks."
  def default_weeks, do: @default_weeks

  ## Request validation - completes before any query

  defp validate(opts, allowed_keys) when is_list(opts) do
    if Keyword.keyword?(opts) do
      keys = Keyword.keys(opts)

      cond do
        not Enum.all?(keys, &(&1 in allowed_keys)) -> {:error, :invalid_request}
        length(keys) != length(Enum.uniq(keys)) -> {:error, :invalid_request}
        true -> validate_values(opts)
      end
    else
      {:error, :invalid_request}
    end
  end

  defp validate(_opts, _keys), do: {:error, :invalid_request}

  defp validate_values(opts) do
    with {:ok, weeks} <- validate_weeks(Keyword.get(opts, :weeks)),
         {:ok, owner} <- validate_scope(Keyword.get(opts, :owner)),
         {:ok, environment} <- validate_scope(Keyword.get(opts, :environment)),
         {:ok, cve} <- validate_cve(Keyword.get(opts, :cve)),
         {:ok, events_after} <- validate_cursor(Keyword.get(opts, :events_after)),
         {:ok, cases_after} <- validate_cursor(Keyword.get(opts, :cases_after)),
         :ok <- history_selection(cve, events_after, cases_after) do
      {:ok,
       Map.merge(
         build_window(weeks, owner, environment, cve),
         %{events_after: events_after, cases_after: cases_after}
       )}
    end
  end

  defp validate_cursor(cursor) do
    if History.valid_cursor?(cursor), do: {:ok, cursor}, else: {:error, :invalid_cursor}
  end

  defp history_selection(nil, events, cases) when not is_nil(events) or not is_nil(cases),
    do: {:error, :invalid_cursor}

  defp history_selection(_cve, _events, _cases), do: :ok

  defp validate_weeks(nil), do: {:ok, @default_weeks}

  defp validate_weeks(weeks)
       when is_integer(weeks) and weeks >= @min_weeks and weeks <= @max_weeks,
       do: {:ok, weeks}

  defp validate_weeks(_weeks), do: {:error, :invalid_window}

  defp validate_scope(nil), do: {:ok, nil}
  defp validate_scope(value) when not is_binary(value), do: {:error, :invalid_scope}
  defp validate_scope(value), do: normalize_text(value, :invalid_scope)

  defp validate_cve(nil), do: {:ok, nil}
  defp validate_cve(value) when not is_binary(value), do: {:error, :invalid_cve}

  defp validate_cve(value) do
    case normalize_text(value, :invalid_cve) do
      {:ok, nil} -> {:error, :invalid_cve}
      other -> other
    end
  end

  # The same value contract as the existing read-side scope filters: raw valid
  # UTF-8 with no NUL/C0/DEL before trimming, at most 120 characters after
  # trimming, and blank meaning the intentional All choice.
  defp normalize_text(value, error) do
    cond do
      not String.valid?(value) -> {:error, error}
      Regex.match?(@unsafe_text, value) -> {:error, error}
      true -> trimmed(value, error)
    end
  end

  defp trimmed(value, error) do
    case String.trim(value) do
      "" -> {:ok, nil}
      trimmed -> if String.length(trimmed) > @scope_max, do: {:error, error}, else: {:ok, trimmed}
    end
  end

  # Whole weeks ending today, Monday-aligned, so the grid is a full rectangle
  # and the newest band is the current (partial) week.
  defp build_window(weeks, owner, environment, cve) do
    today = Date.utc_today()
    current_week = Date.beginning_of_week(today, :monday)
    first_week = Date.add(current_week, -7 * (weeks - 1))

    %{
      weeks: weeks,
      owner: owner,
      environment: environment,
      cve: cve,
      from: first_week,
      to: today,
      from_dt: DateTime.new!(first_week, ~T[00:00:00], "Etc/UTC"),
      to_dt: DateTime.new!(today, ~T[23:59:59], "Etc/UTC"),
      week_starts: Enum.map(0..(weeks - 1), &Date.add(first_week, 7 * &1))
    }
  end

  ## Load

  defp load(req) do
    {events, truncated?} = fetch_events(req)
    judged = fetch_judged_counts(req)
    days = Triage.Timeline.Days.build(req, events, judged)
    lanes = build_lanes(req, events)

    %{
      window: %{
        weeks: req.weeks,
        from: req.from,
        to: req.to,
        label: window_label(req),
        owner: req.owner,
        environment: req.environment
      },
      days: days,
      grid: build_grid(req, events),
      lanes: lanes,
      chart: build_chart(req, events, lanes),
      summary: summary(req, events, judged, days, lanes, truncated?)
    }
  end

  defp window_label(%{weeks: weeks, from: from, to: to}) do
    "Last #{weeks} weeks · #{Calendar.strftime(from, "%d %b")} to #{Calendar.strftime(to, "%d %b %Y")}"
  end

  # One SELECT: every recorded event inside the window, joined to its current
  # finding and image, newest recorded observation first. Bounded by
  # `@event_limit` with a sentinel row so truncation is visible rather than
  # silent.
  defp fetch_events(req) do
    # Bound a plain variable rather than an expression: `limit: ^expr` is only
    # reliably expanded by a full compile, not by in-process code reloading.
    fetch_limit = @event_limit + 1

    rows =
      from(e in FindingEvent,
        join: f in Finding,
        as: :finding,
        on: f.id == e.finding_id,
        join: i in Image,
        on: i.id == f.image_id,
        where: e.occurred_at >= ^req.from_dt and e.occurred_at <= ^req.to_dt,
        order_by: [desc: e.occurred_at, desc: e.id],
        limit: ^fetch_limit,
        select: {e, f, i}
      )
      |> apply_finding_scope(req)
      |> Repo.all()

    if length(rows) > @event_limit do
      {Enum.take(rows, @event_limit), true}
    else
      {rows, false}
    end
  end

  # Scoping means "events whose finding's image has a recorded placement
  # matching the filters", matching `Triage.Activity`: inactive placements
  # still match, and it is display scoping, never historical attribution.
  defp apply_finding_scope(query, %{owner: nil, environment: nil}), do: query

  defp apply_finding_scope(query, %{owner: owner, environment: nil}) do
    where(
      query,
      exists(
        from(p in ImagePlacement,
          where: p.image_id == parent_as(:finding).image_id and p.owner == ^owner,
          select: 1
        )
      )
    )
  end

  defp apply_finding_scope(query, %{owner: nil, environment: environment}) do
    where(
      query,
      exists(
        from(p in ImagePlacement,
          where: p.image_id == parent_as(:finding).image_id and p.environment == ^environment,
          select: 1
        )
      )
    )
  end

  defp apply_finding_scope(query, %{owner: owner, environment: environment}) do
    where(
      query,
      exists(
        from(p in ImagePlacement,
          where:
            p.image_id == parent_as(:finding).image_id and p.owner == ^owner and
              p.environment == ^environment,
          select: 1
        )
      )
    )
  end

  # Count by the case's own scope, not any team sharing its finding image.
  # At most one result per day in the requested window is loaded into memory.
  defp fetch_judged_counts(req) do
    from(c in ReviewCase,
      join: r in Review,
      on: r.case_id == c.id,
      where: r.inserted_at >= ^req.from_dt and r.inserted_at <= ^req.to_dt,
      group_by: fragment("?::date", r.inserted_at),
      select: {type(fragment("?::date", r.inserted_at), :date), count(r.id)}
    )
    |> apply_case_scope(req)
    |> Repo.all()
    |> Map.new()
  end

  ## Weekday x week grid

  # Cell intensity is the number of distinct CVEs whose FIRST recorded
  # observation falls on that date. A CVE appearing on two findings on the
  # same day is counted once.
  defp build_grid(req, events) do
    counts =
      events
      |> Enum.filter(fn {e, _f, _i} -> e.event == "appeared" end)
      |> Enum.map(fn {e, f, _i} -> {DateTime.to_date(e.occurred_at), f.cve} end)
      |> Enum.uniq()
      |> Enum.frequencies_by(&elem(&1, 0))

    %{
      max_count: counts |> Map.values() |> Enum.max(fn -> 0 end),
      weeks: Enum.map(req.week_starts, &%{start: &1, label: Calendar.strftime(&1, "%d %b")}),
      rows:
        Enum.map(1..7, fn iso ->
          %{
            iso_weekday: iso,
            weekday: Enum.at(@weekdays, iso - 1),
            cells:
              Enum.map(req.week_starts, fn week_start ->
                date = Date.add(week_start, iso - 1)

                %{
                  date: date,
                  week_start: week_start,
                  count: Map.get(counts, date, 0),
                  in_window?:
                    Date.compare(date, req.from) != :lt and Date.compare(date, req.to) != :gt,
                  in_future?: Date.compare(date, req.to) == :gt
                }
              end)
          }
        end)
    }
  end

  ## Chart

  # The connected-lane chart is built from the same recorded events the day
  # bands and the lane table use, so the picture cannot disagree with the
  # records it summarises. It is bounded to the most severe lanes; the lane
  # table still lists every lane, and the canvas states the bound.
  @chart_lane_limit 12

  defp build_chart(req, events, lanes) do
    by_cve = chart_days_by_cve(events)

    %{
      lane_limit: @chart_lane_limit,
      shown: min(lanes.total, @chart_lane_limit),
      total: lanes.total,
      dates: Enum.map(Date.range(req.from, req.to), &chart_date(&1, req.to)),
      tracks:
        lanes.rows
        |> Enum.take(@chart_lane_limit)
        |> Enum.map(&chart_track(&1, by_cve, req))
    }
  end

  defp chart_date(date, today) do
    %{
      date: date,
      iso_date: Date.to_iso8601(date),
      day: Calendar.strftime(date, "%d"),
      month: Calendar.strftime(date, "%b"),
      weekday: Calendar.strftime(date, "%a"),
      week_start?: date == Date.beginning_of_week(date, :monday),
      today?: date == today,
      label: Calendar.strftime(date, "%a %d %b %Y")
    }
  end

  defp chart_days_by_cve(events) do
    events
    |> Enum.group_by(fn {_e, f, _i} -> f.cve end)
    |> Map.new(fn {cve, rows} ->
      days =
        rows
        |> Enum.group_by(fn {e, _f, _i} -> DateTime.to_date(e.occurred_at) end)
        |> Map.new(fn {date, day_rows} ->
          {date,
           %{
             kinds:
               day_rows
               |> Enum.map(fn {e, _f, _i} -> e.event end)
               |> Enum.uniq()
               |> Enum.sort(),
             count: length(day_rows),
             suppressed?: Enum.any?(day_rows, fn {_e, f, _i} -> f.suppressed end)
           }}
        end)

      {cve, days}
    end)
  end

  defp chart_track(lane, by_cve, req) do
    days = Map.get(by_cve, lane.cve, %{})

    points =
      days
      |> Enum.filter(fn {date, _info} -> in_window?(date, req) end)
      |> Enum.sort_by(fn {date, _info} -> date end, Date)
      |> Enum.map(fn {date, info} ->
        %{
          date: date,
          iso_date: Date.to_iso8601(date),
          kinds: info.kinds,
          count: info.count,
          suppressed?: info.suppressed?,
          label: Calendar.strftime(date, "%a %d %b %Y")
        }
      end)

    %{
      cve: lane.cve,
      severity: lane.severity,
      state: lane.state,
      points: points,
      recorded_before?: before_window?(lane.first_seen, req.from)
    }
  end

  # A lane whose first recorded observation predates the window starts with an
  # entry tick instead of an implied beginning.
  defp before_window?(nil, _from), do: false

  defp before_window?(first_seen, from) do
    case first_seen do
      %DateTime{} = value -> Date.compare(DateTime.to_date(value), from) == :lt
      %NaiveDateTime{} = value -> Date.compare(NaiveDateTime.to_date(value), from) == :lt
      %Date{} = value -> Date.compare(value, from) == :lt
      _other -> false
    end
  end

  ## Lanes

  defp build_lanes(req, events) do
    grouped = Enum.group_by(events, fn {_e, f, _i} -> f.cve end)
    total = map_size(grouped)

    rows =
      grouped
      |> Enum.map(fn {cve, grouped_events} ->
        findings =
          grouped_events
          |> Enum.map(fn {_e, f, i} -> {f, i} end)
          |> Enum.uniq_by(fn {f, _i} -> f.id end)

        lane(cve, findings, Enum.map(grouped_events, &elem(&1, 0)), req)
      end)
      |> Enum.sort_by(fn lane -> {-severity_rank(lane.severity), lane.cve} end)

    {shown, rest} = Enum.split(rows, @lane_limit)
    cases = cases_by_cve(Enum.map(shown, & &1.cve), req)

    %{
      total: total,
      shown: length(shown),
      truncated_count: length(rest),
      rows: Enum.map(shown, fn lane -> enrich_lane(lane, Map.get(cases, lane.cve)) end)
    }
  end

  defp lane(cve, findings_rows, events, req) do
    findings = Enum.map(findings_rows, &elem(&1, 0))
    first = findings |> Enum.map(& &1.first_seen) |> Enum.reject(&is_nil/1)
    last = findings |> Enum.map(& &1.last_seen) |> Enum.reject(&is_nil/1)

    observed_dates =
      events |> Enum.map(&DateTime.to_date(&1.occurred_at)) |> Enum.uniq() |> Enum.sort(Date)

    most_severe =
      findings
      |> Enum.map(& &1.severity)
      |> Enum.reject(&is_nil/1)
      |> Enum.max_by(&severity_rank/1, fn -> nil end)

    head = hd(findings)

    %{
      cve: cve,
      severity: most_severe,
      package_name: head.package_name,
      package_version: head.package_version,
      fix: head.fix,
      url: head.url,
      finding_ids: findings |> Enum.map(& &1.id) |> Enum.sort(),
      occurrence_count: length(findings),
      open_count: Enum.count(findings, &is_nil(&1.resolved_at)),
      resolved_count: Enum.count(findings, &(not is_nil(&1.resolved_at))),
      suppressed_count: Enum.count(findings, & &1.suppressed),
      reopen_count: findings |> Enum.map(&(&1.reopen_count || 0)) |> Enum.max(fn -> 0 end),
      first_seen: min_or_nil(first),
      last_seen: max_or_nil(last),
      state:
        if(Enum.any?(findings, &is_nil(&1.resolved_at)), do: :open, else: :no_longer_observed),
      # Only set when every recorded occurrence is currently resolved: a partly
      # open CVE has no single "no longer observed" time to report.
      resolved_at: resolved_at(findings),
      observed_dates: observed_dates,
      window_observed_count: Enum.count(observed_dates, &in_window?(&1, req)),
      event_count: length(events),
      appeared_count: Enum.count(events, &(&1.event == "appeared")),
      resolved_events: Enum.count(events, &(&1.event == "resolved")),
      reopened_events: Enum.count(events, &(&1.event == "reopened")),
      first_seen_in_window?: in_window?(List.first(observed_dates), req),
      last_observed_in_window?: in_window?(List.last(observed_dates), req),
      images: findings_rows |> Enum.map(fn {_f, i} -> image_reference(i) end) |> Enum.uniq()
    }
  end

  # Cases are keyed by their own explicit scope, so a scoped view shows the
  # cases opened against that team's scope rather than another team's.
  defp cases_by_cve([], _req), do: %{}
  defp cases_by_cve(cves, req), do: cves |> case_query(req) |> History.case_summaries()

  defp case_query(cves, req) do
    from(c in ReviewCase,
      as: :case,
      join: f in Finding,
      as: :finding,
      on: f.id == c.finding_id,
      where: f.cve in ^cves
    )
    |> apply_case_scope(req)
  end

  defp apply_case_scope(query, %{owner: nil, environment: nil}), do: query

  defp apply_case_scope(query, %{owner: owner, environment: nil}),
    do: where(query, [c], c.owner == ^owner)

  defp apply_case_scope(query, %{owner: nil, environment: environment}),
    do: where(query, [c], c.environment == ^environment)

  defp apply_case_scope(query, %{owner: owner, environment: environment}),
    do: where(query, [c], c.owner == ^owner and c.environment == ^environment)

  defp enrich_lane(lane, summary) do
    Map.merge(
      lane,
      summary || %{cases: [], case_count: 0, judged_count: 0, cases_truncated_count: 0}
    )
  end

  ## Summary

  defp summary(req, events, judged, days, lanes, truncated?) do
    observed_days = Enum.count(days, & &1.observed?)

    %{
      weeks: req.weeks,
      from: req.from,
      to: req.to,
      days: length(days),
      observed_days: observed_days,
      empty_days: length(days) - observed_days,
      events: length(events),
      new_cves: new_cve_count(events),
      resolved: count_events(events, "resolved"),
      reopened: count_events(events, "reopened"),
      cves: events |> Enum.map(fn {_e, f, _i} -> f.cve end) |> Enum.uniq() |> length(),
      suppressed: suppressed_cve_count(events),
      judged: judged |> Map.values() |> Enum.sum(),
      lanes_total: lanes.total,
      lanes_shown: lanes.shown,
      truncated?: truncated?
    }
  end

  defp count_events(events, kind), do: Enum.count(events, fn {e, _f, _i} -> e.event == kind end)

  # Distinct CVEs whose first recorded observation falls inside the window, so
  # the summary and the weekday grid cannot disagree about "new".
  defp new_cve_count(events) do
    events
    |> Enum.filter(fn {e, _f, _i} -> e.event == "appeared" end)
    |> Enum.map(fn {_e, f, _i} -> f.cve end)
    |> Enum.uniq()
    |> length()
  end

  defp suppressed_cve_count(events) do
    events
    |> Enum.filter(fn {_e, f, _i} -> f.suppressed end)
    |> Enum.map(fn {_e, f, _i} -> f.cve end)
    |> Enum.uniq()
    |> length()
  end

  ## One-CVE detail

  defp load_cve(%{cve: cve} = req) do
    rows =
      from(f in Finding,
        as: :finding,
        join: i in Image,
        on: i.id == f.image_id,
        where: f.cve == ^cve,
        order_by: [asc: f.id],
        select: {f, i}
      )
      |> apply_finding_scope(req)
      |> Repo.all()

    case rows do
      [] -> {:error, :not_found}
      _ -> load_history(cve, rows, req)
    end
  end

  defp load_history(cve, rows, req) do
    finding_ids = Enum.map(rows, fn {finding, _image} -> finding.id end)

    with {:ok, events} <- History.event_page(finding_ids, req.events_after, req),
         {:ok, cases} <- History.case_page(case_query([cve], req), req.cases_after) do
      detail_lane =
        lane(cve, rows, [], req)
        |> Map.delete(:observed_dates)
        |> Map.merge(events.summary)

      {:ok,
       %{
         cve: cve,
         lane: detail_lane,
         events: Enum.map(events.rows, &detail_event(&1, req)),
         event_page: Map.drop(events, [:rows, :summary]),
         cases: cases,
         window: %{weeks: req.weeks, from: req.from, to: req.to}
       }}
    end
  end

  defp detail_event(event, req) do
    date = DateTime.to_date(event.occurred_at)

    %{
      id: event.id,
      kind: event.event,
      occurred_at: event.occurred_at,
      note: event.note,
      date: date,
      in_window?: in_window?(date, req)
    }
  end

  ## Shared helpers

  defp in_window?(nil, _req), do: false

  defp in_window?(date, req) do
    Date.compare(date, req.from) != :lt and Date.compare(date, req.to) != :gt
  end

  # `Date` and `DateTime` are structs, so plain term ordering compares their
  # fields structurally (day, then month, then year) rather than in time order.
  # The module sorters use the calendar comparison instead.
  defp resolved_at(findings) do
    if Enum.any?(findings, &is_nil(&1.resolved_at)) do
      nil
    else
      findings |> Enum.map(& &1.resolved_at) |> Enum.reject(&is_nil/1) |> max_or_nil()
    end
  end

  defp min_or_nil([]), do: nil
  defp min_or_nil(values), do: Enum.min(values, DateTime)

  defp max_or_nil([]), do: nil
  defp max_or_nil(values), do: Enum.max(values, DateTime)

  defp severity_rank(severity), do: Triage.Severity.rank(severity)

  defp image_reference(%{repository: repository, tag: tag})
       when is_binary(repository) and repository != "" and is_binary(tag) and tag != "",
       do: repository <> ":" <> tag

  defp image_reference(%{repository: repository}) when is_binary(repository) and repository != "",
    do: repository

  defp image_reference(image), do: Map.get(image, :digest)
end
