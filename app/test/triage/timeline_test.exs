defmodule Triage.TimelineTest do
  @moduledoc """
  Read-model unit tests for the read-only CVE timeline.

  Fixtures are dated relative to today so the default window always contains
  them, and every test starts from an empty inventory: an assertion about
  counts must not depend on rows another test left behind.
  """
  use Triage.DataCase, async: false

  import Triage.Fixtures

  alias Triage.{Cases, Timeline}

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  describe "request validation" do
    test "rejects every unrecognized request shape" do
      for bad <- [
            %{},
            "opts",
            nil,
            7,
            [:weeks],
            [weeks: 4, unknown: 1],
            [owner: "a", owner: "b"],
            [{"weeks", 4}]
          ] do
        assert {:error, reason} = Timeline.list_timeline(bad)
        assert reason == :invalid_request
      end
    end

    test "rejects an out-of-range or non-integer window" do
      for bad <- [0, 13, -1, "8", 8.0, true, :eight] do
        assert {:error, :invalid_window} = Timeline.list_timeline(weeks: bad)
      end

      for good <- [1, 4, 8, 12] do
        assert {:ok, _view} = Timeline.list_timeline(weeks: good)
      end
    end

    test "rejects a malformed scope value" do
      assert {:error, :invalid_scope} = Timeline.list_timeline(owner: 5)
      assert {:error, :invalid_scope} = Timeline.list_timeline(owner: "a" <> <<0>>)

      assert {:error, :invalid_scope} =
               Timeline.list_timeline(environment: String.duplicate("a", 121))
    end

    test "rejects a malformed cve" do
      for bad <- ["", "   ", 5, "a" <> <<0>>, String.duplicate("C", 121), nil] do
        assert {:error, reason} = Timeline.cve_detail(bad)
        assert reason in [:invalid_cve, :invalid_request]
      end
    end

    test "a blank scope is the intentional All choice, not an error" do
      assert {:ok, view} = Timeline.list_timeline(owner: "  ", environment: "")
      assert view.window.owner == nil
      assert view.window.environment == nil
    end

    test "filter options come from recorded placements" do
      image = image!("options")
      placement!(image, "alpha", "prod")
      placement!(image, "beta", "staging", false)

      assert %{owners: ["alpha", "beta"], environments: ["prod", "staging"]} =
               Timeline.filter_options()
    end

    test "advertised window options match the accepted range" do
      for {_label, weeks} <- Timeline.window_options() do
        assert {:ok, _view} = Timeline.list_timeline(weeks: weeks)
      end

      assert Timeline.default_weeks() == 12
    end
  end

  describe "window" do
    test "defaults to twelve Monday-aligned weeks ending today" do
      assert {:ok, view} = Timeline.list_timeline()
      span = window_span(12)

      assert view.window.weeks == 12
      assert view.window.from == span.from
      assert view.window.to == span.to
      assert Date.day_of_week(view.window.from) == 1
      assert view.window.to == today()

      # Monday to today is a round 84 days only on a Sunday, so the span is
      # derived from the contract rather than hard-coded.
      assert length(view.days) == span.days
      assert span.days == 77 + Date.day_of_week(span.to)

      # The window ends today and is never padded into days that have not
      # happened: unless today closes its week, it is shorter than twelve full
      # weeks. Rendering future days as empty bands would be a claim about time
      # that has not passed.
      assert length(view.days) == Date.diff(view.window.to, view.window.from) + 1
      assert Date.day_of_week(view.window.to) == 7 or length(view.days) < 12 * 7
      assert view.days |> hd() |> Map.fetch!(:date) == today()
      assert view.days |> List.last() |> Map.fetch!(:date) == view.window.from
      assert length(view.grid.weeks) == 12

      # The label states the real span, so "Last 12 weeks" cannot pass a shorter
      # partial week off as twelve full weeks.
      assert view.window.label =~ "Last 12 weeks"
      assert view.window.label =~ Calendar.strftime(span.from, "%d %b")
      assert view.window.label =~ Calendar.strftime(span.to, "%d %b %Y")
      assert view.summary.days == span.days
      assert view.summary.empty_days == span.days - view.summary.observed_days
    end

    test "honours the 4 and 12 week windows" do
      for weeks <- [4, 12] do
        assert {:ok, view} = Timeline.list_timeline(weeks: weeks)
        span = window_span(weeks)

        assert view.window.weeks == weeks
        assert view.window.from == span.from
        assert Date.day_of_week(view.window.from) == 1
        assert length(view.days) == span.days
        assert length(view.grid.weeks) == weeks
      end
    end

    test "an empty window reports zero observations without claiming a clean estate" do
      assert {:ok, view} = Timeline.list_timeline()
      assert view.summary.events == 0
      assert view.summary.observed_days == 0
      assert view.summary.empty_days == window_span(12).days
      assert view.lanes.total == 0
      assert view.lanes.rows == []
      assert Enum.all?(view.days, &(&1.observed? == false))
    end
  end

  describe "day bands and connectors" do
    setup do
      image = image!("bands")
      continuing = finding!(image, "CVE-2026-0001")
      event!(continuing, "appeared", at(1, ~T[07:00:00]))
      event!(continuing, "reopened", at(0, ~T[07:00:00]))
      single = finding!(image, "CVE-2026-0002")
      event!(single, "appeared", at(0, ~T[09:00:00]))
      %{}
    end

    test "bands are newest first and empty days are explicit" do
      assert {:ok, view} = Timeline.list_timeline()
      newest = Enum.find(view.days, &(&1.date == today()))
      assert newest.observed?
      assert newest.reopened_count == 1
      assert newest.event_count == 2

      yesterday = Enum.find(view.days, &(&1.date == Date.add(today(), -1)))
      assert yesterday.observed?
      assert yesterday.new_count == 1

      two_days_ago = Enum.find(view.days, &(&1.date == Date.add(today(), -2)))
      refute two_days_ago.observed?
      assert two_days_ago.rows == []
      assert view.summary.observed_days == 2
      assert view.summary.empty_days == window_span(12).days - 2
    end

    test "adjacent observations are joined by a connector in both directions" do
      assert {:ok, view} = Timeline.list_timeline()
      newest = Enum.find(view.days, &(&1.date == today()))
      yesterday = Enum.find(view.days, &(&1.date == Date.add(today(), -1)))

      continuing = Enum.find(newest.rows, &(&1.cve == "CVE-2026-0001"))
      assert continuing.continues?
      refute continuing.continued_from?

      older = Enum.find(yesterday.rows, &(&1.cve == "CVE-2026-0001"))
      assert older.continued_from?
      refute older.continues?

      single = Enum.find(newest.rows, &(&1.cve == "CVE-2026-0002"))
      refute single.continues?
      refute single.continued_from?
    end

    test "rows carry current state, not a replayed historical state" do
      assert {:ok, view} = Timeline.list_timeline()
      newest = Enum.find(view.days, &(&1.date == today()))
      row = Enum.find(newest.rows, &(&1.cve == "CVE-2026-0001"))
      assert row.state == :open
      assert row.package_name == "libssl"
      assert row.resolved_at == nil
      assert row.kind == "reopened"
    end
  end

  describe "weekday grid" do
    test "counts one distinct CVE per first recorded observation date" do
      image = image!("grid")
      first = finding!(image, "CVE-2026-1001", package_name: "p1")
      duplicate = finding!(image, "CVE-2026-1001", package_name: "p2")
      other = finding!(image, "CVE-2026-1002", package_name: "p3")
      event!(first, "appeared", at(2, ~T[05:00:00]))
      event!(duplicate, "appeared", at(2, ~T[08:00:00]))
      event!(other, "appeared", at(2, ~T[09:00:00]))

      assert {:ok, view} = Timeline.list_timeline()
      assert cell_for(view, Date.add(today(), -2)).count == 2
      assert view.summary.new_cves == 2
      assert view.summary.cves == 2
      assert view.grid.max_count == 2
    end

    test "is a full rectangle with Monday first and future days marked" do
      assert {:ok, view} = Timeline.list_timeline()
      assert Enum.map(view.grid.rows, & &1.weekday) == ~w(Mon Tue Wed Thu Fri Sat Sun)
      assert Enum.map(view.grid.rows, & &1.iso_weekday) == [1, 2, 3, 4, 5, 6, 7]

      assert Enum.all?(view.grid.rows, fn row ->
               length(row.cells) == view.window.weeks
             end)

      cells = Enum.flat_map(view.grid.rows, & &1.cells)
      # Every day after today is a future cell, so there is no future cell only
      # when today is itself the last day of the week (Sunday).
      assert Enum.any?(cells, & &1.in_future?) == (Date.day_of_week(today()) != 7)

      assert Enum.all?(cells, fn cell ->
               cell.in_future? == (Date.compare(cell.date, today()) == :gt)
             end)

      assert Enum.all?(cells, fn cell -> cell.in_window? == not cell.in_future? end)
    end

    test "a day after today is never counted" do
      assert {:ok, view} = Timeline.list_timeline()

      for cell <- Enum.flat_map(view.grid.rows, & &1.cells), cell.in_future? do
        assert cell.count == 0
      end
    end
  end

  describe "lanes" do
    setup do
      image_a = image!("lane-a")
      image_b = image!("lane-b")
      placement!(image_a, "alpha", "prod")
      placement!(image_b, "beta", "prod")
      low = finding!(image_a, "CVE-2026-2001", severity: "LOW")

      high =
        finding!(image_b, "CVE-2026-2001",
          severity: "CRITICAL",
          suppressed: true,
          resolved_at: at(1)
        )

      event!(low, "appeared", at(5))
      event!(high, "appeared", at(5, ~T[08:00:00]))
      event!(high, "resolved", at(1))
      %{}
    end

    test "aggregates occurrences of one CVE and keeps the most severe severity" do
      assert {:ok, view} = Timeline.list_timeline()
      assert [lane] = view.lanes.rows
      assert lane.cve == "CVE-2026-2001"
      assert lane.severity == "CRITICAL"
      assert lane.occurrence_count == 2
      assert lane.open_count == 1
      assert lane.resolved_count == 1
      assert lane.suppressed_count == 1
      assert lane.state == :open
      assert lane.resolved_events == 1
      assert lane.appeared_count == 2
      assert lane.observed_dates == [Date.add(today(), -5), Date.add(today(), -1)]
      assert view.lanes.total == 1
      assert view.lanes.truncated_count == 0
      assert view.summary.cves == 1
    end

    test "a scoped view only shows findings with a matching recorded placement" do
      assert {:ok, view} = Timeline.list_timeline(owner: "alpha")
      assert [lane] = view.lanes.rows
      assert lane.occurrence_count == 1
      assert lane.severity == "LOW"
      assert lane.suppressed_count == 0
      assert view.summary.cves == 1
      assert view.summary.events == 1

      assert {:ok, scoped} = Timeline.list_timeline(owner: "alpha", environment: "prod")
      assert scoped.summary.events == 1

      assert {:ok, empty} = Timeline.list_timeline(owner: "alpha", environment: "staging")
      assert empty.summary.events == 0
      assert empty.lanes.total == 0
    end
  end

  test "lanes are ordered by severity then CVE id" do
    image = image!("lane-order")
    low = finding!(image, "CVE-2026-2100", severity: "LOW", package_name: "a")
    medium = finding!(image, "CVE-2026-2200", severity: "MEDIUM", package_name: "b")
    critical = finding!(image, "CVE-2026-2201", severity: "CRITICAL", package_name: "c")
    event!(low, "appeared", at(1, ~T[04:00:00]))
    event!(medium, "appeared", at(1, ~T[05:00:00]))
    event!(critical, "appeared", at(1, ~T[06:00:00]))

    assert {:ok, view} = Timeline.list_timeline()

    assert Enum.map(view.lanes.rows, & &1.cve) == [
             "CVE-2026-2201",
             "CVE-2026-2200",
             "CVE-2026-2100"
           ]

    assert Enum.map(view.lanes.rows, & &1.severity) == ["CRITICAL", "MEDIUM", "LOW"]
  end

  test "an unknown severity ranks below every known one but is still shown" do
    image = image!("lane-unknown")
    unknown = finding!(image, "CVE-2026-2300", severity: "MODERATE", package_name: "a")
    low = finding!(image, "CVE-2026-2301", severity: "LOW", package_name: "b")
    event!(unknown, "appeared", at(1, ~T[04:00:00]))
    event!(low, "appeared", at(1, ~T[05:00:00]))

    assert {:ok, view} = Timeline.list_timeline()
    assert Enum.map(view.lanes.rows, & &1.cve) == ["CVE-2026-2301", "CVE-2026-2300"]
    assert Enum.map(view.lanes.rows, & &1.severity) == ["LOW", "MODERATE"]
  end

  test "a CVE with no recorded severity is still listed" do
    image = image!("lane-null-severity")
    finding = finding!(image, "CVE-2026-2400", severity: nil)
    event!(finding, "appeared", at(1))

    assert {:ok, view} = Timeline.list_timeline()
    assert [%{cve: "CVE-2026-2400", severity: nil}] = view.lanes.rows
  end

  describe "recorded assessments" do
    test "a saved review is counted as a judgment and loaded with its case" do
      image = image!("judged")
      placement!(image, "alpha", "prod")
      finding = finding!(image, "CVE-2026-3001")
      event!(finding, "appeared", at(2))

      assert {:ok, %{case: cse, snapshot: snap}} =
               Cases.open_case(finding.id, owner: "alpha", environment: "prod")

      assert {:ok, %{review: _review}} =
               Cases.submit_review(
                 cse.id,
                 cse.revision,
                 snap.id,
                 Ecto.UUID.generate(),
                 review_attrs()
               )

      assert {:ok, view} = Timeline.list_timeline()
      assert view.summary.judged == 1
      assert [lane] = view.lanes.rows
      assert lane.judged_count == 1
      assert [%{id: case_id, review_count: 1, owner: "alpha", environment: "prod"}] = lane.cases
      assert case_id == cse.id

      today_band = Enum.find(view.days, &(&1.date == today()))
      assert today_band.judged_count == 1

      yesterday_band = Enum.find(view.days, &(&1.date == Date.add(today(), -1)))
      assert yesterday_band.judged_count == 0
    end

    test "an assessment recorded in the window counts even without an in-window observation" do
      image = image!("judged-old")
      placement!(image, "alpha", "prod")
      finding = finding!(image, "CVE-2026-3002")
      event!(finding, "appeared", at(200))

      assert {:ok, %{case: cse, snapshot: snap}} =
               Cases.open_case(finding.id, owner: "alpha", environment: "prod")

      assert {:ok, _} =
               Cases.submit_review(
                 cse.id,
                 cse.revision,
                 snap.id,
                 Ecto.UUID.generate(),
                 review_attrs()
               )

      assert {:ok, view} = Timeline.list_timeline(weeks: 4)
      assert view.summary.events == 0
      assert view.lanes.total == 0
      assert view.summary.judged == 1

      # The assessment was recorded today, so it is a recorded event inside the
      # window even though the CVE has no in-window observation: the day band
      # carries the judgment without claiming an observation happened.
      today_band = Enum.find(view.days, &(&1.date == today()))
      assert today_band.judged_count == 1
      refute today_band.observed?
    end

    test "a scoped view only shows cases opened against that scope" do
      image = image!("judged-scope")
      placement!(image, "beta", "prod")
      finding = finding!(image, "CVE-2026-3003")
      event!(finding, "appeared", at(2))

      assert {:ok, %{case: cse, snapshot: snap}} =
               Cases.open_case(finding.id, owner: "beta", environment: "prod")

      assert {:ok, _} =
               Cases.submit_review(
                 cse.id,
                 cse.revision,
                 snap.id,
                 Ecto.UUID.generate(),
                 review_attrs()
               )

      assert {:ok, view} = Timeline.list_timeline(owner: "beta")
      assert [lane] = view.lanes.rows
      assert lane.judged_count == 1

      # Recorded observation survives the scope change, but the other team's
      # case does not appear in a scope that is not its own.
      assert {:ok, other} = Timeline.list_timeline(owner: "alpha")
      assert other.lanes.total == 0
    end
  end

  describe "one cve detail" do
    test "returns full-history counts and the first event page, marking events outside the window" do
      image = image!("detail")
      placement!(image, "alpha", "prod")
      finding = finding!(image, "CVE-2026-4001")
      event!(finding, "appeared", at(200))
      event!(finding, "resolved", at(1))

      assert {:ok, detail} = Timeline.cve_detail("CVE-2026-4001", weeks: 4)
      assert detail.cve == "CVE-2026-4001"
      assert detail.lane.cve == "CVE-2026-4001"
      assert Enum.map(detail.events, & &1.kind) == ["appeared", "resolved"]

      appeared = Enum.find(detail.events, &(&1.kind == "appeared"))
      refute appeared.in_window?
      assert appeared.note == nil

      resolved = Enum.find(detail.events, &(&1.kind == "resolved"))
      assert resolved.in_window?
      assert detail.lane.window_observed_count == 1
      assert detail.lane.observed_day_count == 2
      assert detail.event_page.total == 2
      refute detail.event_page.has_more?
    end

    test "includes saved cases with their timeline data" do
      image = image!("detail-case")
      placement!(image, "alpha", "prod")
      finding = finding!(image, "CVE-2026-4003")
      event!(finding, "appeared", at(2))

      assert {:ok, %{case: cse, snapshot: snap}} =
               Cases.open_case(finding.id, owner: "alpha", environment: "prod")

      assert {:ok, _} =
               Cases.submit_review(
                 cse.id,
                 cse.revision,
                 snap.id,
                 Ecto.UUID.generate(),
                 review_attrs()
               )

      assert {:ok, detail} = Timeline.cve_detail("CVE-2026-4003")
      assert detail.cases.total == 1
      assert detail.cases.truncated_count == 0
      assert [%{id: case_id, data: data}] = detail.cases.rows
      assert case_id == cse.id
      assert data.case.owner == "alpha"
      assert data.reviews != []
      assert data.events != []
    end

    test "an unknown cve is not found and a malformed one is rejected" do
      assert {:error, :not_found} = Timeline.cve_detail("CVE-0000-0000")
      assert {:error, :invalid_cve} = Timeline.cve_detail("")
    end

    test "a scoped detail hides a CVE with no matching placement" do
      image = image!("detail-scope")
      placement!(image, "beta", "prod")
      finding = finding!(image, "CVE-2026-4002")
      event!(finding, "appeared", at(1))

      assert {:error, :not_found} = Timeline.cve_detail("CVE-2026-4002", owner: "alpha")
      assert {:ok, _detail} = Timeline.cve_detail("CVE-2026-4002", owner: "beta")
    end

    test "rejects an unknown option before any query" do
      assert {:error, :invalid_request} = Timeline.cve_detail("CVE-2026-4001", cursor: 1)
    end
  end

  describe "quality regressions" do
    test "assessments follow the case owner/environment even when placements share an image" do
      image = image!("shared-assessments")

      for {owner, environment} <- [{"alpha", "prod"}, {"alpha", "staging"}, {"beta", "prod"}] do
        placement!(image, owner, environment)
      end

      finding = finding!(image, "CVE-2026-7001")
      event!(finding, "appeared", at(2))
      reviewed_case!(finding, "beta", "prod")
      reviewed_case!(finding, "alpha", "staging")

      for {opts, expected} <- [
            {[], 2},
            {[owner: "alpha"], 1},
            {[environment: "prod"], 1},
            {[owner: "alpha", environment: "prod"], 0},
            {[owner: "alpha", environment: "staging"], 1},
            {[owner: "beta", environment: "staging"], 0}
          ] do
        assert {:ok, view} = Timeline.list_timeline(opts)
        assert view.summary.judged == expected
        assert Enum.find(view.days, &(&1.date == today())).judged_count == expected
      end
    end

    test "daily counts include events beyond the display cap" do
      image = image!("daily-cap")
      finding = finding!(image, "CVE-2026-7002")
      for second <- 1..26, do: event!(finding, "appeared", DateTime.add(at(1), second))
      assert {:ok, view} = Timeline.list_timeline()
      day = Enum.find(view.days, &(&1.date == Date.add(today(), -1)))
      assert {day.event_count, day.new_count, day.truncated_count} == {26, 26, 1}
      assert length(day.rows) == 25
    end

    test "chronological event pages retain full totals and handle backdated ids" do
      image = image!("event-pages")
      placement!(image, "alpha", "prod")
      finding = finding!(image, "CVE-2026-7003")

      events =
        for second <- 50..0//-1, do: event!(finding, "appeared", DateTime.add(at(2), second))

      assert {:ok, first} = Timeline.cve_detail(finding.cve, owner: "alpha", environment: "prod")
      assert length(first.events) == 50
      assert first.event_page.has_more?
      assert first.event_page.total == 51
      assert first.lane.event_count == 51
      assert first.lane.observed_day_count == 1
      assert first.lane.appeared_count == 51

      assert {:ok, second} =
               Timeline.cve_detail(finding.cve,
                 owner: "alpha",
                 environment: "prod",
                 events_after: first.event_page.next_after
               )

      assert Enum.map(first.events ++ second.events, & &1.id) ==
               Enum.map(Enum.reverse(events), & &1.id)

      assert second.lane == first.lane
      refute second.event_page.has_more?

      foreign =
        finding!(image, "CVE-2026-7999", package_name: "other") |> event!("appeared", at(2))

      assert Timeline.cve_detail(finding.cve, events_after: foreign.id) ==
               {:error, :invalid_cursor}
    end

    test "event cursor tie-breaking does not skip events recorded at the same instant" do
      image = image!("event-ties")
      finding = finding!(image, "CVE-2026-7004")
      sibling = finding!(image, finding.cve, package_name: "sibling")
      for second <- 0..48, do: event!(finding, "appeared", DateTime.add(at(2), second))
      first_tie = event!(finding, "appeared", DateTime.add(at(2), 49))
      second_tie = event!(sibling, "appeared", DateTime.add(at(2), 49))
      assert {:ok, first} = Timeline.cve_detail(finding.cve)
      assert first.event_page.next_after == first_tie.id

      assert {:ok, second} =
               Timeline.cve_detail(finding.cve, events_after: first.event_page.next_after)

      assert Enum.map(second.events, & &1.id) == [second_tie.id]
      assert second.lane.event_count == 51
    end

    test "case pages and lane previews are bounded without truncating their totals" do
      image = image!("case-pages")
      placement!(image, "alpha", "prod")

      cases =
        for index <- 1..11 do
          finding = finding!(image, "CVE-2026-7005", package_name: "package-#{index}")
          event!(finding, "appeared", at(1))

          assert {:ok, %{case: cse}} =
                   Cases.open_case(finding.id, owner: "alpha", environment: "prod")

          cse
        end

      assert {:ok, view} = Timeline.list_timeline(owner: "alpha")
      assert [lane] = view.lanes.rows
      assert lane.case_count == 11
      assert length(lane.cases) == 10
      assert lane.cases_truncated_count == 1
      assert {:ok, first} = Timeline.cve_detail("CVE-2026-7005", owner: "alpha")
      assert first.cases.total == 11
      assert first.cases.shown == 10
      assert first.cases.has_more?

      assert {:ok, second} =
               Timeline.cve_detail("CVE-2026-7005",
                 owner: "alpha",
                 cases_after: first.cases.next_after
               )

      assert Enum.map(first.cases.rows ++ second.cases.rows, & &1.id) == Enum.map(cases, & &1.id)
      refute second.cases.has_more?
      placement!(image, "beta", "prod")

      assert Timeline.cve_detail("CVE-2026-7005", owner: "beta", cases_after: hd(cases).id) ==
               {:error, :invalid_cursor}
    end
  end

  defp reviewed_case!(finding, owner, environment) do
    assert {:ok, %{case: cse, snapshot: snapshot}} =
             Cases.open_case(finding.id, owner: owner, environment: environment)

    assert {:ok, _} =
             Cases.submit_review(
               cse.id,
               cse.revision,
               snapshot.id,
               Ecto.UUID.generate(),
               review_attrs()
             )

    cse
  end

  defp cell_for(view, date) do
    view.grid.rows
    |> Enum.flat_map(& &1.cells)
    |> Enum.find(&(&1.date == date))
  end
end
