defmodule Triage.DailyTimelineTest do
  use Triage.DataCase, async: false
  import Triage.Fixtures
  alias Triage.DailyTimeline
  alias Triage.Decisions.Decision

  @now ~U[2026-09-22 12:00:00Z]

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  test "groups CVE appearances by day with descriptions" do
    image = image!("daily-1")
    a = finding!(image, "CVE-2099-3001", description: "RCE in test server")
    b = finding!(image, "CVE-2099-3002", description: "XSS in widget")
    event!(a, "appeared", ~U[2026-09-10 08:00:00Z])
    event!(b, "appeared", ~U[2026-09-10 15:00:00Z])

    {:ok, %{days: days}} = DailyTimeline.list()
    assert [%{date: date, count: 2, cves: cves}] = days
    assert Date.compare(date, ~D[2026-09-10]) == :eq
    assert Enum.map(cves, & &1.cve) == ["CVE-2099-3002", "CVE-2099-3001"]
    assert Enum.find(cves, &(&1.cve == "CVE-2099-3001")).description == "RCE in test server"
    assert Enum.find(cves, &(&1.cve == "CVE-2099-3002")).description == "XSS in widget"
  end

  test "multiple days sort newest first and page via before_date" do
    image = image!("daily-2")
    a = finding!(image, "CVE-2099-4001")
    b = finding!(image, "CVE-2099-4002")
    event!(a, "appeared", ~U[2026-09-01 08:00:00Z])
    event!(b, "appeared", ~U[2026-09-02 08:00:00Z])

    {:ok, %{days: days}} = DailyTimeline.list()
    assert [first, second] = days
    assert Date.compare(first.date, ~D[2026-09-02]) == :eq
    assert Date.compare(second.date, ~D[2026-09-01]) == :eq

    {:ok, %{days: before}} = DailyTimeline.list(before_date: first.date)
    assert [%{date: d}] = before
    assert Date.compare(d, ~D[2026-09-01]) == :eq
  end

  test "same CVE on multiple packages appears once with its full history" do
    image = image!("daily-3")
    a = finding!(image, "CVE-2099-5001", package_name: "openssl", package_version: "3.2")
    b = finding!(image, "CVE-2099-5001", package_name: "curl", package_version: "8.1")
    event!(a, "appeared", ~U[2026-09-10 08:00:00Z])
    event!(b, "appeared", ~U[2026-09-11 09:00:00Z])

    {:ok, %{days: [%{count: 1, cves: [cve_entry]}]}} = DailyTimeline.list()
    assert cve_entry.cve == "CVE-2099-5001"
    assert cve_entry.packages == "curl 8.1, openssl 3.2"
    assert length(cve_entry.events) == 2
  end

  test "missing description is shown honestly" do
    image = image!("daily-4")
    a = finding!(image, "CVE-2099-6001")
    event!(a, "appeared", ~U[2026-09-10 08:00:00Z])

    {:ok, %{days: [%{cves: [entry]}]}} = DailyTimeline.list()
    assert entry.description == "No description recorded"
  end

  test "invalid before_date is rejected before querying" do
    assert {:error, :invalid_date} = DailyTimeline.list(before_date: "not-a-date")
    assert {:error, :invalid_date} = DailyTimeline.list(before_date: 123)
  end

  test "scanner changes remain observations and do not invent a human response" do
    image = image!("daily-5")
    a = finding!(image, "CVE-2099-7001")
    event!(a, "appeared", ~U[2026-09-10 08:00:00Z])
    event!(a, "resolved", ~U[2026-09-11 08:00:00Z])
    event!(a, "reopened", ~U[2026-09-12 08:00:00Z])

    {:ok, %{days: days}} = DailyTimeline.list()
    assert [%{date: ~D[2026-09-12], cves: [entry]}] = days
    assert Enum.map(entry.events, & &1.kind) == ["detected", "resolved", "reopened"]
    assert is_nil(entry.first_action)
  end

  test "connects detection, whitelist and later actions with exact response times and scopes" do
    image = image!("lifecycle")
    prod = placement!(image, "alpha", "prod")
    placement!(image, "beta", "staging")
    finding = finding!(image, "CVE-2099-7101", first_seen: ~U[2026-09-10 08:00:00Z])

    whitelist =
      decision!(finding, "accepted_risk", ~U[2026-09-12 10:30:00Z],
        placement_id: prod.id,
        expires_at: ~U[2026-09-20 00:00:00Z],
        metadata: %{"target" => %{"team" => "alpha", "environment" => "prod"}}
      )

    ticket = decision!(finding, "create_ticket", ~U[2026-09-15 11:00:00Z], placement_id: prod.id)
    fixed = decision!(finding, "fixed", ~U[2026-09-18 12:00:00Z], placement_id: prod.id)

    {:ok, data} = DailyTimeline.list(now: @now)
    events = events(data)
    assert length(entries(data)) == 1
    assert Enum.map(events, & &1.source) == ["detection", "decision", "decision", "decision"]
    assert Enum.map(events, & &1.kind) == ["detected", "accepted_risk", "create_ticket", "fixed"]
    assert Enum.map(events, & &1.id) == [finding.id, whitelist.id, ticket.id, fixed.id]

    assert Enum.find(events, &(&1.id == whitelist.id and &1.source == "decision")).scope ==
             "alpha · prod · deployment ##{prod.id}"

    for day <- data.days, entry <- day.cves do
      assert entry.first_detected_at == ~U[2026-09-10 08:00:00Z]
      assert entry.first_action.kind == "accepted_risk"
      assert entry.first_action.at == whitelist.decided_at
      assert entry.response_seconds == 181_800
      assert entry.waiting_seconds == nil
    end
  end

  test "future and pre-detection decisions do not count as the first response" do
    finding = finding!(image!("timing"), "CVE-2099-7102", first_seen: ~U[2026-09-20 12:00:00Z])
    earlier = decision!(finding, "not_affected", ~U[2026-09-19 12:00:00Z])
    future = decision!(finding, "fixed", ~U[2026-09-23 12:00:00Z])

    {:ok, data} = DailyTimeline.list(now: @now)
    assert Enum.any?(events(data), &(&1.source == "decision" and &1.id == earlier.id))
    refute Enum.any?(events(data), &(&1.source == "decision" and &1.id == future.id))
    assert Enum.all?(entries(data), &is_nil(&1.first_action))
    assert Enum.all?(entries(data), &(&1.waiting_seconds == 172_800))
    assert Enum.find(events(data), &(&1.source == "decision")).elapsed_seconds == nil
  end

  test "inventory first_seen works without an event and scanner suppression does not mean whitelisted" do
    finding!(image!("without-event"), "CVE-2099-7103",
      first_seen: ~U[2026-09-22 10:00:00Z],
      suppressed: true
    )

    {:ok, data} = DailyTimeline.list(now: @now)

    assert [%{first_action: nil, waiting_seconds: 7200, events: [%{kind: "detected"}]}] =
             entries(data)
  end

  test "pages unique CVEs without splitting histories or losing same-time activity" do
    image = image!("busy-day")

    for index <- 1..45 do
      finding = finding!(image, "CVE-2099-#{8000 + index}", first_seen: ~U[2026-09-01 08:00:00Z])
      decision!(finding, "accepted_risk", ~U[2026-09-20 08:00:00Z])
    end

    {:ok, first} = DailyTimeline.list(now: @now)
    {:ok, second} = DailyTimeline.list(now: @now, before: first.next_before)
    {:ok, third} = DailyTimeline.list(now: @now, before: second.next_before)

    assert first.has_more? and second.has_more?
    refute third.has_more?
    all = Enum.flat_map([first, second, third], &entries/1)
    assert Enum.map([first, second, third], &length(entries(&1))) == [20, 20, 5]
    assert length(Enum.uniq_by(all, & &1.cve)) == 45

    assert Enum.all?(
             all,
             &(Enum.map(&1.events, fn event -> event.kind end) == ["detected", "accepted_risk"])
           )

    assert Enum.all?(entries(second), &(&1.response_seconds == 19 * 86_400))
  end

  test "one operation across deployments is one step, while later reviews remain distinct" do
    image = image!("shared-operation")
    a = placement!(image, "alpha", "prod")
    b = placement!(image, "beta", "staging")
    finding = finding!(image, "CVE-2099-7104", first_seen: ~U[2026-09-20 08:00:00Z])

    original =
      for placement <- [a, b] do
        decision!(finding, "accepted_risk", ~U[2026-09-20 10:00:00Z],
          placement_id: placement.id,
          operation_id: "shared-whitelist",
          metadata: %{
            "target" => %{"team" => placement.owner, "environment" => placement.environment}
          }
        )
      end

    for placement <- [a, b] do
      decision!(finding, "accepted_risk", ~U[2026-09-21 10:00:00Z],
        placement_id: placement.id,
        operation_id: "renewed-whitelist",
        metadata: %{
          "target" => %{"team" => placement.owner, "environment" => placement.environment}
        }
      )
    end

    {:ok, data} = DailyTimeline.list(now: @now)
    assert [entry] = entries(data)
    assert [detected, whitelist, renewed] = entry.events
    assert detected.kind == "detected"
    assert whitelist.record_ids == Enum.map(original, & &1.id)
    assert length(whitelist.scopes) == 2
    refute whitelist.repeated?
    assert renewed.repeated?
    assert entry.response_seconds == 7200
    assert Repo.aggregate(Decision, :count) == 4
  end

  test "a long history stays complete and independent reviews are not deduplicated" do
    finding =
      finding!(image!("long-history"), "CVE-2099-7200", first_seen: ~U[2026-09-20 08:00:00Z])

    for _ <- 1..125, do: decision!(finding, "fixed", ~U[2026-09-21 08:00:00Z])
    {:ok, data} = DailyTimeline.list(now: @now)
    assert [entry] = entries(data)
    assert length(entry.events) == 126
    refute data.has_more?
  end

  test "fictional samples show detection before whitelist or fix and seeding is repeatable" do
    :ok = Triage.Seeds.TimelineSamples.seed!()
    :ok = Triage.Seeds.TimelineSamples.seed!()
    assert Repo.aggregate(Decision, :count) == 6
    assert Repo.aggregate(Triage.Inventory.Finding, :count) == 3
    assert Repo.aggregate(Triage.Inventory.FindingEvent, :count) == 4

    {:ok, data} = DailyTimeline.list(now: @now)
    samples = Map.new(entries(data), &{&1.cve, &1})

    for {cve, seconds} <- [{"CVE-2099-9028", 7200}, {"CVE-2099-9029", 18_000}] do
      assert Enum.map(samples[cve].events, & &1.kind) == ["detected", "accepted_risk"]
      assert samples[cve].response_seconds == seconds
      assert length(List.last(samples[cve].events).scopes) == 2
    end

    fixed = samples["CVE-2099-9030"]
    assert Enum.map(fixed.events, & &1.kind) == ["detected", "fixed", "resolved"]
    assert fixed.response_seconds == 25 * 3600 + 1800
    assert List.last(fixed.events).elapsed_seconds == 26 * 3600
  end

  test "critical filtering includes actions and rejects invalid cursors" do
    critical =
      finding!(image!("critical"), "CVE-2099-7105",
        severity: "CRITICAL",
        first_seen: ~U[2026-09-20 08:00:00Z]
      )

    other = finding!(image!("high"), "CVE-2099-7106", first_seen: ~U[2026-09-20 08:00:00Z])
    decision!(critical, "investigate", ~U[2026-09-21 08:00:00Z])
    decision!(other, "fixed", ~U[2026-09-21 08:00:00Z])
    {:ok, data} = DailyTimeline.list(scope: "critical", now: @now)
    assert data.total_cves == 1
    assert Enum.all?(entries(data), &(&1.cve == critical.cve))
    assert {:error, :invalid_cursor} = DailyTimeline.list(before: "bad-cursor")
    assert {:error, :invalid_request} = DailyTimeline.list(scope: "invalid")
  end

  defp decision!(finding, kind, at, opts \\ []) do
    attrs =
      Keyword.merge(
        [
          cve: finding.cve,
          decision: kind,
          decided_at: at,
          actor: "reviewer",
          reason: "Recorded review decision"
        ],
        opts
      )

    Repo.insert!(struct!(Decision, attrs))
  end

  defp entries(data), do: Enum.flat_map(data.days, & &1.cves)
  defp events(data), do: data |> entries() |> Enum.flat_map(& &1.events)
end
