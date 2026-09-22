defmodule TriageWeb.DailyAndAiLiveTest do
  @moduledoc "CVE timeline navigation and recorded detections."
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :reviewer
  import Phoenix.LiveViewTest
  import Triage.Fixtures
  alias Triage.Repo

  setup do
    Triage.DataCase.reset_inventory!()
    image = image!("daily-live")
    prod = placement!(image, "alpha", "prod")
    finding = finding!(image, "CVE-2099-8001", description: "RCE in parser")
    other = finding!(image, "CVE-2099-8002", description: "Second advisory")
    %{prod: prod, cve: finding.cve, finding: finding, other_cve: other.cve}
  end

  describe "CVE timeline" do
    test "renders days with CVEs and descriptions", c do
      Repo.insert!(%Triage.Inventory.FindingEvent{
        finding_id: c.finding.id,
        event: "appeared",
        occurred_at: ~U[2026-09-10 08:00:00Z]
      })

      {:ok, view, _} = live(c.conn, "/?page=daily")
      assert has_element?(view, "#daily-feed")
      assert has_element?(view, "#day-2026-09-10")
      assert has_element?(view, "#daily-CVE-2099-8001")
      assert render(view) =~ "RCE in parser"
      assert render(view) =~ "CVE-2099-8001"
    end

    test "empty state is honest when no inventory or decisions exist", c do
      Triage.DataCase.reset_inventory!()
      {:ok, view, _} = live(c.conn, "/?page=daily")
      assert has_element?(view, "#daily-feed")
      assert has_element?(view, ".daily-empty", "No CVE activity recorded yet")
    end

    test "timeline is reachable from the primary nav", c do
      {:ok, view, _} = live(c.conn, "/")
      assert has_element?(view, "#workspace-nav-daily", "Timeline")
      view |> element("#workspace-nav-daily") |> render_click()
      assert_patch(view, "/?page=daily")
      assert has_element?(view, "#daily-feed")
    end

    test "shows whitelist timing, actor, scope and expiry and opens the CVE for review", c do
      at = ~U[2026-09-10 08:00:00Z]
      event!(c.finding, "appeared", at)

      decision =
        Repo.insert!(%Triage.Decisions.Decision{
          cve: c.cve,
          placement_id: c.prod.id,
          decision: "accepted_risk",
          actor: "alice",
          reason: "Upgrade scheduled",
          decided_at: ~U[2026-09-12 10:30:00Z],
          expires_at: ~U[2026-10-01 00:00:00Z],
          metadata: %{"target" => %{"team" => "alpha", "environment" => "prod"}}
        })

      {:ok, view, _} = live(c.conn, "/?page=daily")
      row = "#daily-#{c.cve}"
      assert has_element?(view, "#{row} .timeline-duration", "2 d 2 h 30 min")
      assert has_element?(view, "#{row} time[datetime='2026-09-10T08:00:00Z']")
      assert has_element?(view, "#timeline-event-decision-#{decision.id}", "Whitelisted")
      assert has_element?(view, "#timeline-event-decision-#{decision.id}", "alpha · prod")
      assert has_element?(view, "#timeline-event-decision-#{decision.id}", "alice")

      assert has_element?(
               view,
               "#timeline-event-decision-#{decision.id} .timeline-event-expiry",
               "01 Oct 2026"
             )

      view |> element("#{row} .cve-id") |> render_click()
      assert_patch(view, "/?item=#{c.cve}&page=review")
      assert has_element?(view, "#workspace-review")
    end

    test "pages whole CVE histories and returns to the latest activity", c do
      image = image!("timeline-pages")

      for index <- 1..21 do
        finding!(image, "CVE-2099-#{9000 + index}")
      end

      {:ok, view, _} = live(c.conn, "/?page=daily")
      assert has_element?(view, "#timeline-earlier")
      view |> element("#timeline-earlier") |> render_click()
      assert has_element?(view, "#timeline-latest")
      refute has_element?(view, "#timeline-earlier")
      view |> element("#timeline-latest") |> render_click()
      assert has_element?(view, "#timeline-earlier")
      refute has_element?(view, "#timeline-latest")
    end

    test "sample histories render once in detection-to-action order", c do
      :ok = Triage.Seeds.TimelineSamples.seed!()
      {:ok, view, _} = live(c.conn, "/?page=daily")
      html = render(view) |> LazyHTML.from_document()
      assert Enum.count(LazyHTML.query(html, "#daily-CVE-2099-9028")) == 1

      labels =
        html
        |> LazyHTML.query("#daily-CVE-2099-9028 .timeline-event-heading strong")
        |> Enum.map(&LazyHTML.text/1)

      assert labels == ["Detected", "Whitelisted"]
      assert has_element?(view, "#daily-CVE-2099-9028 .timeline-duration", "2 h 0 min")

      assert has_element?(
               view,
               "#daily-CVE-2099-9028 .timeline-event-scopes summary",
               "2 deployment scopes"
             )

      fixed_labels =
        html
        |> LazyHTML.query("#daily-CVE-2099-9030 .timeline-event-heading strong")
        |> Enum.map(&LazyHTML.text/1)

      assert fixed_labels == [
               "Detected",
               "Fix marked by reviewer",
               "No longer detected (scanner observation)"
             ]

      refute render(view) =~ "Reported fixed"
    end
  end
end
