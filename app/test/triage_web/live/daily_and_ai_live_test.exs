defmodule TriageWeb.DailyAndAiLiveTest do
  @moduledoc """
  CVE timeline page and the AI triage suggestion panel.

  The AI panel is a suggestion only: no automatic whitelisting is possible,
  and the reviewer always confirms explicitly (D11/I06).

  W01a: analysis is explicitly disabled by default, async delivery is bound
  to the exact request, row CVE, target fingerprints and reviewer permission,
  and stale or forged deliveries are discarded without touching reviewer
  drafts (A12). The fake runner fixture is the only runner these tests use.
  """
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :reviewer
  import Phoenix.LiveViewTest
  import Triage.Fixtures
  alias Triage.{Repo, Workspace}
  alias Triage.Workspace.Commit

  @fake_runner Path.expand("../../fixtures/experiment/fake_kiro_cli.sh", __DIR__)

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

  describe "AI triage panel" do
    defp configure_ai!(overrides) do
      previous = Application.get_env(:triage, Triage.AiTriage)
      Application.put_env(:triage, Triage.AiTriage, Keyword.put(overrides, :test_env, true))

      on_exit(fn ->
        if previous,
          do: Application.put_env(:triage, Triage.AiTriage, previous),
          else: Application.delete_env(:triage, Triage.AiTriage)
      end)

      :ok
    end

    defp runner_mode(mode) do
      System.put_env("TRIAGE_FAKE_RUNNER_MODE", mode)

      on_exit(fn ->
        System.delete_env("TRIAGE_FAKE_RUNNER_MODE")
        System.delete_env("TRIAGE_FAKE_RUNNER_LOG")
      end)
    end

    test "shows the disabled state honestly when analysis is not enabled", c do
      configure_ai!(enabled: false, cli_path: @fake_runner)

      {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
      assert has_element?(view, "#ai-triage")
      assert has_element?(view, "#classification-setup", "Connect Kiro")
      assert render(view) =~ "TRIAGE_ANALYSIS_ENABLED"
      assert has_element?(view, "#classify-now[disabled]", "Classify now")
    end

    test "a fake-runner assessment renders only through the bound request", c do
      configure_ai!(enabled: true, cli_path: @fake_runner)

      {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
      view |> element("#ai-triage .ai-analyze-btn") |> render_click()
      assert %{success: 1, failure: 0} = Oban.drain_queue(queue: :classifier)
      render(view)

      assert has_element?(view, "#ai-triage .ai-result")
      assert has_element?(view, "#classification-risk strong", "42")
      assert has_element?(view, "#classification-whitelist strong", "18")
      assert render(view) =~ "Investigate this CVE"
      assert render(view) =~ "Fake runner fixture: deterministic pipeline response."
      assert render(view) =~ "does not approve, whitelist, or commit anything"
    end

    test "duplicate triggers are bounded to one runner invocation", c do
      configure_ai!(enabled: true, cli_path: @fake_runner)

      log =
        Path.join(
          System.tmp_dir!(),
          "triage_fake_runner_#{System.unique_integer([:positive])}.log"
        )

      on_exit(fn -> File.rm(log) end)
      File.rm(log)
      System.put_env("TRIAGE_FAKE_RUNNER_LOG", log)

      {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
      view |> element("#ai-triage .ai-analyze-btn") |> render_click()
      # A second trigger while one request is in flight starts no new runner,
      # even if the hidden button were bypassed.
      view |> render_click("ai-analyze", %{})
      assert %{success: 1, failure: 0} = Oban.drain_queue(queue: :classifier)
      render(view)

      assert File.read!(log) |> String.split("\n", trim: true) |> length() == 1
      assert has_element?(view, "#ai-triage .ai-result")
    end

    test "a stale result after navigating to another CVE is never displayed", c do
      configure_ai!(enabled: true, cli_path: @fake_runner)

      {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
      view |> element("#ai-triage .ai-analyze-btn") |> render_click()

      # Navigate to the second advisory before the result is delivered.
      view |> element("#queue-#{c.other_cve}") |> render_click()
      assert render(view) =~ c.other_cve

      assert %{success: 1, failure: 0} = Oban.drain_queue(queue: :classifier)
      render(view)

      refute has_element?(view, "#ai-triage .ai-result")
      refute render(view) =~ "Fake runner fixture"
    end

    test "an evidence change during analysis discards the result and preserves the draft", c do
      configure_ai!(enabled: true, cli_path: @fake_runner)

      {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")

      # A reviewer draft is in progress; a discarded AI result must never
      # clobber it (A12).
      render_hook(view, "draft", %{
        "decision" => %{"action" => "accepted_risk", "reason" => "My manual justification"}
      })

      # The draft is durably stored before analysis starts.
      assert {:ok, %{fields: %{"reason" => "My manual justification"}}} =
               Triage.Workspace.Drafts.get(c.principal, c.cve)

      view |> element("#ai-triage .ai-analyze-btn") |> render_click()

      # A concurrent decision changes the evidence revision fingerprints.
      # Its expiry sits outside the attention review window so the covered
      # item stays in the progress queue (the review-due band-1 case has
      # its own parity regression).
      versions = Workspace.targets(%{"cve" => c.cve}) |> Map.new(&{&1.id, &1.fingerprint})

      assert {:ok, [_]} =
               Commit.save(
                 c.cve,
                 [c.prod.id],
                 versions,
                 Ecto.UUID.generate(),
                 %{
                   "action" => "investigate",
                   "owner" => "Other reviewer",
                   "actor" => "Other reviewer",
                   "reason" => "Concurrent work recorded elsewhere",
                   "due_on" => Date.utc_today() |> Date.add(30) |> Date.to_iso8601()
                 }
               )

      assert %{success: 1, failure: 0} = Oban.drain_queue(queue: :classifier)
      render(view)

      assert has_element?(view, "#ai-triage .ai-error")
      assert render(view) =~ "Evidence changed during analysis"
      refute has_element?(view, "#ai-triage .ai-result")

      # The manual draft survives the discard in the durable store (A12).
      assert {:ok, %{fields: %{"reason" => "My manual justification"}}} =
               Triage.Workspace.Drafts.get(c.principal, c.cve)

      # It also restores into a fresh mount of the item: the concurrent
      # decision moved the covered advisory into the progress queue, so the
      # preserved justification is still reachable there.
      {:ok, reloaded, _} = live(c.conn, "/?page=review&mode=progress&item=#{c.cve}")

      assert has_element?(
               reloaded,
               "textarea[name='decision[reason]']",
               "My manual justification"
             )
    end

    test "a runner failure renders the bounded error, never a fallback score", c do
      configure_ai!(enabled: true, cli_path: @fake_runner)
      runner_mode("invalid_json")

      {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
      view |> element("#ai-triage .ai-analyze-btn") |> render_click()
      assert %{success: 1, failure: 0} = Oban.drain_queue(queue: :classifier)
      render(view)

      assert has_element?(view, "#ai-triage .ai-error")
      assert render(view) =~ "unexpected response format"
      refute has_element?(view, "#ai-triage .ai-result")
    end

    test "saved scores survive reconnect and are invalidated without overwriting a dirty draft",
         c do
      configure_ai!(enabled: true, cli_path: @fake_runner)
      {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
      view |> element("#classify-now") |> render_click()
      assert %{success: 1} = Oban.drain_queue(queue: :classifier)
      assert has_element?(view, "#classification-risk strong", "42")
      {:ok, reconnected, _} = live(c.conn, "/?page=review&item=#{c.cve}")
      assert has_element?(reconnected, "#classification-risk strong", "42")

      render_hook(reconnected, "draft", %{
        "decision" => %{"action" => "accepted_risk", "reason" => "Preserve this manual draft"}
      })

      Repo.update!(
        Ecto.Changeset.change(c.finding, description: "New evidence after classification")
      )

      send(reconnected.pid, {:workspace_changed, c.cve})
      assert has_element?(reconnected, ".ai-error", "Evidence changed")
      refute has_element?(reconnected, "#classification-result")

      assert {:ok, %{fields: %{"reason" => "Preserve this manual draft"}}} =
               Triage.Workspace.Drafts.get(c.principal, c.cve)
    end

    test "forged pre-binding deliveries are discarded without touching the view", c do
      configure_ai!(enabled: true, cli_path: @fake_runner)

      {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")

      # Old message shape from earlier deployments: no request binding.
      send(
        view.pid,
        {:ai_assessment, c.cve,
         {:ok,
          %{
            cve: c.cve,
            danger_score: 99,
            danger_level: "critical",
            recommendation: "remediate",
            rationale: "forged content must never render"
          }}}
      )

      html = render(view)
      refute has_element?(view, "#ai-triage .ai-result")
      refute html =~ "forged content"
    end
  end
end
