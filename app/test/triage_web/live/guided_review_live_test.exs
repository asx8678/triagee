defmodule TriageWeb.GuidedReviewLiveTest do
  use TriageWeb.LegacyUICase, async: false
  import Phoenix.LiveViewTest
  import Triage.Fixtures
  alias Triage.{GuidedReview, Repo}

  setup do
    Triage.DataCase.reset_inventory!()
    Repo.delete_all(GuidedReview.Request)
    image = image!("guided")
    placement = placement!(image, "alpha", "prod")

    finding =
      finding!(image, "CVE-2024-3094",
        severity: "HIGH",
        description: "Malicious code in xz releases."
      )

    %{finding: finding, image: image, placement: placement}
  end

  test "unavailable progress database preserves step and requests retry" do
    row = GuidedReview.get("CVE-2024-3094")

    {:ok, repo} =
      start_supervised(
        {Repo,
         name: :unavailable_progress_repo,
         hostname: "127.0.0.1",
         port: 1,
         pool: DBConnection.ConnectionPool,
         pool_size: 1,
         queue_target: 1,
         queue_interval: 1,
         timeout: 50,
         connect_timeout: 50}
      )

    previous = Repo.put_dynamic_repo(repo)

    try do
      socket = %Phoenix.LiveView.Socket{
        assigns: %{__changed__: %{}, row: row, step: 2, error: nil}
      }

      assert {:noreply, updated} =
               TriageWeb.GuidedReviewLive.handle_event("next", %{}, socket)

      assert updated.assigns.step == 2
      assert updated.assigns.error == "Review progress could not be saved. Please retry."
    after
      Repo.put_dynamic_repo(previous)
    end
  end

  test "AI completion rejects changed evidence", %{finding: finding} do
    row = GuidedReview.get("CVE-2024-3094")
    fingerprint = GuidedReview.review_fingerprint(row)
    request = {:advice, row.cve, fingerprint, make_ref()}

    socket = %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        cve: row.cve,
        review_fingerprint: fingerprint,
        advice_request: request,
        ai_busy: true,
        advice: nil
      }
    }

    finding |> Ecto.Changeset.change(description: "Changed during AI request") |> Repo.update!()

    assert {:noreply, updated} =
             TriageWeb.GuidedReviewLive.handle_async(
               request,
               {:ok, {:ok, "stale advice"}},
               socket
             )

    assert {:error, message} = updated.assigns.advice
    assert message =~ "Evidence changed"
    refute updated.assigns.ai_busy
    assert updated.assigns.advice_request == nil
  end

  test "AI completion from an older request cannot replace current advice" do
    row = GuidedReview.get("CVE-2024-3094")
    fingerprint = GuidedReview.review_fingerprint(row)
    old_request = {:advice, row.cve, fingerprint, make_ref()}
    current_request = {:advice, row.cve, fingerprint, make_ref()}

    socket = %Phoenix.LiveView.Socket{
      assigns: %{
        __changed__: %{},
        cve: row.cve,
        review_fingerprint: fingerprint,
        advice_request: current_request,
        ai_busy: true,
        advice: nil
      }
    }

    assert {:noreply, ^socket} =
             TriageWeb.GuidedReviewLive.handle_async(old_request, {:ok, {:ok, "old"}}, socket)
  end

  test "review navigation survives remount without restoring action authorization", %{conn: conn} do
    {:ok, view, _} = live(conn, "/triage/CVE-2024-3094")
    for _ <- 1..3, do: view |> element("#review-next") |> render_click()
    assert Triage.ReviewProgress.step(GuidedReview.get("CVE-2024-3094")) == 4
    GenServer.stop(view.pid)
    {:ok, resumed, _} = live(conn, "/triage/CVE-2024-3094")
    assert has_element?(resumed, "#review-progress", "Step 4 of 4")
    assert has_element?(resumed, "#confirm-team-tickets[disabled]")
    assert GuidedReview.requests("CVE-2024-3094") == []
    render_click(resumed, "back")
    assert Triage.ReviewProgress.step(GuidedReview.get("CVE-2024-3094")) == 3
  end

  test "changed evidence resets persisted navigation", %{conn: conn, finding: finding} do
    {:ok, view, _} = live(conn, "/triage/CVE-2024-3094")
    view |> element("#review-next") |> render_click()
    finding |> Ecto.Changeset.change(description: "New evidence") |> Repo.update!()
    GenServer.stop(view.pid)
    {:ok, resumed, _} = live(conn, "/triage/CVE-2024-3094")
    assert has_element?(resumed, "#review-progress", "Step 1 of 4")
  end

  test "bulk planning requires preview and confirmation and never accepts risk", %{conn: conn} do
    {:ok, view, _} = live(conn, "/triage")
    render_hook(view, "bulk_confirm", %{})
    assert Repo.aggregate(GuidedReview.Request, :count) == 0
    view |> element("#select-CVE-2024-3094") |> render_click()
    view |> element("#bulk-preview") |> render_click()
    assert has_element?(view, "#bulk-scope-preview", "alpha")
    assert Repo.aggregate(GuidedReview.Request, :count) == 0
    view |> element("#bulk-confirm") |> render_click()
    assert has_element?(view, "#bulk-message", "No tickets sent or risk accepted")
    assert [%{status: "planned"}] = GuidedReview.requests("CVE-2024-3094")
    assert Repo.aggregate(Triage.Decisions.Decision, :count) == 0
    refute has_element?(view, "#bulk-confirm")
  end

  test "bulk planning rejects changed evidence atomically", %{
    conn: conn,
    image: image,
    finding: finding
  } do
    finding!(image, "CVE-2024-9999")
    {:ok, view, _} = live(conn, "/triage")

    for cve <- ["CVE-2024-3094", "CVE-2024-9999"] do
      view |> element("#select-#{cve}") |> render_click()
    end

    view |> element("#bulk-preview") |> render_click()
    finding |> Ecto.Changeset.change(description: "Changed evidence") |> Repo.update!()
    view |> element("#bulk-confirm") |> render_click()
    assert has_element?(view, "#bulk-message", "Nothing was planned")
    assert Repo.aggregate(GuidedReview.Request, :count) == 0
  end

  test "bulk selection cannot target off-page CVEs and changing filters clears preview", %{
    conn: conn
  } do
    {:ok, view, _} = live(conn, "/triage")
    render_hook(view, "bulk_toggle", %{"cve" => "CVE-FORGED"})
    refute has_element?(view, "#bulk-preview")
    view |> element("#select-CVE-2024-3094") |> render_click()
    view |> element("#bulk-preview") |> render_click()
    render_hook(view, "filter_queue", %{"team" => "alpha"})
    refute has_element?(view, "#bulk-confirm")
    render_hook(view, "bulk_confirm", %{})
    assert Repo.aggregate(GuidedReview.Request, :count) == 0
    assert {:error, :invalid_selection} = GuidedReview.bulk_mark_for_fix(%{})

    assert {:error, :invalid_selection} =
             GuidedReview.bulk_mark_for_fix(Map.new(1..26, &{&1, "x"}))
  end

  test "saved filters use a browser-local hook and reload through validated queue filters", %{
    conn: conn
  } do
    {:ok, view, _} = live(conn, "/triage")
    assert has_element?(view, "#saved-queue-filters[phx-hook='SavedQueueFilters']")
    assert has_element?(view, "#saved-filter-name[maxlength='80']")
    refute has_element?(view, "#queue-filter-options[open]")
    refute has_element?(view, "#review-help[open]")
    assert has_element?(view, "#review-help #guided-scope-note")

    render_hook(view, "filter_queue", %{
      "team" => "alpha",
      "after_cve" => "untrusted",
      "admin" => "true"
    })

    assert_patch(view, "/triage?team=alpha")
    assert has_element?(view, "#queue-filter-options[open]")
    assert has_element?(view, "#action-CVE-2024-3094")
  end

  test "keyboard navigation never confirms a mutation", %{conn: conn} do
    {:ok, view, _} = live(conn, "/triage/CVE-2024-3094")
    render_keydown(view, "review_shortcut", %{"key" => "ArrowRight", "altKey" => false})
    assert has_element?(view, "#review-progress", "Step 1 of 4")

    for _ <- 1..5 do
      render_keydown(view, "review_shortcut", %{"key" => "ArrowRight", "altKey" => true})
    end

    assert has_element?(view, "#review-progress", "Step 4 of 4")
    assert Repo.aggregate(GuidedReview.Request, :count) == 0
    assert Repo.aggregate(Triage.Decisions.Decision, :count) == 0
    render_keydown(view, "review_shortcut", %{"key" => "ArrowLeft", "altKey" => true})
    assert has_element?(view, "#review-progress", "Step 3 of 4")
  end

  test "action-only queue uses full-width compact rows and guided CTA for noncritical CVEs", %{
    conn: conn
  } do
    {:ok, view, _} = live(conn, "/triage")
    assert has_element?(view, "h1", "Action required")
    assert has_element?(view, "#action-CVE-2024-3094", "Malicious code")
    refute has_element?(view, "#action-queue table")
    refute has_element?(view, "#action-queue .review-card")
    assert has_element?(view, ".review-queue-compact > #action-CVE-2024-3094.review-queue-row")
    assert has_element?(view, "#action-CVE-2024-3094 .review-row-teams", "alpha")
    assert has_element?(view, "#action-CVE-2024-3094 .review-row-libraries", "libssl")
    assert has_element?(view, "#triage-issue-CVE-2024-3094[href='/triage/CVE-2024-3094']")
  end

  test "review polish labels the queue and guides each next step", %{conn: conn} do
    {:ok, queue, _} = live(conn, "/triage")
    assert has_element?(queue, "h2", "1 CVE needs action")
    assert has_element?(queue, ".review-queue-heading", "Libraries")
    assert has_element?(queue, ".review-row-priority.review-priority-high", "HIGH")
    assert has_element?(queue, ".review-row-teams[data-label='Teams']", "alpha")

    {:ok, view, _} = live(conn, "/triage/CVE-2024-3094")
    assert has_element?(view, "#review-progress", "Step 1 of 4")
    assert has_element?(view, "#review-next", "Next: teams & exposure")
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#review-progress", "Step 2 of 4")
    assert has_element?(view, ".review-steps .is-previous", "Understand CVE")
    assert has_element?(view, ".review-steps [aria-current='step']", "Teams & exposure")
    assert has_element?(view, "#review-next", "Next: risk & AI advice")
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#review-next", "Next: take action")
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#review-progress", "Step 4 of 4")
    refute has_element?(view, "#review-next")
    assert Repo.aggregate(GuidedReview.Request, :count) == 0
  end

  test "timeline CVE links open guided review only while action is required", %{
    conn: conn,
    finding: finding
  } do
    event!(finding, "appeared", at(3))
    {:ok, timeline, _} = live(conn, "/timeline?cve=CVE-2024-3094")

    for selector <- ["#tl-chart", "#tl-lanes-table", "#tl-bands", "#tl-drawer-title"] do
      assert has_element?(
               timeline,
               "#{selector} a[href='/triage/CVE-2024-3094']",
               "CVE-2024-3094"
             )
    end

    assert {:error, {:live_redirect, %{to: "/triage/CVE-2024-3094"}}} =
             timeline
             |> element("#tl-lane-CVE-2024-3094 a[href='/triage/CVE-2024-3094']")
             |> render_click()

    {:ok, review, _} = live(conn, "/triage/CVE-2024-3094")
    assert has_element?(review, "#review-step-1", "Malicious code")

    expiry = Date.utc_today() |> Date.add(5) |> Date.to_iso8601()
    fingerprint = finding.cve |> GuidedReview.get() |> GuidedReview.review_fingerprint()

    assert {:ok, _} =
             GuidedReview.whitelist(finding.cve, "Temporary accepted risk", expiry, fingerprint)

    {:ok, covered, _} = live(conn, "/timeline?cve=CVE-2024-3094")

    for selector <- ["#tl-chart", "#tl-lanes-table", "#tl-bands", "#tl-drawer-title"] do
      refute has_element?(covered, "#{selector} a[href='/triage/CVE-2024-3094']")
      assert has_element?(covered, "#{selector} a[href='/cves/CVE-2024-3094']", "CVE-2024-3094")
    end
  end

  test "four steps, unknown exposure, unavailable integrations and local fix plan", %{conn: conn} do
    {:ok, view, _} = live(conn, "/triage/CVE-2024-3094")
    assert has_element?(view, "#review-step-1", "Malicious code")
    render_click(view, "plan_fix")
    assert Repo.aggregate(GuidedReview.Request, :count) == 0
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#review-step-2", "alpha")
    assert has_element?(view, "#review-step-2", "Exposure unknown")
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#ai-unconfigured")
    assert has_element?(view, "#review-step-3", "not a CVSS score")
    view |> element("#review-next") |> render_click()
    assert has_element?(view, "#azure-unconfigured")
    assert has_element?(view, "#confirm-team-tickets[disabled]")
    view |> element("#mark-for-fix") |> render_click()
    assert has_element?(view, "#team-ticket-results", "planned")
    assert Repo.aggregate(GuidedReview.Request, :count) == 1
  end

  test "whitelist requires reason and expiry and leaves actionable queue", %{conn: conn} do
    {:ok, view, _} = live(conn, "/triage/CVE-2024-3094")
    for _ <- 1..3, do: render_click(view, "next")

    view
    |> form("#guided-whitelist-form", decision: %{reason: "", expires_on: ""})
    |> render_submit()

    assert has_element?(view, "#guided-error")
    expiry = Date.utc_today() |> Date.add(5) |> Date.to_iso8601()

    view
    |> form("#guided-whitelist-form",
      decision: %{reason: "Temporary accepted risk", expires_on: expiry}
    )
    |> render_submit()

    assert_redirect(view, "/triage")
    assert GuidedReview.queue() == []
  end

  test "KEV queue priority matches the CVE detail", %{conn: conn, finding: finding} do
    Repo.insert!(%Triage.Intel.Advisory{
      source: "kev",
      external_id: finding.cve,
      fetched_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })

    {:ok, queue, _} = live(conn, "/triage")
    assert has_element?(queue, "#action-#{finding.cve} .review-priority-critical", "CRITICAL")
    {:ok, detail, _} = live(conn, "/cves/#{finding.cve}")
    assert has_element?(detail, "#cve-priority", "critical")
    assert has_element?(detail, "#cve-priority-reasons", "Actively exploited (KEV)")
  end

  for change <- [:description, :team, :exposure, :kev] do
    test "changed #{change} must be reviewed again even after refreshing the ticket preview",
         context do
      {:ok, view, _} = live(context.conn, "/triage/#{context.finding.cve}")

      case unquote(change) do
        :description ->
          context.finding
          |> Ecto.Changeset.change(description: "New evidence to review")
          |> Repo.update!()

        :team ->
          placement!(context.image, "beta", "prod")

        :exposure ->
          Triage.Exposure.record(
            context.placement.id,
            "internet_exposed",
            "test",
            DateTime.utc_now()
          )

        :kev ->
          Repo.insert!(%Triage.Intel.Advisory{
            source: "kev",
            external_id: context.finding.cve,
            fetched_at: DateTime.utc_now() |> DateTime.truncate(:second)
          })
      end

      for _ <- 1..3, do: render_click(view, "next")
      view |> element("#refresh-ticket-preview") |> render_click()

      decision = %{
        reason: "Temporary accepted risk",
        expires_on: Date.utc_today() |> Date.add(5) |> Date.to_iso8601()
      }

      view |> form("#guided-whitelist-form", decision: decision) |> render_submit()
      assert has_element?(view, "#guided-error", "no risk was accepted")
      assert has_element?(view, "#review-step-1")
      refute has_element?(view, "#guided-whitelist-form")
      assert Repo.aggregate(Triage.Decisions.Decision, :count) == 0

      # The refreshed evidence is now visible, but acceptance still needs a new walkthrough.
      for _ <- 1..3, do: render_click(view, "next")
      view |> form("#guided-whitelist-form", decision: decision) |> render_submit()
      assert_redirect(view, "/triage")
      assert GuidedReview.get(context.finding.cve) == nil
    end
  end

  test "queue pages and direct details reach CVEs beyond the first 25 candidates", %{conn: conn} do
    findings = paged_findings!()
    last = List.last(findings)
    {:ok, view, _} = live(conn, "/triage")
    refute has_element?(view, "#action-#{last.cve}")
    assert has_element?(view, "#action-queue-next")
    view |> element("#action-queue-next") |> render_click()
    assert has_element?(view, "#action-#{last.cve}")
    assert has_element?(view, "#action-queue-first")
    refute has_element?(view, "#action-queue-next")
    view |> element("#action-queue-first") |> render_click()
    assert has_element?(view, "#action-#{hd(findings).cve}")

    {:ok, detail, _} = live(conn, "/triage/#{last.cve}")
    assert has_element?(detail, "#review-step-1", "Page regression")
    refute has_element?(detail, "#guided-not-actionable")
  end

  test "an empty filtered candidate page still offers the next page", %{conn: conn} do
    findings = paged_findings!()

    for finding <- Enum.take(findings, 25) do
      assert {:ok, _} =
               Triage.Decisions.record(%{
                 cve: finding.cve,
                 decision: "not_affected",
                 reason: "Covered for this test",
                 actor: "test",
                 decided_at: DateTime.add(DateTime.utc_now(), -60)
               })
    end

    {:ok, view, _} = live(conn, "/triage")
    assert has_element?(view, "#action-queue-empty", "More candidates remain")
    assert has_element?(view, "#action-queue-next")
    view |> element("#action-queue-next") |> render_click()
    assert has_element?(view, "#action-#{List.last(findings).cve}")
  end

  test "invalid cursor clears rows and can recover via First page", %{conn: conn} do
    {:ok, view, _} = live(conn, "/triage?after_cve[]=bad")
    assert has_element?(view, "#action-queue-error")
    refute has_element?(view, "#action-CVE-2024-3094")
    refute has_element?(view, "#action-queue-next")
    view |> element("#action-queue-first") |> render_click()
    assert has_element?(view, "#action-CVE-2024-3094")
    refute has_element?(view, "#action-queue-error")
  end

  test "timeline links a displayed actionable CVE beyond the first queue page", %{conn: conn} do
    last = List.last(paged_findings!())
    event!(last, "appeared", at(1))
    {:ok, view, _} = live(conn, "/timeline?cve=#{last.cve}")

    for selector <- ["#tl-chart", "#tl-lanes-table", "#tl-bands", "#tl-drawer-title"] do
      assert has_element?(view, "#{selector} a[href='/triage/#{last.cve}']")
    end
  end

  test "day bands and the selected drawer link actionable CVEs beyond the lane cap", %{conn: conn} do
    image = image!("outside-lane-cap")
    placement!(image, "alpha", "prod")

    for n <- 1..50 do
      finding = finding!(image, "CVE-2090-#{1000 + n}", severity: "CRITICAL")
      event!(finding, "appeared", at(2))
    end

    outside = finding!(image, "CVE-2090-9999", severity: "LOW")
    event!(outside, "appeared", at(1))
    {:ok, view, _} = live(conn, "/timeline?cve=#{outside.cve}")
    refute has_element?(view, "#tl-lane-#{outside.cve}")

    for selector <- ["#tl-bands", "#tl-drawer-title"] do
      assert has_element?(view, "#{selector} a[href='/triage/#{outside.cve}']")
    end
  end

  test "a selected actionable CVE without window events still links to guided review", %{
    conn: conn
  } do
    {:ok, view, _} = live(conn, "/timeline?cve=CVE-2024-3094")
    assert has_element?(view, "#tl-drawer-title a[href='/triage/CVE-2024-3094']")
  end

  test "search filters reset paging and survive next-page and detail navigation", %{conn: conn} do
    findings = paged_findings!()
    {:ok, view, _} = live(conn, "/triage")

    view
    |> form("#queue-filters", %{
      q: "CVE-2020",
      team: "alpha",
      severity: "HIGH",
      kev: "no",
      exposure: "unknown"
    })
    |> render_submit()

    refute has_element?(view, "#action-CVE-2024-3094")
    assert has_element?(view, "#queue-search[value='CVE-2020']")
    view |> element("#action-queue-next") |> render_click()
    last = List.last(findings)
    assert has_element?(view, "#action-#{last.cve}")
    assert has_element?(view, "#triage-issue-#{last.cve}[href*='q=CVE-2020']")

    view
    |> form("#queue-filters", %{q: "no-match", team: "", severity: "", kev: "", exposure: ""})
    |> render_submit()

    assert has_element?(view, "#action-queue-empty")
    refute has_element?(view, "#action-queue-first")
  end

  test "malformed filters fail visibly and critical priority leads the queue", %{conn: conn} do
    [first | _] = paged_findings!()
    Triage.Repo.update!(Ecto.Changeset.change(first, severity: "LOW"))
    image = image!("critical-order")
    placement!(image, "urgent", "prod")
    finding!(image, "CVE-2099-9999", severity: "CRITICAL")
    {:ok, view, _} = live(conn, "/triage")
    assert has_element?(view, ".review-queue > article:first-child#action-CVE-2099-9999")
    {:ok, invalid, _} = live(conn, "/triage?team[]=bad")
    assert has_element?(invalid, "#action-queue-error")
    refute has_element?(invalid, "#action-CVE-2099-9999")
  end

  defp paged_findings! do
    image = image!("guided-pages")
    placement!(image, "alpha", "prod")

    for number <- 1..26 do
      suffix = String.pad_leading(Integer.to_string(number), 4, "0")

      finding!(image, "CVE-2020-#{suffix}",
        description: "Page regression",
        severity: "HIGH"
      )
    end
  end
end
