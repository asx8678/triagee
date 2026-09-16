defmodule TriageWeb.CaseLiveIndexTest do
  @moduledoc """
  Targeted PR 3 LiveView tests for the read-only review queue: rendering and
  stable DOM ids, saved-scope row links and status badges, honest empty and
  invalid states, keyset pagination with cursor reset, manual reload,
  hostile text escaping and unsupported events.
  """

  use TriageWeb.ConnCase, async: true

  import Ecto.Query
  alias Triage.{Cases, Inventory, Repo, Seeds}
  alias Triage.Cases.ReviewCase
  alias Triage.Inventory.Finding

  @env "prod"
  @now ~U[2026-09-09 06:00:00Z]

  setup do
    :ok = Seeds.seed()
    :ok
  end

  defp finding_id(package) do
    Repo.one!(
      from f in Finding,
        where: f.cve == "CVE-2025-1001" and f.package_name == ^package,
        select: f.id
    )
  end

  defp open_case!(package, owner) do
    {:ok, %{case: cse}} = Cases.open_case(finding_id(package), owner: owner, environment: @env)
    cse
  end

  defp review!(cse) do
    {:ok, data} = Cases.get_case(cse.id)

    assert {:ok, _} =
             Cases.submit_review(
               cse.id,
               1,
               data.case.current_snapshot_id,
               Ecto.UUID.generate(),
               %{
                 "applicability" => "affected",
                 "priority" => "expedited_review",
                 "next_action" => "investigation",
                 "rationale" => "Affected locally; scheduling a rebuild"
               }
             )
  end

  # Queue-owned fixtures: `count` distinct synthetic findings under one image
  # placed in the given scope, one case opened per finding. Independent of the
  # shared seeds.
  defp seed_cases!(count, owner) do
    n = :erlang.unique_integer([:positive])

    {:ok, image} =
      Inventory.upsert_image(
        %{
          digest: "sha256:queue-" <> Integer.to_string(n),
          repository: "registry.internal/queue-fixtures-#{n}",
          tag: "1.0",
          description: "Synthetic review queue fixture image"
        },
        @now
      )

    {:ok, _} =
      Inventory.upsert_placement(
        image,
        %{namespace: "web", owner: owner, environment: @env},
        @now
      )

    for i <- 1..count do
      {:ok, finding} =
        Inventory.upsert_finding(
          image,
          %{
            cve: "CVE-2026-#{n}-#{i}",
            package_name: "queue-pkg-#{i}",
            package_version: "1.0.#{i}",
            severity: "LOW",
            fix: nil,
            description: "Synthetic review queue fixture finding",
            suppressed: false
          },
          @now,
          reopen: false
        )

      {:ok, %{case: cse}} = Cases.open_case(finding.id, owner: owner, environment: @env)
      cse
    end
  end

  defp case_ids_desc(owner) do
    Repo.all(from c in ReviewCase, where: c.owner == ^owner, order_by: [desc: c.id])
    |> Enum.map(& &1.id)
  end

  test "queue renders heading, filter form, stream container and reload", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/cases")

    assert has_element?(view, "h1", "Review Queue")
    assert has_element?(view, "#queue-banner", "local-operator")
    assert has_element?(view, "#queue-filters", "All teams")
    assert has_element?(view, "#case-queue")
    assert has_element?(view, "#queue-empty")
    assert has_element?(view, "#reload-queue")
    refute has_element?(view, "#queue-error")
    refute has_element?(view, "#older-cases")
    refute has_element?(view, "#newest-cases")
  end

  test "rows render badges, review metadata and saved-scope detail links", %{conn: conn} do
    alpha = open_case!("busybox", "alpha")
    beta = open_case!("curl", "beta")
    review!(alpha)

    {:ok, view, _html} = live(conn, "/cases")

    assert has_element?(view, "#case-#{alpha.id}")
    assert has_element?(view, "#case-#{beta.id}")
    assert has_element?(view, "#case-#{alpha.id}", "busybox")
    assert has_element?(view, "#case-#{alpha.id}", "Expedited review")
    assert has_element?(view, "#review-status-#{alpha.id}", "Assessment recorded")
    assert has_element?(view, "#evidence-status-#{alpha.id}", "Local evidence match")
    assert has_element?(view, "#review-status-#{beta.id}", "No assessment recorded")

    alpha_href =
      ~p"/cases/#{alpha.id}?#{%{owner: "alpha", environment: @env, queue: %{from: "queue"}}}"

    beta_href =
      ~p"/cases/#{beta.id}?#{%{owner: "beta", environment: @env, queue: %{from: "queue"}}}"

    assert has_element?(view, "#case-link-#{alpha.id}[href='#{alpha_href}']")
    assert has_element?(view, "#case-link-#{beta.id}[href='#{beta_href}']")
  end

  test "URL scope filters rows; row links keep each row's saved scope", %{conn: conn} do
    alpha = open_case!("busybox", "alpha")
    beta = open_case!("curl", "beta")

    {:ok, view, _html} = live(conn, "/cases?owner=alpha")

    assert has_element?(view, "#case-#{alpha.id}")
    refute has_element?(view, "#case-#{beta.id}")

    alpha_href =
      ~p"/cases/#{alpha.id}?#{%{owner: "alpha", environment: @env, queue: %{from: "queue", owner: "alpha"}}}"

    assert has_element?(view, "#case-link-#{alpha.id}[href='#{alpha_href}']")

    {:ok, view, _html} = live(conn, "/cases?environment=#{@env}")

    assert has_element?(view, "#case-#{alpha.id}")
    assert has_element?(view, "#case-#{beta.id}")
  end

  test "an unknown but valid scope renders the honest empty state", %{conn: conn} do
    _alpha = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, "/cases?owner=ghost-team")

    assert has_element?(view, "#queue-empty")
    refute has_element?(view, "#queue-error")
    refute has_element?(view, "[id^='case-link-']")
    refute has_element?(view, "#older-cases")
  end

  test "the empty state is visibly rendered only when the queue has no rows", %{conn: conn} do
    cse = open_case!("busybox", "alpha")

    # Rows exist: the empty state is absent from the DOM entirely.
    {:ok, view, _html} = live(conn, "/cases")

    assert has_element?(view, "#case-#{cse.id}")
    refute has_element?(view, "#queue-empty")

    # Zero rows for an unknown valid scope: the empty state is rendered
    # visibly, not via a hidden-class trick, with its honest message.
    {:ok, view, _html} = live(conn, "/cases?owner=ghost-team")

    assert has_element?(view, "#queue-empty", "No saved review cases for this scope")
    assert has_element?(view, "#queue-empty", "not proof of a clean estate")
    refute has_element?(view, "#queue-error")
    refute has_element?(view, "[id^='case-link-']")

    html = view |> element("#queue-empty") |> render()
    refute html =~ "hidden"
  end

  # Regression guard for the D1 browser defect: a static conditional child of
  # a phx-update="stream" container is unmanaged client DOM, so in a real
  # browser it can survive patches even after the server unassigns the empty
  # state. The empty message must therefore live OUTSIDE #case-queue. ExUnit
  # re-renders full templates, so the structural descendant assertion — not
  # rendered text — is what catches the misplaced block here; computed browser
  # style verification remains Astra's independent responsibility.
  test "the empty state is a sibling of the stream container across filter transitions", %{
    conn: conn
  } do
    cse = open_case!("busybox", "alpha")

    # Valid empty scope, one mount for the whole sequence.
    {:ok, view, _html} = live(conn, "/cases?owner=ghost-team")

    assert has_element?(view, "#queue-empty")
    refute has_element?(view, "#case-queue #queue-empty")

    stream_html = view |> element("#case-queue") |> render()
    refute stream_html =~ "queue-empty"

    # Malformed filter event: visible error, the empty state is gone.
    view
    |> element("#queue-filters")
    |> render_change(%{"owner" => String.duplicate("x", 121), "environment" => ""})

    assert has_element?(view, "#queue-error")
    refute has_element?(view, "#queue-empty")

    # Valid filter back to rows, no remount: no empty state.
    view |> element("#queue-filters") |> render_change(%{"owner" => "", "environment" => ""})

    assert has_element?(view, "#case-#{cse.id}")
    refute has_element?(view, "#queue-empty")
    refute has_element?(view, "#queue-error")

    # Valid empty scope again: the empty message returns, visibly rendered.
    view
    |> element("#queue-filters")
    |> render_change(%{"owner" => "ghost-team", "environment" => ""})

    assert has_element?(view, "#queue-empty", "No saved review cases for this scope")
    refute has_element?(view, "#queue-error")
  end

  test "invalid scope or cursor renders the visible error with no rows; valid recovers", %{
    conn: conn
  } do
    cse = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, "/cases?owner=" <> String.duplicate("a", 121))

    assert has_element?(view, "#queue-error")
    refute has_element?(view, "#case-#{cse.id}")
    refute has_element?(view, "[id^='case-link-']")
    refute has_element?(view, "#queue-pagination")
    refute has_element?(view, "#older-cases")
    refute has_element?(view, "#newest-cases")

    # An invalid cursor is equally rejected with no stale rows.
    render_patch(view, "/cases?before=abc")

    assert has_element?(view, "#queue-error")
    refute has_element?(view, "[id^='case-link-']")

    render_patch(view, "/cases?before=0")

    assert has_element?(view, "#queue-error")
    refute has_element?(view, "[id^='case-link-']")

    # Browser-back-like recovery to a valid URL restores the queue.
    render_patch(view, "/cases")

    refute has_element?(view, "#queue-error")
    assert has_element?(view, "#case-#{cse.id}")
  end

  test "older/newest pagination walks the keyset cursor; a re-patch restores the page", %{
    conn: conn
  } do
    _cases = seed_cases!(30, "alpha")
    ids_desc = case_ids_desc("alpha")
    assert length(ids_desc) == 30

    page1 = Enum.take(ids_desc, 25)
    page2 = Enum.drop(ids_desc, 25)

    {:ok, view, _html} = live(conn, "/cases?owner=alpha")

    assert has_element?(view, "#queue-pagination", "Newest opened first")
    assert has_element?(view, "#older-cases")
    refute has_element?(view, "#newest-cases")

    for id <- page1, do: assert(has_element?(view, "#case-#{id}"))
    for id <- page2, do: refute(has_element?(view, "#case-#{id}"))

    # The older control patches with before = the last displayed case id.
    expected_before = Enum.at(page1, 24)
    html = view |> element("#older-cases") |> render()
    assert html =~ "before=#{expected_before}"

    view |> element("#older-cases") |> render_click()

    for id <- page2, do: assert(has_element?(view, "#case-#{id}"))
    for id <- page1, do: refute(has_element?(view, "#case-#{id}"))

    # Last page is exhausted: no older control, but newest is offered.
    refute has_element?(view, "#older-cases")
    assert has_element?(view, "#newest-cases")

    # Newest resets to the first page without a cursor.
    view |> element("#newest-cases") |> render_click()

    for id <- page1, do: assert(has_element?(view, "#case-#{id}"))
    refute has_element?(view, "#newest-cases")
    assert has_element?(view, "#older-cases")

    # Browser-back-like re-patch to the cursor URL restores the second page.
    render_patch(view, "/cases?owner=alpha&before=#{expected_before}")

    for id <- page2, do: assert(has_element?(view, "#case-#{id}"))
    assert has_element?(view, "#newest-cases")
  end

  test "a filter event patches the canonical URL and discards the cursor", %{conn: conn} do
    _cases = seed_cases!(30, "alpha")
    beta = open_case!("curl", "beta")

    {:ok, view, _html} = live(conn, "/cases")

    view |> element("#older-cases") |> render_click()
    assert has_element?(view, "#newest-cases")

    view |> element("#queue-filters") |> render_change(%{"owner" => "beta", "environment" => ""})

    # The new scope starts at the newest page: no cursor, no newest control.
    refute has_element?(view, "#newest-cases")
    assert has_element?(view, "#case-#{beta.id}")
    refute has_element?(view, "[id^='case-link-']", "queue-pkg")
  end

  test "a malformed filter event fails visibly and a valid one recovers", %{conn: conn} do
    cse = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, "/cases")

    # Oversized scope values are decodable by the channel (raw invalid UTF-8
    # bytes cannot traverse the LiveView transport at all) yet still malformed
    # for the queue contract, so they must fail visibly without a write.
    view
    |> element("#queue-filters")
    |> render_change(%{"owner" => String.duplicate("x", 121), "environment" => ""})

    assert has_element?(view, "#queue-error")
    refute has_element?(view, "#case-#{cse.id}")

    view |> element("#queue-filters") |> render_change(%{"owner" => "", "environment" => ""})

    refute has_element?(view, "#queue-error")
    assert has_element?(view, "#case-#{cse.id}")
  end

  test "manual reload re-queries the current scope without a patch", %{conn: conn} do
    first = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, "/cases")

    assert has_element?(view, "#case-#{first.id}")

    later = open_case!("curl", "beta")
    refute has_element?(view, "#case-#{later.id}")

    view |> element("#reload-queue") |> render_click()

    assert has_element?(view, "#case-#{later.id}")
    assert has_element?(view, "#case-#{first.id}")
    refute has_element?(view, "#queue-error")
  end

  test "hostile finding text renders escaped in queue rows", %{conn: conn} do
    hostile = "<script>alert(1)</script> onerror=alert(2) \"quoted\" 'single'"
    n = :erlang.unique_integer([:positive])

    {:ok, image} =
      Inventory.upsert_image(
        %{
          digest: "sha256:hostile-" <> Integer.to_string(n),
          repository: "registry.internal/hostile-fixture-#{n}",
          tag: "1.0",
          description: "hostile fixture image"
        },
        @now
      )

    {:ok, _} =
      Inventory.upsert_placement(
        image,
        %{namespace: "web", owner: "hostile-team", environment: @env},
        @now
      )

    {:ok, finding} =
      Inventory.upsert_finding(
        image,
        %{
          cve: "CVE-2026-#{n}-hostile",
          package_name: hostile,
          package_version: "1.0",
          severity: "LOW",
          fix: nil,
          description: hostile,
          suppressed: false
        },
        @now,
        reopen: false
      )

    {:ok, %{case: cse}} = Cases.open_case(finding.id, owner: "hostile-team", environment: @env)

    {:ok, view, _html} = live(conn, "/cases?owner=hostile-team")

    assert has_element?(view, "#case-#{cse.id}", hostile)
    assert has_element?(view, "#case-queue", hostile)
    refute has_element?(view, "script")
  end

  test "an unsupported event fails visibly and the channel stays alive", %{conn: conn} do
    cse = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, "/cases")

    assert has_element?(view, "#case-#{cse.id}")

    render_click(view, "bogus_event", %{"payload" => "forged"})

    assert has_element?(view, "#queue-error")
    refute has_element?(view, "#case-#{cse.id}")
    refute has_element?(view, "[id^='case-link-']")

    # The channel is alive: reload re-runs the still-valid current URL.
    view |> element("#reload-queue") |> render_click()

    refute has_element?(view, "#queue-error")
    assert has_element?(view, "#case-#{cse.id}")
  end

  test "queue routes are registered" do
    paths = Phoenix.Router.routes(TriageWeb.Router) |> Enum.map(& &1.path)

    assert "/cases" in paths
    assert "/cases/:id" in paths
  end

  test "the scope filters, reload and clear actions share one toolbar", %{conn: conn} do
    _cse = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, "/cases?owner=alpha")

    assert has_element?(view, "section.filter-toolbar #queue-filters")
    assert has_element?(view, "section.filter-toolbar #reload-queue")
    assert has_element?(view, "section.filter-toolbar #clear-filters[href='/cases']")
  end

  test "each row shares table headings for finding, image, saved scope, evidence, assessment and action",
       %{conn: conn} do
    cse = open_case!("busybox", "alpha")
    {:ok, view, _html} = live(conn, "/cases")
    assert has_element?(view, "tbody#case-queue > tr#case-#{cse.id}")

    for label <- [
          "Finding / package",
          "Image",
          "Saved scope",
          "Evidence / capture",
          "Assessment",
          "Action"
        ] do
      assert has_element?(view, "#queue-table thead th[scope='col']", label)
    end

    assert has_element?(view, "#case-#{cse.id}", "Case ##{cse.id}")
    assert has_element?(view, "#case-#{cse.id}", "alpha")
    assert has_element?(view, "#case-#{cse.id}", @env)
    refute has_element?(view, "#case-#{cse.id} .triage-section-label")
  end

  test "badge text states the status and colour is only a secondary cue", %{conn: conn} do
    cse = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, "/cases")

    assert has_element?(view, "#evidence-status-#{cse.id}", "Local evidence match")
    assert has_element?(view, "#review-status-#{cse.id}", "No assessment recorded")
    assert has_element?(view, "#evidence-status-#{cse.id} .status-badge-neutral")
    assert has_element?(view, "#review-status-#{cse.id} .status-badge-neutral")
  end

  test "an unknown but valid scope stays selected instead of silently showing All", %{conn: conn} do
    _cse = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, "/cases?owner=ghost-team")

    assert has_element?(view, "#queue-empty")
    assert has_element?(view, "select[name='owner'] option[value='ghost-team'][selected]")
    refute has_element?(view, "#case-queue tr")
  end

  test "the coverage notice stays compact behind a detail disclosure", %{conn: conn} do
    _cse = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, "/cases")

    assert has_element?(view, "#queue-banner", "local-operator")
    assert has_element?(view, "#queue-legend summary")
    refute has_element?(view, "#queue-legend[open]")
  end
end
