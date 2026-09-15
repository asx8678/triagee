defmodule TriageWeb.CveLiveTest do
  use TriageWeb.ConnCase, async: false

  import Ecto.Query
  import Phoenix.LiveViewTest

  alias Triage.{Intel, Repo, Seeds}
  alias Triage.Inventory.Finding

  setup do
    Triage.DataCase.reset_inventory!()
    :ok = Seeds.seed()
    :ok
  end

  test "renders CVE aggregate with teams, packages, exposure and priority", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/cves/CVE-2025-1001")

    assert html =~ "Advisory"
    assert html =~ "Teams affected"
    assert html =~ "alpha"
    assert html =~ "beta"
    assert html =~ "exec" or html =~ "critical" or html =~ "high"
    assert html =~ "Package"
    assert html =~ "Placements"
    assert html =~ "Exposure"
    assert html =~ "Lifecycle"
  end

  test "scoped advisory excludes other teams and their exposure from review priority", %{
    conn: conn
  } do
    # The same image is internet-exposed in alpha but internal in beta.
    alpha = placement_id("registry.internal/app-a", "web", "alpha")
    beta = placement_id("registry.internal/app-a", "web", "beta")

    {:ok, _} =
      Triage.Exposure.record(beta, "internal", "test:scoped placement", DateTime.utc_now())

    {:ok, view, _} = live(conn, ~p"/cves/CVE-2024-4004?owner=beta&environment=prod-cluster-1")

    assert has_element?(view, "#cve-placement-#{beta}", "high")
    refute has_element?(view, "#cve-placement-#{alpha}")
    refute has_element?(view, "#cve-teams", "alpha")
    assert has_element?(view, "#cve-priority .status-badge", "high")
    refute has_element?(view, "#cve-priority-reasons", "Internet-exposed")
  end

  test "a populated KEV feed without this CVE is not reported as an empty cache", %{conn: conn} do
    {:ok, 2} =
      Intel.replace_advisories("kev", [
        %{external_id: "CVE-2025-1001"},
        %{external_id: "CVE-2024-3094"}
      ])

    {:ok, _} = Intel.record_receipt("kev", true, 99)

    for cve <- ["CVE-2025-1001", "CVE-2024-4004"] do
      {:ok, view, _} = live(conn, ~p"/cves/#{cve}")
      assert has_element?(view, "#cve-kev-cache-state", "2 rows stored")
      assert has_element?(view, "#cve-intel-banner.notice-info")
      refute has_element?(view, "#cve-kev-cache-empty")
    end

    {:ok, _} = Intel.record_receipt("kev", false, nil, "request failed")
    {:ok, view, _} = live(conn, ~p"/cves/CVE-2024-4004")
    assert has_element?(view, "#cve-kev-cache-state", "2 rows stored, last refresh failed")
    assert has_element?(view, "#cve-intel", "No cached KEV entry")
    refute has_element?(view, "#cve-kev-cache-empty")
  end

  test "an intentionally empty successful refresh is not labelled never refreshed", %{conn: conn} do
    {:ok, 0} = Intel.replace_advisories("kev", [])
    {:ok, _} = Intel.record_receipt("kev", true, 0)
    {:ok, view, _} = live(conn, ~p"/cves/CVE-2025-1001")

    assert has_element?(view, "#cve-kev-cache-state", "0 rows stored, refreshed")
    assert has_element?(view, "#cve-kev-cache-empty", "No KEV advisories are currently cached")
    refute has_element?(view, "#cve-kev-cache-empty", "no refresh has stored")
  end

  test "internet-exposed placement shows escalated priority", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/cves/CVE-2024-2002")

    # image_a placement is internet_exposed per seeds
    assert html =~ "internet_exposed"
    assert html =~ "critical"
  end

  test "internal placement shows labelled evidence", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/cves/CVE-2024-4004")

    assert html =~ "unknown"
    assert html =~ "Exposure is operator-declared evidence"
  end

  test "absent KEV cache entry is explicit, not reassuring", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/cves/CVE-2025-1001")

    assert html =~ "No cached KEV entry" or html =~ "never fetched"
  end

  test "priority is derived per placement, not from the advisory's worst severity", %{conn: conn} do
    # CVE-2024-4004 has a HIGH occurrence on image_a (internet_exposed placement)
    # and only a MEDIUM occurrence on the shared-base image, whose placement has no
    # exposure evidence. The unexposed placement must not inherit image_a's severity.
    {:ok, view, _html} = live(conn, ~p"/cves/CVE-2024-4004")

    exposed = placement_id("registry.internal/app-a", "web", "alpha")
    unexposed = placement_id("registry.internal/shared-base", "(unknown)", "alpha")

    assert has_element?(view, "#cve-placement-#{exposed}", "critical")
    assert has_element?(view, "#cve-placement-#{unexposed}", "medium")
  end

  test "a cached KEV entry escalates review priority for every placement", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/cves/CVE-2024-4004")

    unexposed = placement_id("registry.internal/shared-base", "(unknown)", "alpha")

    refute has_element?(view, "#cve-priority-reasons", "Actively exploited (KEV)")
    assert has_element?(view, "#cve-placement-#{unexposed}", "medium")

    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2024-4004",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    {:ok, view, html} = live(conn, ~p"/cves/CVE-2024-4004")

    assert html =~ "KEV cache match: Yes"
    assert has_element?(view, "#cve-priority-reasons", "Actively exploited (KEV)")
    # MEDIUM + unknown exposure is "medium" evidence-free; KEV raises it to "high".
    assert has_element?(view, "#cve-placement-#{unexposed}", "high")
  end

  test "the advisory links into the scoped inventory and per affected package", %{conn: conn} do
    {:ok, view, html} = live(conn, ~p"/cves/CVE-2025-1001")

    # The inventory link uses the findings page's own search contract: q matches
    # an advisory id, so the link opens that advisory's occurrences.
    assert has_element?(view, "#cve-inventory-link[href='/findings?q=CVE-2025-1001']")

    # Every affected library row links to the advisories affecting that package —
    # a real search term, never a client-side filter of the loaded rows.
    assert has_element?(view, "#cve-packages [id^='cve-package-link-']")
    assert html =~ "q=busybox"

    # One link per affected package row, addressed by the occurrence it belongs to.
    busybox =
      Repo.one!(
        from f in Finding,
          where: f.cve == "CVE-2025-1001" and f.package_name == "busybox",
          select: f.id
      )

    # Opened in a scope, the links carry that scope instead of silently widening
    # to every team. Both sides build the URL through the same contract, so the
    # expectation cannot drift from what the page renders.
    {:ok, scoped, _html} =
      live(conn, ~p"/cves/CVE-2025-1001?owner=alpha&environment=prod-cluster-1")

    scoped_scope = %{owner: "alpha", environment: "prod-cluster-1"}

    assert has_element?(
             scoped,
             "#cve-inventory-link[href='#{~p"/findings?#{Map.put(scoped_scope, :q, "CVE-2025-1001")}"}']"
           )

    assert has_element?(
             scoped,
             "#cve-package-link-#{busybox}[href='#{~p"/findings?#{Map.put(scoped_scope, :q, "busybox")}"}']"
           )
  end

  test "disagreeing public sources are shown side by side and never blended into priority",
       %{conn: conn} do
    # NVD claims the advisory is maximally severe while the scanner recorded MEDIUM and
    # this placement has no exposure evidence. A public severity claim is displayed as a
    # claim; it must not move the priority. A KEV row is exploitation evidence and does.
    unexposed = placement_id("registry.internal/shared-base", "(unknown)", "alpha")
    row = "#cve-placement-#{unexposed}"

    {:ok, view, html} = live(conn, ~p"/cves/CVE-2024-4004")

    assert has_element?(view, row, "medium")
    refute has_element?(view, row, "high")
    assert html =~ "NVD entries: 0"

    {:ok, _} =
      Intel.replace_advisories("nvd:CVE-2024-4004", [
        %{
          external_id: "CVE-2024-4004",
          summary: "NVD single-source severity claim",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    {:ok, view2, html2} = live(conn, ~p"/cves/CVE-2024-4004")

    # Displayed, attributed to its own source, and separately from KEV.
    assert html2 =~ "NVD entries: 1"
    assert has_element?(view2, "#cve-nvd-list", "NVD single-source severity claim")
    refute has_element?(view2, "#cve-kev-list", "NVD single-source severity claim")
    assert html2 =~ "KEV cache match: No cached KEV entry"

    # The conflicting claim changed nothing the evidence supports.
    assert has_element?(view2, row, "medium")
    refute has_element?(view2, row, "high")

    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2024-4004",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    {:ok, view3, html3} = live(conn, ~p"/cves/CVE-2024-4004")

    # Exploitation evidence, unlike the severity claim, does raise priority.
    assert html3 =~ "KEV cache match: Yes"
    assert has_element?(view3, "#cve-priority-reasons", "Actively exploited (KEV)")
    assert has_element?(view3, row, "high")
  end

  defp placement_id(repository, namespace, owner) do
    Repo.one!(
      from(p in Triage.Inventory.ImagePlacement,
        join: i in Triage.Inventory.Image,
        on: i.id == p.image_id,
        where: i.repository == ^repository and p.namespace == ^namespace and p.owner == ^owner,
        select: p.id
      )
    )
  end

  test "unknown advisory navs back with error", %{conn: conn} do
    assert {:error, {:live_redirect, %{to: "/findings"}}} = live(conn, ~p"/cves/CVE-2099-9999")
  end

  test "invalid scope shows visible error, no advisory", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/cves/CVE-2025-1001?owner[]=bad")

    assert has_element?(view, "#cve-scope-error")
    refute has_element?(view, "#cve-title")
  end

  test "teams are a live count from current placements, not stale text", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/cves/CVE-2025-1001")

    assert html =~ "Teams affected"
    refute html =~ "(unknown)"
  end

  test "the intel panel states how much is cached and what CISA asks for", %{conn: conn} do
    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2025-1001",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z],
          required_action: "Apply updates per vendor instructions.",
          due_date: ~U[2026-01-23 00:00:00Z],
          known_ransomware: true
        }
      ])

    {:ok, _} = Intel.record_receipt("kev", true, 1)

    assert [kev] = Intel.cached_kev("CVE-2025-1001")

    {:ok, view, html} = live(conn, ~p"/cves/CVE-2025-1001")

    assert html =~ "KEV cache match: Yes"
    assert has_element?(view, "#cve-intel-banner.notice-info")
    assert has_element?(view, "#cve-kev-cache-state", "1 row stored")

    assert has_element?(
             view,
             "#cve-kev-action-#{kev.id}",
             "Apply updates per vendor instructions."
           )

    assert has_element?(view, "#cve-kev-due-#{kev.id} time")
    assert has_element?(view, "#cve-kev-ransomware-#{kev.id}", "known ransomware campaign use")
    refute has_element?(view, "#cve-kev-cache-empty")
  end

  test "an empty KEV cache is a warning about the cache, not a claim about the advisory",
       %{conn: conn} do
    {:ok, _} = Intel.record_receipt("kev", false, nil, "request failed")

    {:ok, view, html} = live(conn, ~p"/cves/CVE-2025-1001")

    assert has_element?(view, "#cve-intel-banner.notice-warning")
    assert has_element?(view, "#cve-kev-cache-empty")
    assert has_element?(view, "#cve-kev-cache-state", "last refresh failed")
    assert has_element?(view, "#cve-kev-cache-state", "request failed")
    assert html =~ "No cached KEV entry"
    refute html =~ "Required action:"
  end
end
