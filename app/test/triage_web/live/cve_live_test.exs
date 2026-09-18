defmodule TriageWeb.CveLiveTest do
  use TriageWeb.ConnCase, async: false

  import Ecto.Query
  import Phoenix.LiveViewTest
  import Triage.Fixtures

  alias Triage.{Exposure, Intel, Repo, Seeds}
  alias Triage.Inventory.Finding

  setup do
    Triage.DataCase.reset_inventory!()
    :ok = Seeds.seed()
    :ok
  end

  test "renders CVE aggregate with teams, packages, exposure and priority", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/cves/CVE-2026-60002")

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

  test "real library advisories show descriptions, versions and infrastructure", %{conn: conn} do
    for {cve, packages, description, service} <- [
          {"CVE-2023-38545", ["curl", "libcurl"], "SOCKS5", "edge-gateway"},
          {"CVE-2021-44228", ["log4j-core"], "Log4Shell", "search-service"},
          {"CVE-2022-0778", ["libssl", "libcrypto"], "BN_mod_sqrt", "background-worker"},
          {"CVE-2022-37434", ["zlib"], "inflateGetHeader", "background-worker"},
          {"CVE-2023-4863", ["libwebp"], "WebP", "media-processor"},
          {"CVE-2023-4911", ["glibc"], "GLIBC_TUNABLES", "background-worker"}
        ] do
      {:ok, view, html} = live(conn, "/cves/#{cve}")
      assert html =~ description
      assert html =~ service
      assert has_element?(view, "#cve-placement-rows", "prod")

      for package <- packages do
        assert has_element?(view, "#cve-package-rows", package)
      end
    end
  end

  test "scoped advisory excludes other teams and their exposure from review priority", %{
    conn: conn
  } do
    # The same image is internet-exposed in alpha but internal in beta.
    alpha = placement_id("registry.internal/app-a", "web", "alpha")
    beta = placement_id("registry.internal/app-a", "web", "beta")

    {:ok, _} =
      Triage.Exposure.record(beta, "internal", "test:scoped placement", DateTime.utc_now())

    {:ok, view, _} = live(conn, ~p"/cves/CVE-2026-60002?owner=beta&environment=prod")

    assert has_element?(view, "#cve-placement-#{beta}", "high")
    refute has_element?(view, "#cve-placement-#{alpha}")
    refute has_element?(view, "#cve-teams", "alpha")
    assert has_element?(view, "#cve-priority .status-badge", "high")
    refute has_element?(view, "#cve-priority-reasons", "Internet-exposed")
  end

  test "a populated KEV feed without this CVE is not reported as an empty cache", %{conn: conn} do
    {:ok, 2} =
      Intel.replace_advisories("kev", [
        %{external_id: "CVE-2026-53492"},
        %{external_id: "CVE-2024-3094"}
      ])

    {:ok, _} = Intel.record_receipt("kev", true, 99)

    for cve <- ["CVE-2026-53492", "CVE-2026-60002"] do
      {:ok, view, _} = live(conn, ~p"/cves/#{cve}")
      assert has_element?(view, "#cve-kev-cache-state", "2 rows stored")
      assert has_element?(view, "#cve-intel-banner.notice-info")
      refute has_element?(view, "#cve-kev-cache-empty")
    end

    {:ok, _} = Intel.record_receipt("kev", false, nil, "request failed")
    {:ok, view, _} = live(conn, ~p"/cves/CVE-2026-60002")
    assert has_element?(view, "#cve-kev-cache-state", "2 rows stored, last refresh failed")
    assert has_element?(view, "#cve-intel", "No cached KEV entry")
    refute has_element?(view, "#cve-kev-cache-empty")
  end

  test "an intentionally empty successful refresh is not labelled never refreshed", %{conn: conn} do
    {:ok, 0} = Intel.replace_advisories("kev", [])
    {:ok, _} = Intel.record_receipt("kev", true, 0)
    {:ok, view, _} = live(conn, ~p"/cves/CVE-2026-53492")

    assert has_element?(view, "#cve-kev-cache-state", "0 rows stored, refreshed")
    assert has_element?(view, "#cve-kev-cache-empty", "No KEV advisories are currently cached")
    refute has_element?(view, "#cve-kev-cache-empty", "no refresh has stored")
  end

  test "internet-exposed placement shows escalated priority", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/cves/CVE-2026-53492")

    # image_a placement is internet_exposed per seeds
    assert html =~ "internet_exposed"
    assert html =~ "critical"
  end

  test "a retired placement never raises the headline priority", %{conn: conn} do
    image = image!("retired-scope")
    retired = placement!(image, "alpha", "prod", false)
    active = placement!(image, "alpha", "staging")
    finding!(image, "CVE-2099-700001", severity: "HIGH")

    {:ok, _} = Exposure.record(retired.id, "internet_exposed", "operator", at(0))

    {:ok, view, _html} = live(conn, ~p"/cves/CVE-2099-700001")

    # The retired placement stays visible and labelled, with its own row priority.
    assert has_element?(view, "#cve-placement-#{retired.id}", "No")
    assert has_element?(view, "#cve-placement-#{retired.id}", "critical")

    # The headline aggregate follows the active placement only.
    assert has_element?(view, "#cve-placement-#{active.id}", "high")
    refute has_element?(view, "#cve-priority", "critical")

    refute has_element?(
             view,
             "#cve-priority-reasons",
             "Internet-exposed placement with HIGH severity"
           )

    assert has_element?(view, "#cve-priority-reasons", "HIGH severity; exposure not verified")
  end

  test "internal placement shows labelled evidence", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/cves/CVE-2026-57236")

    assert html =~ "unknown"
    assert html =~ "Exposure is operator-declared evidence"
  end

  test "absent KEV cache entry is explicit, not reassuring", %{conn: conn} do
    {:ok, view, html} = live(conn, ~p"/cves/CVE-2026-60002")

    # Never fetched is an unknown, stated as one, and never shown as a finding
    # about the world ("no known exploitation").
    assert html =~ "has not been fetched"
    assert has_element?(view, "#cve-intel-kev", "Unknown")
    refute html =~ "Not exploited"
  end

  test "intelligence evidence distinguishes failed refresh from successful absence", %{conn: conn} do
    {:ok, _} = Intel.record_receipt("kev", false, nil, "offline")
    {:ok, view, _} = live(conn, ~p"/cves/CVE-2026-60002")
    assert has_element?(view, "#cve-intel-evidence", "Latest refresh failed")
    assert has_element?(view, "#cve-intel-evidence", "no retained matching data")

    {:ok, _} = Intel.record_receipt("kev", true, 0)
    render_patch(view, ~p"/cves/CVE-2026-60002")
    assert has_element?(view, "#cve-intel-evidence", "Refresh succeeded with no matching entry")
    refute has_element?(view, "#cve-intel-evidence", "Latest refresh failed")
  end

  test "priority is derived per placement, not from the advisory's worst severity", %{conn: conn} do
    # CVE-2026-57236 has a HIGH occurrence on image_a (internet_exposed placement)
    # and only a MEDIUM occurrence on the shared-base image, whose placement has no
    # exposure evidence. The unexposed placement must not inherit image_a's severity.
    {:ok, view, _html} = live(conn, ~p"/cves/CVE-2026-57236")

    exposed = placement_id("registry.internal/app-a", "web", "alpha")
    unexposed = placement_id("registry.internal/shared-base", "(unknown)", "alpha")

    assert has_element?(view, "#cve-placement-#{exposed}", "critical")
    assert has_element?(view, "#cve-placement-#{unexposed}", "medium")
  end

  test "a cached KEV entry escalates review priority for every placement", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/cves/CVE-2026-57236")

    unexposed = placement_id("registry.internal/shared-base", "(unknown)", "alpha")

    refute has_element?(view, "#cve-priority-reasons", "Actively exploited (KEV)")
    assert has_element?(view, "#cve-placement-#{unexposed}", "medium")

    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2026-57236",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    {:ok, view, html} = live(conn, ~p"/cves/CVE-2026-57236")

    assert html =~ "KEV cache match: Yes"
    assert has_element?(view, "#cve-priority-reasons", "Actively exploited (KEV)")
    # MEDIUM + unknown exposure is "medium" evidence-free; KEV raises it to "high".
    assert has_element?(view, "#cve-placement-#{unexposed}", "high")
  end

  test "the advisory links into the scoped inventory and per affected package", %{conn: conn} do
    {:ok, view, html} = live(conn, ~p"/cves/CVE-2026-53492")

    # The inventory link uses the findings page's own search contract: q matches
    # an advisory id, so the link opens that advisory's occurrences.
    assert has_element?(view, "#cve-inventory-link[href='/findings?q=CVE-2026-53492']")

    # Every affected library row links to the advisories affecting that package —
    # a real search term, never a client-side filter of the loaded rows.
    assert has_element?(view, "#cve-packages [id^='cve-package-link-']")
    assert html =~ "q=containerd"

    # One link per affected package row, addressed by the occurrence it belongs to.
    containerd =
      Repo.one!(
        from f in Finding,
          where: f.cve == "CVE-2026-53492" and f.package_name == "containerd",
          select: f.id
      )

    # Opened in a scope, the links carry that scope instead of silently widening
    # to every team. Both sides build the URL through the same contract, so the
    # expectation cannot drift from what the page renders.
    {:ok, scoped, _html} =
      live(conn, ~p"/cves/CVE-2026-53492?owner=alpha&environment=prod")

    scoped_scope = %{owner: "alpha", environment: "prod"}

    assert has_element?(
             scoped,
             "#cve-inventory-link[href='#{~p"/findings?#{Map.put(scoped_scope, :q, "CVE-2026-53492")}"}']"
           )

    assert has_element?(
             scoped,
             "#cve-package-link-#{containerd}[href='#{~p"/findings?#{Map.put(scoped_scope, :q, "containerd")}"}']"
           )
  end

  test "disagreeing public sources are shown side by side and never blended into priority",
       %{conn: conn} do
    # NVD claims the advisory is maximally severe while the scanner recorded MEDIUM and
    # this placement has no exposure evidence. A public severity claim is displayed as a
    # claim; it must not move the priority. A KEV row is exploitation evidence and does.
    unexposed = placement_id("registry.internal/shared-base", "(unknown)", "alpha")
    row = "#cve-placement-#{unexposed}"

    {:ok, view, html} = live(conn, ~p"/cves/CVE-2026-57236")

    assert has_element?(view, row, "medium")
    refute has_element?(view, row, "high")
    assert html =~ "NVD entries: 0"

    {:ok, _} =
      Intel.replace_advisories("nvd:CVE-2026-57236", [
        %{
          external_id: "CVE-2026-57236",
          summary: "NVD single-source severity claim",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    {:ok, view2, html2} = live(conn, ~p"/cves/CVE-2026-57236")

    # Displayed, attributed to its own source, and separately from KEV.
    assert html2 =~ "NVD entries: 1"
    assert has_element?(view2, "#cve-nvd-list", "NVD single-source severity claim")
    refute has_element?(view2, "#cve-kev-list", "NVD single-source severity claim")
    # No KEV refresh has been recorded here, so the honest state is "not
    # fetched" — not an absence claim about the KEV catalog.
    assert html2 =~ "KEV cache match: Unknown — KEV data has not been fetched"

    # The conflicting claim changed nothing the evidence supports.
    assert has_element?(view2, row, "medium")
    refute has_element?(view2, row, "high")

    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2026-57236",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    {:ok, view3, html3} = live(conn, ~p"/cves/CVE-2026-57236")

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
    {:ok, view, _html} = live(conn, ~p"/cves/CVE-2026-60002?owner[]=bad")

    assert has_element?(view, "#cve-scope-error")
    refute has_element?(view, "#cve-title")
  end

  test "teams are a live count from current placements, not stale text", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/cves/CVE-2026-60002")

    assert html =~ "Teams affected"
    refute html =~ "(unknown)"
  end

  test "the intel panel states how much is cached and what CISA asks for", %{conn: conn} do
    {:ok, _} =
      Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2026-53492",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z],
          required_action: "Apply updates per vendor instructions.",
          due_date: ~U[2026-01-23 00:00:00Z],
          known_ransomware: true
        }
      ])

    {:ok, _} = Intel.record_receipt("kev", true, 1)

    assert [kev] = Intel.cached_kev("CVE-2026-53492")

    {:ok, view, html} = live(conn, ~p"/cves/CVE-2026-53492")

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

    {:ok, view, html} = live(conn, ~p"/cves/CVE-2026-53492")

    assert has_element?(view, "#cve-intel-banner.notice-warning")
    assert has_element?(view, "#cve-kev-cache-empty")
    assert has_element?(view, "#cve-kev-cache-state", "last refresh failed")
    assert has_element?(view, "#cve-kev-cache-state", "request failed")
    assert html =~ "No cached KEV entry"
    refute html =~ "Required action:"
  end
end
