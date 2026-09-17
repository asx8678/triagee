defmodule TriageWeb.CveLiveTest do
  use TriageWeb.ConnCase, async: false

  import Ecto.Query
  import Phoenix.LiveViewTest
  import Triage.Fixtures

  alias Triage.{Exposure, Intel, Repo, Seeds}

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
end
