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

  test "internet-exposed placement shows escalated priority", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/cves/CVE-2024-2002")

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
    assert html2 =~ "KEV cache match: No cached entry"

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
end
