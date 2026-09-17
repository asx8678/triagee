defmodule TriageWeb.StatisticsLiveTest do
  use TriageWeb.ConnCase, async: false
  import Phoenix.LiveViewTest
  alias Triage.Inventory.{Image, Finding}
  alias Triage.Repo

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  test "statistics retains aggregates and links to timeline without duplicating CVE rows", %{
    conn: conn
  } do
    {:ok, view, _} = live(conn, ~p"/statistics")
    assert has_element?(view, "#nav-statistics[aria-current='page']")
    assert has_element?(view, "#statistics-empty", "not proof of a clean estate")
    assert has_element?(view, "#stat-card-total .stat-card-value", "0")
    assert has_element?(view, "#statistics-timeline[href='/timeline#tl-lanes']")
    refute has_element?(view, "#statistics-table")

    assert {:error, {:live_redirect, %{to: "/timeline#tl-lanes"}}} =
             view |> element("#statistics-timeline") |> render_click()

    {:ok, timeline, _} = live(conn, ~p"/timeline")
    assert has_element?(timeline, "#tl-lanes-title", "time to fix")

    assert has_element?(
             timeline,
             "#timeline-observation-timing[href='/statistics']",
             "Summary statistics"
           )
  end

  test "reload updates aggregates, preserving clearance and whitelist metrics", %{conn: conn} do
    {:ok, view, _} = live(conn, ~p"/statistics")
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    image =
      Repo.insert!(%Image{
        digest: "sha256:" <> String.duplicate("a", 64),
        repository: "test",
        tag: "1"
      })

    for {cve, resolved} <- [{"CVE-OPEN", nil}, {"CVE-CLEAR", DateTime.add(now, -86400)}] do
      Repo.insert!(%Finding{
        image_id: image.id,
        cve: cve,
        package_name: cve,
        package_version: "1",
        severity: "CRITICAL",
        first_seen: DateTime.add(now, -10 * 86400),
        last_seen: now,
        resolved_at: resolved
      })
    end

    {:ok, _} =
      Triage.Decisions.record(%{
        cve: "CVE-OPEN",
        decision: "not_affected",
        reason: "Not applicable",
        actor: "test",
        decided_at: DateTime.add(now, -8 * 86400)
      })

    render_click(view, "reload")
    refute has_element?(view, "#statistics-empty")
    refute has_element?(view, "#statistics-table")
    assert has_element?(view, "#stat-card-total .stat-card-value", "2")
    assert has_element?(view, "#stat-card-open .stat-card-value", "1")
    assert has_element?(view, "#stat-card-median-clear .stat-card-value", "9")
    assert has_element?(view, "#stat-card-median-decision .stat-card-value", "2.0")
  end
end
