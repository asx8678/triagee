defmodule TriageWeb.StatisticsLiveTest do
  use TriageWeb.LegacyUICase, async: false
  import Phoenix.LiveViewTest
  alias Triage.Inventory.{Finding, Image}
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

    # Timeline is now shared with the workspace; it must not link users back
    # into a retired statistics route. The retained statistics screen still
    # links forward to the full timeline and its aggregate summary.
    assert has_element?(timeline, "#tl-summary")
    refute has_element?(timeline, "#timeline-observation-timing[href='/statistics']")
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

    for {cve, resolved} <- [{"CVE-OPEN", nil}, {"CVE-CLEAR", DateTime.add(now, -86_400)}] do
      Repo.insert!(%Finding{
        image_id: image.id,
        cve: cve,
        package_name: cve,
        package_version: "1",
        severity: "CRITICAL",
        first_seen: DateTime.add(now, -10 * 86_400),
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
        decided_at: DateTime.add(now, -8 * 86_400)
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
