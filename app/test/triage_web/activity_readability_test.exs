defmodule TriageWeb.ActivityReadabilityTest do
  use TriageWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}
  alias Triage.Repo

  @now ~U[2026-09-09 06:00:00Z]

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  test "one compact notice carries both the placement caveat and the time caveat", %{conn: conn} do
    _event = feed!("compact", "appeared", @now)
    {:ok, view, _html} = live(conn, ~p"/whats-new")

    assert has_element?(view, "#feed-banner.notice", "not historical event ownership")
    assert has_element?(view, "#feed-banner", "not CVE publication")
    refute has_element?(view, "#event-time-context")
  end

  test "event types are visually differentiated and relative time is rendered server-side", %{
    conn: conn
  } do
    appeared = feed!("appeared", "appeared", @now)
    resolved = feed!("resolved", "resolved", @now)

    {:ok, view, _html} = live(conn, ~p"/whats-new")

    assert has_element?(view, "li#event-#{appeared.id}.event-item-appeared")
    assert has_element?(view, "li#event-#{resolved.id}.event-item-resolved")
    assert has_element?(view, "#event-relative-#{appeared.id}")
    assert has_element?(view, "#event-relative-#{resolved.id}")
  end

  test "secondary controls collapse without hiding active scope", %{conn: conn} do
    for {path, id} <- [
          {"/cases", "case-filter-details"},
          {"/whats-new", "activity-filter-details"}
        ] do
      {:ok, view, _} = live(conn, path)
      assert has_element?(view, "details##{id}:not([open]) > summary")
      {:ok, scoped, _} = live(conn, path <> "?owner=alpha")
      assert has_element?(scoped, "details##{id}[open]")
    end
  end

  test "long explanations are disclosed with visible evidence limitations", %{conn: conn} do
    {:ok, activity, _} = live(conn, "/whats-new")
    assert has_element?(activity, "#activity-help:not([open]) > summary", "not proof of a fix")
    assert has_element?(activity, "#activity-help #feed-banner", "not historical event ownership")
    {:ok, statistics, _} = live(conn, "/statistics")

    assert has_element?(
             statistics,
             "#statistics-help:not([open]) > summary",
             "not verified remediation"
           )

    assert has_element?(
             statistics,
             "#statistics-help #statistics-note",
             "not verified remediation"
           )
  end

  defp feed!(seed, event_name, occurred_at) do
    image =
      Repo.insert!(%Image{
        digest: "sha256:" <> String.duplicate(seed, 64),
        repository: "registry.internal/" <> seed,
        tag: "1.0"
      })

    finding =
      Repo.insert!(%Finding{
        image_id: image.id,
        cve: "CVE-2025-1001",
        package_name: "busybox",
        package_version: "1.0",
        severity: "HIGH",
        suppressed: false,
        first_seen: @now,
        last_seen: @now
      })

    Repo.insert!(%ImagePlacement{
      image_id: image.id,
      namespace: "web",
      owner: "alpha",
      environment: "prod-cluster-1",
      active: true,
      first_seen: @now,
      last_seen: @now
    })

    Repo.insert!(%FindingEvent{
      finding_id: finding.id,
      event: event_name,
      occurred_at: occurred_at
    })
  end
end
