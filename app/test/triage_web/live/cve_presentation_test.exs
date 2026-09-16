defmodule TriageWeb.CvePresentationTest do
  @moduledoc """
  Phase 3 closeout regressions: the activity feed names the advisory in its
  row header strictly as CURRENT LOCAL METADATA (the event heading keeps its
  own identity and kind semantics), the scope-preserving advisory link
  contract holds on every render path, no DOM id is emitted twice, and a
  blank/missing captured id degrades to honest text, never a broken link.
  Also covers the finding detail header: no duplicated id between the
  eyebrow and the title, with navigation, copy and KEV marker retained.
  """

  use TriageWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}
  alias Triage.Repo

  @now ~U[2026-09-09 06:00:00Z]

  setup do
    # Same inventory-wide baseline discipline as the other live tests.
    Triage.DataCase.reset_inventory!()
    :ok
  end

  defp image!(seed) do
    Repo.insert!(%Image{
      digest: "sha256:" <> String.duplicate(seed, 64),
      repository: "registry.internal/" <> seed,
      tag: "1.0"
    })
  end

  defp finding!(image, opts) do
    Repo.insert!(%Finding{
      image_id: image.id,
      cve: Keyword.get(opts, :cve, "CVE-2025-1001"),
      package_name: Keyword.get(opts, :package_name, "busybox"),
      package_version: Keyword.get(opts, :package_version, "1.0"),
      severity: Keyword.get(opts, :severity, "HIGH"),
      suppressed: Keyword.get(opts, :suppressed, false),
      resolved_at: Keyword.get(opts, :resolved_at),
      first_seen: @now,
      last_seen: @now
    })
  end

  defp event!(finding, name, opts) do
    Repo.insert!(%FindingEvent{
      finding_id: finding.id,
      event: name,
      occurred_at: Keyword.get(opts, :occurred_at, @now),
      note: Keyword.get(opts, :note)
    })
  end

  defp placement!(image, owner, environment, opts \\ []) do
    Repo.insert!(%ImagePlacement{
      image_id: image.id,
      namespace: Keyword.get(opts, :namespace, "web"),
      owner: owner,
      environment: environment,
      active: Keyword.get(opts, :active, true),
      first_seen: @now,
      last_seen: @now
    })
  end

  defp feed!(seed), do: feed!(seed, [])

  defp feed!(seed, opts) do
    image = image!(seed)
    finding = finding!(image, opts)

    placement!(
      image,
      Keyword.get(opts, :owner, "alpha"),
      Keyword.get(opts, :environment, "prod-cluster-1"),
      active: Keyword.get(opts, :active, true)
    )

    event =
      event!(finding, Keyword.get(opts, :event, "appeared"),
        occurred_at: Keyword.get(opts, :occurred_at, @now)
      )

    {finding, event}
  end

  test "activity row header names the advisory strictly as current local metadata, with scope and unique ids",
       %{conn: conn} do
    {finding, event} = feed!("header-pres", owner: "alpha")

    {:ok, view, _html} = live(conn, ~p"/whats-new?owner=alpha")

    # Event identity and kind semantics are unchanged: the heading is the
    # lifecycle label, joined to the same stream row.
    assert has_element?(view, "#event-title-#{event.id}", "First observed locally")

    assert has_element?(
             view,
             "#event-facts-#{event.id}[aria-labelledby='event-title-#{event.id}']"
           )

    # The advisory sits in the row header, explicitly labelled as current
    # local metadata and never as identity captured when the event happened.
    assert has_element?(view, "#event-current-advisory-#{event.id}", "Current local metadata")
    assert has_element?(view, "#event-current-advisory-#{event.id}", "Advisory")

    assert has_element?(
             view,
             "#event-advisory-provenance-#{event.id}",
             "Current local metadata — joined from current local records, not captured facts about this event"
           )

    # The row-header advisory is declared inside the recorded-facts section,
    # after the event heading.
    assert has_element?(
             view,
             "#event-facts-#{event.id} > .section-header + #event-current-advisory-#{event.id}"
           )

    # The scope-preserving advisory contract is unchanged: only the display
    # scope travels and the target is not widened to All.
    assert has_element?(
             view,
             "#event-current-advisory-#{event.id} #event-cve-#{event.id}[href='/cves/#{finding.cve}?owner=alpha']"
           )

    # The detail view still shows the joined current metadata section.
    assert has_element?(view, "#event-current-#{event.id}", "Current local metadata")
    assert has_element?(view, "#event-current-#{event.id}", "Joined from current local records")

    assert has_element?(
             view,
             "#event-current-cve-#{event.id}[href='/cves/#{finding.cve}?owner=alpha']"
           )

    # Every id carrying this row appears exactly once.
    for id <- [
          "event-#{event.id}",
          "event-title-#{event.id}",
          "event-facts-#{event.id}",
          "event-current-advisory-#{event.id}",
          "event-cve-#{event.id}",
          "event-advisory-provenance-#{event.id}",
          "event-current-#{event.id}",
          "event-current-title-#{event.id}",
          "event-current-cve-#{event.id}"
        ] do
      assert element_count(view, "##{id}") == 1
    end
  end

  test "activity row with a missing advisory id renders honest text and no advisory link",
       %{conn: conn} do
    {_finding, event} = feed!("blank-pres", cve: "", owner: "alpha")

    {:ok, view, html} = live(conn, ~p"/whats-new?owner=alpha")

    assert has_element?(
             view,
             "#event-current-advisory-#{event.id}",
             "No advisory id in current local records"
           )

    assert has_element?(
             view,
             "#event-current-#{event.id}",
             "No advisory id in current local records"
           )

    # No link at all is emitted: a blank id addresses a route that does not
    # exist, so neither render path may claim one.
    refute has_element?(view, "#event-cve-#{event.id}")
    refute has_element?(view, "#event-current-cve-#{event.id}")
    refute has_element?(view, "a[href^='/cves/']")
    refute html =~ "/cves/%"
    refute html =~ "/cves/?"
  end

  test "finding detail keeps one advisory identity: simple eyebrow, title, navigation and copy",
       %{conn: conn} do
    _kev =
      {:ok, _} =
      Triage.Intel.replace_advisories("kev", [
        %{
          external_id: "CVE-2025-1001",
          summary: "kev entry",
          published_at: ~U[2026-09-12 10:00:00Z]
        }
      ])

    {finding, _event} = feed!("finding-header-pres", owner: "alpha")

    {:ok, view, _html} = live(conn, ~p"/findings/#{finding.id}?owner=alpha")

    # The id is no longer duplicated between eyebrow and title.
    assert has_element?(view, "header .eyebrow", "Findings")
    refute has_element?(view, "header .eyebrow", "Findings /")
    refute has_element?(view, "header .eyebrow", finding.cve)
    assert has_element?(view, "header.page-header h1", finding.cve)

    # Navigation and copy affordances are retained, with the same
    # scope-preserving advisory contract.
    assert has_element?(view, "#back-to-findings[href='/findings?owner=alpha']")

    assert has_element?(
             view,
             "#finding-cve-action[href='/cves/#{finding.cve}?owner=alpha']"
           )

    assert has_element?(view, "#finding-cve-copy[aria-label='Copy exact advisory id']")
    assert has_element?(view, "#finding-cve-copy[data-copy-value='#{finding.cve}']")

    # The existing KEV marker and its source disclosure survive untouched.
    assert has_element?(view, "#finding-kev")
    assert has_element?(view, "#finding-kev-badge", "Known exploited (KEV cache)")
    assert has_element?(view, "#finding-summary-title", finding.package_name)
  end

  defp element_count(view, selector) do
    view
    |> render()
    |> LazyHTML.from_fragment()
    |> LazyHTML.query(selector)
    |> Enum.to_list()
    |> length()
  end
end
