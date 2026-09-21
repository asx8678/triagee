defmodule TriageWeb.InventoryReadabilityTest do
  use TriageWeb.LegacyUICase, async: false

  import Ecto.Query

  alias Triage.{Inventory, Repo, Seeds}
  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}

  setup do
    Triage.DataCase.reset_inventory!()
    :ok = Seeds.seed()
    :ok
  end

  test "unknown finding scopes remain selected when an unrelated search changes", %{conn: conn} do
    {:ok, view, _} = live(conn, ~p"/findings?owner=ghost-team&environment=ghost-env")
    assert has_element?(view, "select[name='owner'] option[value='ghost-team'][selected]")
    assert has_element?(view, "select[name='environment'] option[value='ghost-env'][selected]")
    view |> form("#filter-form", %{"q" => "openssh-client"}) |> render_change()
    assert_patch(view, ~p"/findings?environment=ghost-env&owner=ghost-team&q=openssh-client")
    assert has_element?(view, "select[name='owner'] option[value='ghost-team'][selected]")
    assert has_element?(view, "select[name='environment'] option[value='ghost-env'][selected]")
    refute has_element?(view, "#groups > tr")
  end

  test "activity keeps unknown environment when another scope changes", %{conn: conn} do
    {:ok, view, _} = live(conn, ~p"/whats-new?owner=ghost-team&environment=ghost-env")
    assert has_element?(view, "select[name='owner'] option[value='ghost-team'][selected]")
    assert has_element?(view, "select[name='environment'] option[value='ghost-env'][selected]")
    view |> form("#whats-new-form", %{"owner" => "alpha"}) |> render_change()
    assert_patch(view, ~p"/whats-new?environment=ghost-env&owner=alpha")
    assert has_element?(view, "select[name='environment'] option[value='ghost-env'][selected]")
    refute has_element?(view, "#events-stream > li")
  end

  test "package search preserves whole-advisory counts and distinguishes unfiltered totals", %{
    conn: conn
  } do
    counts = Inventory.summary_counts()
    {:ok, view, _html} = live(conn, ~p"/findings?q=openssh-client")

    assert has_element?(view, "h1", "Vulnerabilities")
    assert has_element?(view, "#findings-summary", "1 matching advisory")
    assert has_element?(view, "#findings-summary", "openssh-client")
    assert has_element?(view, "#group-CVE-2026-60002 [data-field='packages']", "3 packages")
    assert has_element?(view, "#group-CVE-2026-60002 [data-field='images']", "2 images")
    assert has_element?(view, "#group-CVE-2026-60002 [data-field='occurrences']", "3 occurrences")
    assert has_element?(view, "#group-CVE-2026-60002 [data-field='teams']", "2 teams")
    assert has_element?(view, "#group-CVE-2026-60002 [data-field='fix']", "2 of 3 occurrences")
    assert has_element?(view, "#open-occurrence-count", to_string(counts.open))
    assert has_element?(view, "#suppressed-occurrence-count", to_string(counts.suppressed))
    assert has_element?(view, "#filter-form #findings-summary")
    assert has_element?(view, "#inventory-search-help", "whole advisory group")

    render_patch(view, ~p"/findings?owner=alpha&q=openssh-client")
    assert has_element?(view, "#group-CVE-2026-60002 [data-field='packages']", "2 packages")
    assert has_element?(view, "#group-CVE-2026-60002 [data-field='images']", "1 image")
    assert has_element?(view, "#open-occurrence-count", to_string(counts.open))
    assert has_element?(view, "#suppressed-occurrence-count", to_string(counts.suppressed))
  end

  test "table preserves authoritative order, suppression and reopened flags with accessible headers",
       %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings?suppressed=1")

    expected = Enum.map(Inventory.list_groups(include_suppressed: true), &"group-#{&1.cve}")
    assert row_ids(view, "#groups > tr") == Enum.take(expected, 25)

    assert has_element?(
             view,
             ".table-region[role='region'][tabindex='0'][aria-label='Advisory inventory']"
           )

    assert has_element?(view, ".data-table th[scope='col']", "Scanner severity")
    render_patch(view, ~p"/findings?suppressed=1&q=CVE-2026-57236")
    assert has_element?(view, "#group-CVE-2026-57236", "Reopened")
    render_patch(view, ~p"/findings?suppressed=1&q=CVE-2026-48931")
    assert has_element?(view, "#group-CVE-2026-48931", "1 suppressed")
    assert has_element?(view, "#group-CVE-2026-48931 [data-field='fix']", "Not reported")
    assert has_element?(view, "#findings-order-details", "affected image count")
    refute has_element?(view, "#group-CVE-2026-61625")
  end

  test "invalid filters show an error, not empty-success counts, and reset recovers", %{
    conn: conn
  } do
    {:ok, view, _html} = live(conn, ~p"/findings?q=openssh-client")
    render_change(view, "filter", %{"q" => ["openssh-client"]})

    assert has_element?(view, "#invalid-filters[role='alert']")
    refute has_element?(view, "#findings-summary")
    refute has_element?(view, "#findings-empty")
    refute has_element?(view, "#groups > tr")

    view |> element("#reset-findings") |> render_click()
    assert_patch(view, ~p"/findings")
    refute has_element?(view, "#invalid-filters")
    assert has_element?(view, "#groups > tr")

    render_patch(view, ~p"/findings?q=no-such-advisory")
    assert has_element?(view, "#findings-summary", "0 matching advisories")
    assert has_element?(view, "#findings-empty", "not proof of a clean estate")
    refute has_element?(view, "#groups #findings-empty")
  end

  test "detail identifies current occurrence before case action and keeps full filter context", %{
    conn: conn
  } do
    finding = finding!("openssh-client") |> Repo.preload(:image)
    qs = %{owner: "alpha", environment: "prod", q: "openssh-client", suppressed: "1"}
    before = record_counts()
    {:ok, view, _html} = live(conn, ~p"/findings/#{finding.id}?#{qs}")

    assert has_element?(view, "#finding-summary", "openssh-client")
    assert has_element?(view, "#finding-summary", "1:10.2p1")
    assert has_element?(view, "#finding-summary", "1:10.4p1")
    assert has_element?(view, "#finding-display-scope", "alpha · prod")
    assert has_element?(view, "#finding-summary ~ #open-case-form")
    assert has_element?(view, "#open-case-btn[data-confirm][phx-disable-with]")

    assert has_element?(
             view,
             "#open-case-form",
             "Existing cases retain their saved scope and evidence"
           )

    assert has_element?(view, "#back-to-findings[href='#{~p"/findings?#{qs}"}']")
    assert has_element?(view, "#finding-image-reference-full", "registry.internal/app-a:1.0")
    assert has_element?(view, "#finding-image-digest-full", finding.image.digest)

    assert has_element?(
             view,
             "#finding-image-digest-copy[data-copy-value='#{finding.image.digest}']"
           )

    exact = DateTime.to_iso8601(finding.first_seen)
    assert has_element?(view, "#finding-observations time[datetime='#{exact}'][title='#{exact}']")
    assert record_counts() == before
  end

  test "missing metadata is explicit and reported source text never becomes an executable link",
       %{conn: conn} do
    finding = finding!("openssh-client-common")

    Repo.update_all(from(f in Finding, where: f.id == ^finding.id),
      set: [
        description: "<img src=x onerror=alert(1)>",
        url: "javascript:alert(1)",
        severity: nil
      ]
    )

    image = Repo.get!(Image, finding.image_id)

    long_repository =
      "registry.internal/" <> String.duplicate("very-long-service/", 25) <> "image"

    Repo.update_all(from(i in Image, where: i.id == ^image.id),
      set: [repository: long_repository]
    )

    {:ok, view, _html} = live(conn, ~p"/findings/#{finding.id}")

    assert has_element?(view, "#finding-summary", "Not reported")
    assert has_element?(view, "#scanner-description", "<img src=x onerror=alert(1)>")
    refute has_element?(view, "#scanner-description img")
    refute has_element?(view, "a[href^='javascript:']")
    assert has_element?(view, "#finding-source-reference-full", "javascript:alert(1)")

    assert has_element?(
             view,
             "#finding-image-reference-copy[data-copy-value='#{long_repository}:#{image.tag}']"
           )

    assert has_element?(view, "#open-case-guidance")
    refute has_element?(view, "#open-case-btn")
  end

  test "disappearance history is not relabelled as remediation", %{conn: conn} do
    finding = finding!("victoria-metrics")
    {:ok, view, _html} = live(conn, ~p"/findings/#{finding.id}")

    assert has_element?(view, "#finding-summary", "No longer observed in local inventory")
    assert has_element?(view, "#finding-disappearance-warning", "not verified remediation")
    assert has_element?(view, "#finding-history", "No longer observed in local inventory")
    refute has_element?(view, "#finding-history h3", "Resolved")
  end

  test "activity return context is independently validated and cannot relabel finding or case scope",
       %{conn: conn} do
    finding = finding!("openssh-client")
    context = %{from: "activity", owner: "beta", environment: "other-environment", before: "12"}
    scope = %{owner: "alpha", environment: "prod", q: "openssh-client", suppressed: "1"}
    params = Map.put(scope, :activity, context)
    {:ok, view, _html} = live(conn, ~p"/findings/#{finding.id}?#{params}")

    expected = ~p"/whats-new?#{Map.delete(context, :from)}"
    assert has_element?(view, "#back-to-activity[href='#{expected}']")
    assert has_element?(view, "#finding-display-scope", "alpha · prod")
    assert has_element?(view, "#open-case-btn", "alpha · prod")
    refute has_element?(view, "#placements", "beta")
    related = finding!("openssh-client-common")

    assert has_element?(
             view,
             "#occurrence-link-#{related.id}[href='#{~p"/findings/#{related.id}?#{params}"}']"
           )

    for invalid <- [
          %{from: "activity", before: "-1"},
          %{from: "activity", owner: ["alpha"]},
          %{from: "https://outside.invalid"}
        ] do
      render_patch(view, ~p"/findings/#{finding.id}?#{Map.put(scope, :activity, invalid)}")
      refute has_element?(view, "#back-to-activity")
      refute has_element?(view, "#invalid-scope")
      assert has_element?(view, "#finding-display-scope", "alpha · prod")
    end
  end

  test "finding detail breadcrumb names the CVE and occurrence stays in the identity strip", %{
    conn: conn
  } do
    finding = finding!("openssh-client")
    {:ok, view, _html} = live(conn, ~p"/findings/#{finding.id}")

    # The advisory id is the page title and copy target; repeating it in the eyebrow
    # was the deliberate round-3 dedupe, so the eyebrow names only the section.
    assert has_element?(view, ".page-header .eyebrow", "Findings")
    refute has_element?(view, ".page-header .eyebrow", finding.cve)
    assert has_element?(view, ".page-header h1", finding.cve)
    assert has_element?(view, "#finding-summary", "Occurrence ##{finding.id}")
  end

  defp finding!(package) do
    Repo.one!(from f in Finding, where: f.package_name == ^package)
  end

  defp row_ids(view, selector) do
    view
    |> render()
    |> LazyHTML.from_fragment()
    |> LazyHTML.query(selector)
    |> LazyHTML.attribute("id")
  end

  defp record_counts do
    for schema <- [
          Finding,
          FindingEvent,
          Image,
          ImagePlacement,
          Triage.Cases.ReviewCase,
          Triage.Cases.EvidenceSnapshot,
          Triage.Cases.Review,
          Triage.Cases.CaseEvent
        ],
        into: %{},
        do: {schema, Repo.aggregate(schema, :count)}
  end
end
