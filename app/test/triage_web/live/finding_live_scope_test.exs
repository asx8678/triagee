defmodule TriageWeb.FindingLive.ScopeTest do
  @moduledoc """
  Environment and context regressions using a test-only additive fixture:
  image_a additionally runs for alpha in staging-cluster-1, and for beta in
  staging-cluster-1 only as a retired (inactive) placement. The seeded beta /
  staging image_b data stays untouched.
  """

  use TriageWeb.ConnCase, async: true

  import Ecto.Query
  alias Triage.Inventory.{Finding, Image, ImagePlacement}
  alias Triage.Repo
  alias Triage.Seeds

  @staging "staging-cluster-1"
  @now ~U[2026-09-09 06:00:00Z]

  setup do
    :ok = Seeds.seed()
    :ok = add_staging_fixture()
    :ok
  end

  defp add_staging_fixture do
    image_a = Repo.one!(from i in Image, where: i.repository == "registry.internal/app-a")

    {:ok, _} =
      Repo.insert(
        ImagePlacement.changeset(%ImagePlacement{}, %{
          image_id: image_a.id,
          namespace: "web",
          owner: "alpha",
          environment: @staging,
          active: true,
          first_seen: @now,
          last_seen: @now
        })
      )

    {:ok, _} =
      Repo.insert(
        ImagePlacement.changeset(%ImagePlacement{}, %{
          image_id: image_a.id,
          namespace: "web",
          owner: "beta",
          environment: @staging,
          active: false,
          first_seen: @now,
          last_seen: @now
        })
      )

    :ok
  end

  defp first_occurrence_id(cve) do
    Repo.one!(
      from f in Finding, where: f.cve == ^cve, order_by: [asc: f.id], limit: 1, select: f.id
    )
  end

  test "environment filter alone scopes the list", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings?environment=#{@staging}")

    assert has_element?(view, "#groups", "CVE-2025-1001")
    assert has_element?(view, "#groups", "CVE-2024-2002")
    # image_b (beta, staging) is outside the staging-cluster-1 scope
    refute has_element?(view, "#groups", "CVE-2025-3003")
  end

  test "owner and environment intersect on the list", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings?owner=alpha&environment=#{@staging}")

    assert has_element?(view, "#groups", "CVE-2025-1001")
  end

  test "mismatched valid scopes stay visibly empty, never invalid or unscoped", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings?owner=beta&environment=#{@staging}")

    assert has_element?(view, "p", "No open findings")
    refute has_element?(view, "#invalid-filters")
    refute has_element?(view, "#groups", "CVE-2025-1001")
  end

  test "unknown valid environments stay visibly empty", %{conn: conn} do
    {:ok, view, _html} = live(conn, "/findings?environment=ghost-cluster")

    assert has_element?(view, "p", "No open findings")
    refute has_element?(view, "#invalid-filters")
  end

  test "detail environment-only scope keeps placements and related occurrences in scope", %{
    conn: conn
  } do
    busybox_id = first_occurrence_id("CVE-2025-1001")

    {:ok, view, _html} = live(conn, "/findings/#{busybox_id}?environment=#{@staging}")

    assert has_element?(view, "#placements", "alpha")
    # the retired beta placement is displayed honestly with active "no"
    assert has_element?(view, "#placements", "beta")
    # related occurrences follow active placements in the environment only
    assert has_element?(view, "#other-occurrences", "busybox-binsh")
    refute has_element?(view, "#other-occurrences", "curl 8.5")
  end

  test "detail owner+environment intersection narrows placements and related occurrences", %{
    conn: conn
  } do
    busybox_id = first_occurrence_id("CVE-2025-1001")

    {:ok, view, _html} =
      live(conn, "/findings/#{busybox_id}?owner=alpha&environment=#{@staging}")

    assert has_element?(view, "#placements", "alpha")
    refute has_element?(view, "#placements", "beta")
    assert has_element?(view, "#other-occurrences", "busybox-binsh")
    refute has_element?(view, "#other-occurrences", "curl 8.5")
  end

  test "a retired-only scope placement does not pass the active gate", %{conn: conn} do
    busybox_id = first_occurrence_id("CVE-2025-1001")

    result = live(conn, "/findings/#{busybox_id}?owner=beta&environment=#{@staging}")

    assert {:error, {:live_redirect, %{to: to}}} = result
    uri = URI.parse(to)
    assert uri.path == "/findings"
    assert URI.decode_query(uri.query || "") == %{"owner" => "beta", "environment" => @staging}

    {:ok, _view, html} = follow_redirect(result, conn)
    assert html =~ "outside the selected"
  end

  test "all four list filters survive index to detail to back and related links", %{conn: conn} do
    qs = %{owner: "alpha", environment: "prod", q: "busybox", suppressed: "1"}
    {:ok, view, _html} = live(conn, ~p"/findings?#{qs}")

    assert has_element?(view, "#groups", "CVE-2025-1001")

    busybox_id = first_occurrence_id("CVE-2025-1001")
    expected_detail = ~p"/findings/#{busybox_id}?#{qs}"

    assert {:error, {:live_redirect, %{to: ^expected_detail}}} =
             view |> element("a", "CVE-2025-1001") |> render_click()

    {:ok, view, _html} = live(conn, expected_detail)

    # back link keeps the full list scope
    assert has_element?(view, ~s{a[href="#{~p"/findings?#{qs}"}"]}, "← Back to inventory")

    # related occurrence links keep the full scope too
    related =
      Repo.one!(
        from f in Finding, where: f.cve == "CVE-2025-1001" and f.package_name == "busybox-binsh"
      )

    assert has_element?(
             view,
             ~s{#occurrence-link-#{related.id}[href="#{~p"/findings/#{related.id}?#{qs}"}"]}
           )
  end

  test "a suppressed related occurrence is labelled honestly, not shown as ordinary", %{
    conn: conn
  } do
    image_a = Repo.one!(from i in Image, where: i.repository == "registry.internal/app-a")

    suppressed =
      Repo.insert!(%Finding{
        image_id: image_a.id,
        cve: "CVE-2024-2002",
        package_name: "openssl-cli",
        package_version: "3.1",
        severity: "CRITICAL",
        suppressed: true,
        first_seen: @now,
        last_seen: @now
      })

    openssl =
      Repo.one!(from f in Finding, where: f.cve == "CVE-2024-2002" and f.suppressed == false)

    {:ok, view, _html} = live(conn, "/findings/#{openssl.id}")

    assert has_element?(view, "#occurrence-link-#{suppressed.id}")
    assert has_element?(view, "#other-occurrences", "suppressed — not mitigation evidence")
  end
end
