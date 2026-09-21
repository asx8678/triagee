defmodule TriageWeb.KevStatusTest do
  @moduledoc """
  KEV source freshness on the CVE surfaces.

  Findings, queue, case header and timeline each show the cache source, the
  whole-source row count and the latest refresh result/timestamp once — with or
  without badges, cache rows or receipts. Only a cached row ever earns a badge,
  and a failed refresh never erases one. Synthetic fixtures only; no live feed
  is contacted here.
  """

  use TriageWeb.LegacyUICase, async: false

  import Ecto.Query
  import Phoenix.LiveViewTest

  alias Triage.Cases
  alias Triage.Intel
  alias Triage.Inventory.Finding
  alias Triage.LegacyFixtures, as: Seeds
  alias Triage.Repo

  @env "prod-cluster-1"

  setup do
    :ok = Seeds.seed()
    clear_intel!()
    :ok
  end

  # The intel cache and receipts are global per test database; a fresh state
  # makes each assertion attributable to this test's rows only.
  defp clear_intel! do
    Repo.delete_all(Intel.RefreshReceipt)
    Repo.delete_all(Intel.Advisory)
  end

  defp finding_id(package) do
    Repo.one!(
      from f in Finding,
        where: f.cve == "CVE-2025-1001" and f.package_name == ^package,
        select: f.id
    )
  end

  defp open_case!(package, owner) do
    {:ok, %{case: cse}} = Cases.open_case(finding_id(package), owner: owner, environment: @env)
    cse
  end

  defp cache_kev!(external_ids) do
    {:ok, _} =
      Intel.replace_advisories(
        "kev",
        Enum.map(external_ids, fn id ->
          %{external_id: id, summary: "kev entry", published_at: ~U[2026-09-12 10:00:00Z]}
        end)
      )
  end

  test "never refreshed: all four surfaces state the source and honestly omit a refresh result",
       %{
         conn: conn
       } do
    {:ok, view, _html} = live(conn, ~p"/findings")

    assert has_element?(view, "#inventory-kev-status", "KEV cache (source \"kev\")")

    assert has_element?(
             view,
             "#inventory-kev-status",
             "0 cached advisories across the whole source"
           )

    assert has_element?(view, "#inventory-kev-status", "No refresh has been recorded yet")
    refute has_element?(view, ".kev-flag")

    {:ok, view, _html} = live(conn, "/cases")
    assert has_element?(view, "#queue-kev-status", "No refresh has been recorded yet")
    refute has_element?(view, "#queue-kev-note")

    cse = open_case!("busybox", "alpha")

    {:ok, view, _html} =
      live(conn, ~p"/cases/#{cse.id}?#{%{owner: "alpha", environment: @env}}")

    assert has_element?(view, "#case-kev-status", "No refresh has been recorded yet")
    refute has_element?(view, "#case-kev")

    {:ok, view, _html} = live(conn, ~p"/timeline")
    assert has_element?(view, "#tl-lanes-kev-status", "No refresh has been recorded yet")
  end

  test "a successful refresh with no matching advisory shows source state and no badges", %{
    conn: conn
  } do
    cache_kev!(["CVE-2099-9999"])
    {:ok, _} = Intel.record_receipt("kev", true, 1)

    _cse = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, ~p"/findings")

    assert has_element?(
             view,
             "#inventory-kev-status",
             "1 cached advisory across the whole source"
           )

    assert has_element?(view, "#inventory-kev-status", "Last refresh succeeded")
    assert has_element?(view, "#inventory-kev-status", "reported 1 feed item")
    refute has_element?(view, ".kev-flag")
    refute has_element?(view, "#inventory-kev-note")

    {:ok, view, _html} = live(conn, "/cases")
    assert has_element?(view, "#queue-kev-status", "Last refresh succeeded")
    refute has_element?(view, ".kev-flag")
    refute has_element?(view, "#queue-kev-note")
  end

  test "the whole-source count is shown, not the rows this scoped view matched", %{conn: conn} do
    cache_kev!(["CVE-2025-1001", "CVE-2099-9999"])
    {:ok, _} = Intel.record_receipt("kev", true, 2)

    {:ok, view, _html} = live(conn, ~p"/findings?#{%{owner: "alpha", environment: @env}}")

    # The display scope is preserved exactly: no widening, and the badge still
    # marks the cached row inside that scope.
    assert has_element?(view, "#findings-summary", "alpha")
    assert has_element?(view, "#findings-summary", @env)
    assert has_element?(view, "#group-kev-CVE-2025-1001", "Known exploited (KEV cache)")

    # The badge count follows cached rows in this view (1); the status count is
    # the whole KEV source (2), never the rows this view matched.
    assert has_element?(
             view,
             "#inventory-kev-status",
             "2 cached advisories across the whole source"
           )

    assert has_element?(view, "#inventory-kev-status", "not just the rows of this view")

    badges =
      view
      |> render()
      |> LazyHTML.from_document()
      |> LazyHTML.query(".kev-flag")
      |> Enum.count()

    assert badges == 1
  end

  test "an empty successful refresh is an honest outcome, never a clear signal", %{conn: conn} do
    cache_kev!([])
    {:ok, _} = Intel.record_receipt("kev", true, 0)

    {:ok, view, _html} = live(conn, ~p"/findings")

    assert has_element?(
             view,
             "#inventory-kev-status",
             "0 cached advisories across the whole source"
           )

    assert has_element?(view, "#inventory-kev-status", "reported 0 items — an empty feed report")
    assert has_element?(view, "#inventory-kev-status", "not a claim that nothing is exploited")
    refute has_element?(view, ".kev-flag")
  end

  test "a failed last refresh is shown while the retained cache still earns badges everywhere", %{
    conn: conn
  } do
    cache_kev!(["CVE-2025-1001"])
    {:ok, _} = Intel.record_receipt("kev", true, 1)
    {:ok, _} = Intel.record_receipt("kev", false, nil, "simulated feed outage")

    cse = open_case!("busybox", "alpha")

    {:ok, view, _html} = live(conn, ~p"/findings")
    assert has_element?(view, "#group-kev-CVE-2025-1001")
    assert has_element?(view, "#inventory-kev-status", "Last refresh failed")
    assert has_element?(view, "#inventory-kev-status", "are retained, not erased")
    assert has_element?(view, "#inventory-kev-status", "(simulated feed outage)")

    {:ok, view, _html} = live(conn, "/cases")
    assert has_element?(view, "#case-kev-#{cse.id}", "Known exploited (KEV cache)")
    assert has_element?(view, "#queue-kev-status", "Last refresh failed")

    {:ok, view, _html} =
      live(conn, ~p"/cases/#{cse.id}?#{%{owner: "alpha", environment: @env}}")

    assert has_element?(view, "#case-kev-badge")
    assert has_element?(view, "#case-kev-status", "Last refresh failed")

    {:ok, view, _html} = live(conn, ~p"/timeline")
    assert has_element?(view, "#tl-lanes-kev-status", "Last refresh failed")
    assert has_element?(view, "#tl-lanes-kev-status", "1 cached advisory across the whole source")
  end

  test "invalid filters render the explicit not-read status instead of a freshness claim", %{
    conn: conn
  } do
    cache_kev!(["CVE-2025-1001"])
    {:ok, _} = Intel.record_receipt("kev", true, 1)

    {:ok, view, _html} = live(conn, ~p"/findings?#{%{severity: "BOGUS"}}")

    assert has_element?(view, "#invalid-filters")
    assert has_element?(view, "#inventory-kev-status", "was not read for this view")
    refute has_element?(view, ".kev-flag")
  end
end
