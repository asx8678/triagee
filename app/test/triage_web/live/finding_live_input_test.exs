defmodule TriageWeb.FindingLive.InputTest do
  @moduledoc """
  Input-boundary regressions for malformed query params (list and detail),
  malformed filter events and finding-id bounds (findings.id is a bigint).
  """

  use TriageWeb.LegacyUICase, async: true

  import Ecto.Query
  alias Triage.Inventory.Finding
  alias Triage.Repo
  alias Triage.Seeds

  setup do
    :ok = Seeds.seed()
    :ok
  end

  defp openssh_client_finding do
    Repo.one!(
      from f in Finding, where: f.cve == "CVE-2026-60002" and f.package_name == "openssh-client"
    )
  end

  @tag :capture_log
  test "index renders a visible invalid-filter state, not a crash or unscoped list", %{conn: conn} do
    for path <-
          ~w(/findings?owner[]=alpha /findings?environment[x]=prod /findings?q[]=openssh-client /findings?q[x]=value /findings?owner=a%00b) do
      {:ok, view, _html} = live(conn, path)

      assert has_element?(view, "#invalid-filters")
      refute has_element?(view, "#groups > tr")
      refute has_element?(view, "#groups", "CVE-2026-53492")
    end
  end

  @tag :capture_log
  test "detail renders a visible invalid-scope state with no finding data", %{conn: conn} do
    finding = openssh_client_finding()

    for suffix <-
          ~w(owner[]=alpha environment[x]=prod q[]=openssh-client q[x]=value owner=a%00b owner=%09alpha q=openssh-client%0A suppressed=%0A1) do
      {:ok, view, _html} = live(conn, "/findings/#{finding.id}?#{suffix}")

      assert has_element?(view, "#invalid-scope")
      refute has_element?(view, "#placements")
      refute has_element?(view, "#other-occurrences")
    end
  end

  @tag :capture_log
  test "an invalid scope on an already-rendered detail clears stale data, keeps the last-valid back scope and recovers",
       %{
         conn: conn
       } do
    finding = openssh_client_finding()
    {:ok, view, _html} = live(conn, "/findings/#{finding.id}?owner=alpha")

    assert has_element?(view, "#placements", "alpha")
    assert has_element?(view, "#other-occurrences")

    # Same-LiveView transition to an invalid scope must not keep rendering the
    # previously loaded finding, placements or related occurrences.
    render_patch(view, "/findings/#{finding.id}?owner[]=alpha")

    assert has_element?(view, "#invalid-scope")
    refute has_element?(view, "#placements")
    refute has_element?(view, "#other-occurrences")
    refute has_element?(view, "h1", "CVE-2026-60002")

    # the explicit last-valid back scope survives, without stale finding data
    assert has_element?(view, ~s{a[href="/findings?owner=alpha"]}, "← Back to inventory")

    # invalid -> valid recovery on the same LiveView
    render_patch(view, "/findings/#{finding.id}?owner=alpha")

    refute has_element?(view, "#invalid-scope")
    assert has_element?(view, "#placements", "alpha")
    assert has_element?(view, "#other-occurrences")
  end

  @tag :capture_log
  test "raw control characters are rejected on list URL and event boundaries even when trimmable",
       %{
         conn: conn
       } do
    for path <-
          ~w(/findings?owner=%09alpha /findings?owner=alpha%0A /findings?q=busy%08box /findings?environment=prod%0D /findings?suppressed=%0A1) do
      {:ok, view, _html} = live(conn, path)

      assert has_element?(view, "#invalid-filters")
      refute has_element?(view, "#groups > tr")
    end

    {:ok, view, _html} = live(conn, ~p"/findings")

    view
    |> element("#filter-form")
    |> render_change(%{
      "owner" => "\talpha",
      "environment" => "prod\n",
      "q" => "openssh-sftp-server"
    })

    assert has_element?(view, "#invalid-filters")
    refute has_element?(view, "#groups > tr")

    view
    |> element("#filter-form")
    |> render_change(%{"suppressed" => "1\t"})

    assert has_element?(view, "#invalid-filters")
  end

  @tag :capture_log
  test "filter events with map-valued fields show the invalid state and no findings", %{
    conn: conn
  } do
    {:ok, view, _html} = live(conn, ~p"/findings")

    view
    |> element("#filter-form")
    |> render_change(%{"owner" => %{"x" => "prod"}, "q" => "openssh-client"})

    assert has_element?(view, "#invalid-filters")
    refute has_element?(view, "#groups > tr")
  end

  @tag :capture_log
  test "filter events with a nested filters wrapper are validated explicitly", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings")

    view
    |> element("#filter-form")
    |> render_change(%{"filters" => %{"owner" => %{"x" => "prod"}}})

    assert has_element?(view, "#invalid-filters")
    refute has_element?(view, "#groups > tr")
  end

  @tag :capture_log
  test "a doubly nested filters wrapper is rejected instead of unwrapping to All", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings?owner=alpha")

    assert has_element?(view, "#groups > tr")

    view
    |> element("#filter-form")
    |> render_change(%{"filters" => %{"filters" => %{"owner" => ["alpha"]}}})

    assert has_element?(view, "#invalid-filters")
    # neither the prior alpha scope nor an unscoped All list may render
    refute has_element?(view, "#groups > tr")
    refute has_element?(view, "#groups", "CVE-2026-48931")
  end

  @tag :capture_log
  test "non-map filter event bodies keep the view alive, show the invalid state and recover", %{
    conn: conn
  } do
    {:ok, view, _html} = live(conn, ~p"/findings")
    assert has_element?(view, "#groups > tr")

    # Simulates a raw channel pushEvent("filter", []) — a non-map body that
    # used to crash the LiveView with a FunctionClauseError before
    # parse_event/1 was made total. (Scalar bodies 123, nil and true are
    # exercised directly against the parser in FindingFiltersTest; the
    # LiveViewTest harness itself only accepts map-or-list event bodies.)
    render_hook(view, "filter", [])

    assert has_element?(view, "#invalid-filters")
    refute has_element?(view, "#groups > tr")

    # the connection stays alive and a valid event recovers to a filtered patch
    view
    |> element("#filter-form")
    |> render_change(%{"owner" => "beta", "q" => "openssh-sftp-server"})

    assert_patch(view, ~p"/findings?owner=beta&q=openssh-sftp-server")
    refute has_element?(view, "#invalid-filters")
    assert has_element?(view, "#group-CVE-2026-60002")
  end

  @tag :capture_log
  test "filter events with a non-map filters wrapper are rejected", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings")

    view
    |> element("#filter-form")
    |> render_change(%{"filters" => "not-a-map"})

    assert has_element?(view, "#invalid-filters")
    refute has_element?(view, "#groups > tr")
  end

  test "valid nested filters wrapper still patches the URL and filters", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings")

    view
    |> element("#filter-form")
    |> render_change(%{
      "filters" => %{"owner" => "beta", "q" => "openssh-sftp-server", "suppressed" => "on"}
    })

    assert_patch(view, ~p"/findings?owner=beta&q=openssh-sftp-server&suppressed=1")
    assert has_element?(view, "#group-CVE-2026-60002")
  end

  test "a realistic flat filter-form event patches the URL with all four params", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings")

    view
    |> element("#filter-form")
    |> render_change(%{
      "owner" => "beta",
      "environment" => "prod",
      "q" => "openssh-sftp-server",
      "suppressed" => "true",
      "_target" => ["owner"]
    })

    assert_patch(
      view,
      ~p"/findings?environment=prod&owner=beta&q=openssh-sftp-server&suppressed=1"
    )

    assert has_element?(view, "#group-CVE-2026-60002")
  end

  test "finding ids are bounded by the actual bigint column, not int4", %{conn: conn} do
    image =
      Repo.one!(
        from i in Triage.Inventory.Image, where: i.repository == "registry.internal/app-a"
      )

    now = ~U[2026-09-09 06:00:00Z]

    high =
      Repo.insert!(%Finding{
        id: Integer.pow(2, 63) - 1,
        image_id: image.id,
        cve: "CVE-2025-9001",
        package_name: "edge-package",
        package_version: "1.0",
        severity: "LOW",
        first_seen: now,
        last_seen: now
      })

    # The true maximum bigint id (2^63 - 1, computed independently of the
    # runtime constant) renders normally.
    {:ok, view, _html} = live(conn, "/findings/#{high.id}")
    assert has_element?(view, "h1", "CVE-2025-9001")
    assert has_element?(view, "#placements")

    # One past the bigint maximum redirects before touching the database.
    result = live(conn, "/findings/#{Integer.pow(2, 63)}")

    assert {:error, {:live_redirect, %{to: to}}} = result
    assert URI.parse(to).path == "/findings"
  end
end
