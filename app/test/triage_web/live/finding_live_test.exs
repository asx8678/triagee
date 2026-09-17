defmodule TriageWeb.FindingLiveTest do
  use TriageWeb.ConnCase, async: true

  import Ecto.Query
  alias Triage.Inventory.Finding
  alias Triage.Repo
  alias Triage.Seeds

  setup do
    :ok = Seeds.seed()
    :ok
  end

  test "index lists grouped advisories", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings")

    assert has_element?(view, "#groups > tr")
    refute has_element?(view, "#groups", "CVE-2026-61625")
  end

  test "index honours the team filter from the URL", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings?owner=alpha")

    assert has_element?(view, "#groups > tr")
    # beta-only suppressed advisory stays hidden without include_suppressed
    refute has_element?(view, "#groups", "CVE-2026-48931")
  end

  test "unknown team shows a visible notice and an empty table", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings?owner=no-such-team")

    assert has_element?(view, "p", "Unknown team")
    assert has_element?(view, "p", "No open findings")
  end

  test "filter event patches the URL and keeps results", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/findings")

    view |> element("form") |> render_change(%{"owner" => "beta"})

    assert_patch(view, ~p"/findings?owner=beta")
    assert has_element?(view, "#groups > tr")
  end

  test "detail renders hostile third-party text as text, never markup", %{conn: conn} do
    finding =
      Repo.one!(
        from f in Finding, where: f.cve == "CVE-2026-60002" and f.package_name == "openssh-client"
      )

    Repo.update_all(from(f in Finding, where: f.id == ^finding.id),
      set: [description: "<script>alert(1)</script> never as markup"]
    )

    {:ok, view, html} = live(conn, ~p"/findings/#{finding.id}")

    assert has_element?(view, "#placements")
    refute html =~ "<script>alert"
    assert html =~ "&lt;script&gt;alert"
  end

  test "detail labels suppressed findings", %{conn: conn} do
    suppressed = Repo.one!(from f in Finding, where: f.cve == "CVE-2026-48931")

    {:ok, view, _html} = live(conn, ~p"/findings/#{suppressed.id}")

    assert has_element?(view, "dd", "Suppressed — not mitigation evidence")
  end

  test "detail labels unknown deployment context", %{conn: conn} do
    unknown_ctx =
      Repo.one!(
        from f in Finding, where: f.cve == "CVE-2026-57236" and f.package_version == "1.19.0"
      )

    {:ok, view, _html} = live(conn, ~p"/findings/#{unknown_ctx.id}")

    assert has_element?(view, "#placements", "deployment context unknown")
  end

  test "detail preserves the selected team scope in its back link", %{conn: conn} do
    finding = Repo.one!(from f in Finding, where: f.cve == "CVE-2026-53492")

    {:ok, view, _html} = live(conn, ~p"/findings/#{finding.id}?owner=alpha")

    assert has_element?(view, "a[href=\"/findings?owner=alpha\"]")
  end

  test "detail applies the selected team to placements and related occurrences", %{conn: conn} do
    finding =
      Repo.one!(
        from f in Finding, where: f.cve == "CVE-2026-60002" and f.package_name == "openssh-client"
      )

    {:ok, view, _html} =
      live(conn, ~p"/findings/#{finding.id}?owner=alpha&environment=prod")

    assert has_element?(view, "#placements", "alpha")
    refute has_element?(view, "#placements", "beta")
    assert has_element?(view, "a", "openssh-client-common")
    refute has_element?(view, "a", "openssh-sftp-server 1:10.2p1")
  end

  test "detail rejects a finding outside the selected team", %{conn: conn} do
    finding =
      Repo.one!(
        from f in Finding,
          where: f.cve == "CVE-2026-60002" and f.package_name == "openssh-sftp-server"
      )

    result = live(conn, ~p"/findings/#{finding.id}?owner=alpha")

    assert {:error, {:live_redirect, %{to: to}}} = result
    uri = URI.parse(to)
    assert uri.path == "/findings"
    assert URI.decode_query(uri.query || "")["owner"] == "alpha"

    {:ok, _view, html} = follow_redirect(result, conn)
    assert html =~ "outside the selected team"
  end

  test "malformed finding ids return safely to inventory", %{conn: conn} do
    for id <- ["not-a-number", "1suffix", "-1", "0", String.duplicate("9", 100)] do
      result = live(conn, ~p"/findings/#{id}")

      assert {:error, {:live_redirect, %{to: to}}} = result
      assert URI.parse(to).path == "/findings"
    end
  end

  test "unknown finding id redirects to the inventory with a flash", %{conn: conn} do
    result = live(conn, ~p"/findings/99999999")

    assert {:error, {:live_redirect, %{to: to}}} = result
    assert to == ~p"/findings"

    {:ok, _view, html} = follow_redirect(result, conn)
    assert html =~ "Finding not found"
  end

  test "inventory routes are registered" do
    paths = Phoenix.Router.routes(TriageWeb.Router) |> Enum.map(& &1.path)

    assert "/findings" in paths
    assert "/findings/:id" in paths
  end
end
