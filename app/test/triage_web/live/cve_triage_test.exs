defmodule TriageWeb.CveTriageTest do
  use TriageWeb.LegacyUICase, async: false
  import Phoenix.LiveViewTest
  import Ecto.Query
  alias Triage.{Cases, Exceptions, Inventory, Repo}
  alias Triage.Cases.ReviewCase
  alias Triage.Exceptions.Decision

  setup do
    Triage.DataCase.reset_inventory!()
    :ok = Triage.LegacyFixtures.seed()
    finding = Repo.get_by!(Inventory.Finding, cve: "CVE-2025-1001", package_name: "busybox")

    placement =
      Repo.get_by!(Inventory.ImagePlacement,
        image_id: finding.image_id,
        owner: "alpha",
        environment: "prod-cluster-1"
      )

    %{finding: finding, placement: placement}
  end

  defp exception_attrs(kind \\ "accepted_risk") do
    %{
      kind: kind,
      reason: "Risk accepted until the next tested release",
      evidence: "Reachability evidence SEC-123",
      review_by: Date.to_iso8601(Date.add(Date.utc_today(), 30))
    }
  end

  defp open(finding) do
    {:ok, %{case: cse}} =
      Cases.open_case(finding.id, owner: "alpha", environment: "prod-cluster-1")

    cse
  end

  test "CVE click offers a direct scoped assessment without writing on GET", %{
    conn: conn,
    finding: finding,
    placement: placement
  } do
    {:ok, view, _} = live(conn, "/cves/CVE-2025-1001")
    assert has_element?(view, "#cve-triage")
    assert Repo.aggregate(ReviewCase, :count) == 0
    button = "#cve-open-triage-#{finding.id}-#{placement.id}"
    result = view |> element(button) |> render_click()
    {:ok, case_view, _} = follow_redirect(result, conn)
    assert has_element?(case_view, "#review-form select[name='review[applicability]']")
    assert has_element?(case_view, "#review-form select[name='review[priority]']")
    assert has_element?(case_view, "#review-form select[name='review[next_action]']")
    assert has_element?(case_view, "#review-form textarea[name='review[rationale]']")
    assert has_element?(case_view, "#case-exception-action")
    exception_navigation = case_view |> element("#case-exception-action") |> render_click()
    {:ok, exception_view, _} = follow_redirect(exception_navigation, conn)
    assert has_element?(exception_view, "#exception-form")

    exception_view
    |> form("#exception-form", exception: exception_attrs("not_affected"))
    |> render_submit()

    assert has_element?(exception_view, "#exception-status", "Not affected")
    cse = Repo.one!(ReviewCase)
    assert cse.owner == "alpha" and cse.environment == "prod-cluster-1"
    assert cse.finding_id == finding.id
  end

  test "tampered targets and malformed scope never open cases", %{conn: conn} do
    {:ok, view, _} = live(conn, "/cves/CVE-2025-1001?owner=alpha&environment=prod-cluster-1")
    render_click(view, "open_triage", %{"target" => "forged", "owner" => "beta"})
    assert has_element?(view, "#cve-triage-error")
    assert Repo.aggregate(ReviewCase, :count) == 0
    {:ok, invalid, _} = live(conn, "/cves/CVE-2025-1001?owner[]=alpha")
    refute has_element?(invalid, "#cve-triage")
    render_click(invalid, "open_triage", %{"target" => "1-1"})
    assert Repo.aggregate(ReviewCase, :count) == 0
  end

  test "scope retires between display and click; opening fails closed", %{
    conn: conn,
    finding: finding,
    placement: placement
  } do
    {:ok, view, _} = live(conn, "/cves/CVE-2025-1001?owner=alpha&environment=prod-cluster-1")

    Repo.update_all(from(p in Inventory.ImagePlacement, where: p.id == ^placement.id),
      set: [active: false]
    )

    view |> element("#cve-open-triage-#{finding.id}-#{placement.id}") |> render_click()
    assert has_element?(view, "#cve-triage-error")
    assert Repo.aggregate(ReviewCase, :count) == 0
  end

  test "save, reload, show on CVE/queue/finding, and revoke a scoped exception", %{
    conn: conn,
    finding: finding,
    placement: placement
  } do
    cse = open(finding)
    {:ok, view, _} = live(conn, "/cases/#{cse.id}/exception")
    assert has_element?(view, "#exception-form")
    assert Repo.aggregate(Decision, :count) == 0
    view |> form("#exception-form", exception: exception_attrs()) |> render_submit()
    assert has_element?(view, "#exception-status", "Temporarily suppressed locally")
    assert has_element?(view, "#exception-history-rows li", "local-operator")
    refute Repo.get!(Inventory.Finding, finding.id).suppressed

    {:ok, advisory, _} = live(conn, "/cves/CVE-2025-1001")

    assert has_element?(
             advisory,
             "#cve-triage-status-#{finding.id}-#{placement.id}",
             "Temporarily suppressed locally"
           )

    {:ok, queue, _} = live(conn, "/cases")

    assert has_element?(
             queue,
             "#case-exception-status-#{cse.id}",
             "Temporarily suppressed locally"
           )

    {:ok, occurrence, _} =
      live(conn, "/findings/#{finding.id}?owner=alpha&environment=prod-cluster-1")

    assert has_element?(occurrence, "#finding-exception-status", "Temporarily suppressed locally")
    {:ok, beta, _} = live(conn, "/findings/#{finding.id}?owner=beta&environment=prod-cluster-1")
    assert has_element?(beta, "#finding-exception-status", "Action required")

    {:ok, reloaded, _} = live(conn, "/cases/#{cse.id}/exception")
    assert has_element?(reloaded, "#exception-status", "Temporarily suppressed locally")

    reloaded
    |> form("#exception-form",
      exception: %{kind: "reopened", reason: "New evidence requires investigation"}
    )
    |> render_submit()

    assert has_element?(reloaded, "#exception-status", "reopened")
    assert Repo.aggregate(Decision, :count) == 2
  end

  test "not affected requires evidence and invalid fields preserve the draft", %{
    conn: conn,
    finding: finding
  } do
    cse = open(finding)
    {:ok, view, _} = live(conn, "/cases/#{cse.id}/exception")

    view
    |> form("#exception-form", exception: Map.put(exception_attrs("not_affected"), :evidence, ""))
    |> render_submit()

    assert has_element?(view, "textarea[name='exception[reason]']", "Risk accepted")
    assert Repo.aggregate(Decision, :count) == 0
    view |> form("#exception-form", exception: exception_attrs("not_affected")) |> render_submit()
    assert has_element?(view, "#exception-status", "Not affected")
  end

  test "forged binding is refused and reconnect recovery requires explicit rebind", %{
    conn: conn,
    finding: finding
  } do
    cse = open(finding)
    {:ok, view, _} = live(conn, "/cases/#{cse.id}/exception")

    render_submit(view, "save", %{
      "exception" => %{"kind" => "reopened", "reason" => "bad binding"},
      "meta" => %{"case_id" => "999"}
    })

    assert has_element?(view, "#exception-error")
    assert has_element?(view, "#exception-save[disabled]")
    assert Exceptions.history(cse.id) == []

    render_change(view, "recover", %{
      "exception" => %{"kind" => "reopened", "reason" => "Recovered draft"}
    })

    assert has_element?(view, "#exception-save[disabled]")
    view |> element("#exception-rebind") |> render_click()
    refute has_element?(view, "#exception-save[disabled]")
    view |> form("#exception-form") |> render_submit()
    assert has_element?(view, "#exception-status", "reopened")
  end

  test "stale tabs preserve reason and cannot replace a newer decision", %{
    conn: conn,
    finding: finding
  } do
    cse = open(finding)
    {:ok, first, _} = live(conn, "/cases/#{cse.id}/exception")
    {:ok, second, _} = live(conn, "/cases/#{cse.id}/exception")
    first |> form("#exception-form", exception: exception_attrs()) |> render_submit()

    second
    |> form("#exception-form", exception: exception_attrs("not_affected"))
    |> render_submit()

    assert has_element?(second, "#exception-error", "Another decision")
    assert has_element?(second, "#exception-save[disabled]")
    assert length(Exceptions.history(cse.id)) == 1
  end
end
