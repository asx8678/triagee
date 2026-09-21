defmodule TriageWeb.ReferenceDataLiveTest do
  use TriageWeb.LegacyUICase, async: false
  import Phoenix.LiveViewTest
  import Ecto.Query
  alias Triage.{Inventory, ReferenceCatalog, ReferenceData, Repo}

  setup do
    Triage.DataCase.reset_inventory!()
    :ok = Triage.LegacyFixtures.seed()
    {:ok, catalog} = ReferenceCatalog.read()
    {:ok, result} = ReferenceData.install(catalog)

    finding =
      Repo.one!(
        from f in Inventory.Finding,
          where: f.image_id == ^result.image_id,
          order_by: f.id,
          limit: 1
      )

    placement = Repo.get_by!(Inventory.ImagePlacement, image_id: result.image_id)
    %{finding: finding, placement: placement}
  end

  test "real source links, provenance and assessment flow are visible", %{
    conn: conn,
    finding: finding,
    placement: placement
  } do
    {:ok, view, _} = live(conn, "/cves/#{finding.cve}")
    assert has_element?(view, "#cve-reference-source", "not a scanner finding")
    assert has_element?(view, "#cve-reference-source-details", "CVSS")
    assert has_element?(view, "#cve-reference-source-link[href='#{finding.url}']")
    assert Repo.aggregate(Triage.Cases.ReviewCase, :count) == 0
    result = view |> element("#cve-open-triage-#{finding.id}-#{placement.id}") |> render_click()
    {:ok, review, _} = follow_redirect(result, conn)
    assert has_element?(review, "#review-form")
    assert has_element?(review, "#case-exception-action")
    assert has_element?(review, "#evidence-limitations-details", "Real NVD advisory data")
  end

  test "inventory counts, severity filters and finding detail use the real catalogue", %{
    conn: conn,
    finding: finding
  } do
    {:ok, view, _} = live(conn, "/findings")
    assert has_element?(view, "#open-occurrence-count", "95")
    assert has_element?(view, "#reference-inventory-help", "real NVD CVEs")

    for {severity, count} <- [{"CRITICAL", 30}, {"HIGH", 40}, {"MEDIUM", 20}, {"LOW", 5}] do
      assert Inventory.count_groups(severity: severity) == count
      {:ok, filtered, _} = live(conn, "/findings?severity=#{severity}")
      assert has_element?(filtered, "#findings-summary", to_string(count))
    end

    {:ok, detail, _} = live(conn, "/findings/#{finding.id}")
    assert has_element?(detail, "#finding-reference-source-link[href='#{finding.url}']")
    assert has_element?(detail, "#finding-summary", "NVD CVSS severity")
  end
end
