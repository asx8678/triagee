defmodule Triage.ReferenceDataTest do
  use Triage.DataCase, async: false
  alias Triage.{Cases, Exceptions, Inventory, ReferenceCatalog, ReferenceData, Repo, Seeds}
  alias Triage.Cases.{EvidenceSnapshot, Review, ReviewCase}

  setup do
    reset_inventory!()
    :ok = Seeds.seed()
    {:ok, catalog} = ReferenceCatalog.read()
    %{catalog: catalog}
  end

  test "replaces active demo rows with 30/40/20/5 real CVEs and is a repeat no-op", %{
    catalog: catalog
  } do
    assert {:ok, %{retired_placements: 4}} = ReferenceData.install(catalog)

    assert Inventory.cve_summary_counts() == %{
             total: 95,
             critical: 30,
             high: 40,
             medium: 20,
             low: 5
           }

    assert Inventory.summary_counts() == %{open: 95, suppressed: 0}
    assert ReferenceData.active_counts() == catalog["counts"]
    assert Inventory.count_groups() == 95
    before = fingerprint()
    assert {:ok, %{retired_placements: 0}} = ReferenceData.install(catalog)
    assert fingerprint() == before
    assert {:error, :not_found} = Inventory.fetch_cve("CVE-2024-2002")
  end

  test "reviews, frozen evidence and exceptions survive; unrelated imported data stays active", %{
    catalog: catalog
  } do
    fake = Repo.get_by!(Inventory.Finding, cve: "CVE-2025-1001", package_name: "busybox")

    {:ok, %{case: cse, snapshot: snapshot}} =
      Cases.open_case(fake.id, owner: "alpha", environment: "prod-cluster-1")

    {:ok, %{case: reviewed}} =
      Cases.submit_review(cse.id, cse.revision, snapshot.id, Ecto.UUID.generate(), %{
        "applicability" => "unknown",
        "priority" => "normal_review",
        "next_action" => "investigation",
        "rationale" => "Keep historical assessment"
      })

    {:ok, _} =
      Exceptions.submit(reviewed.id, reviewed.revision, snapshot.id, Ecto.UUID.generate(), %{
        "kind" => "accepted_risk",
        "reason" => "Historical exception",
        "review_by" => Date.to_iso8601(Date.add(Date.utc_today(), 7))
      })

    history = {Repo.all(EvidenceSnapshot), Repo.all(Review), Exceptions.history(cse.id)}
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {:ok, image} =
      Inventory.upsert_image(
        %{digest: "sha256:" <> String.duplicate("d", 64), repository: "actual/import", tag: "1"},
        now
      )

    {:ok, placement} =
      Inventory.upsert_placement(
        image,
        %{owner: "real-team", environment: "real-env", namespace: "real"},
        now
      )

    {:ok, real} =
      Inventory.upsert_finding(
        image,
        %{
          cve: "CVE-2025-1001",
          package_name: "real-package",
          package_version: "1",
          severity: "HIGH"
        },
        now
      )

    assert {:ok, _} = ReferenceData.install(catalog)
    assert {Repo.all(EvidenceSnapshot), Repo.all(Review), Exceptions.history(cse.id)} == history
    assert Repo.get!(Inventory.Finding, real.id) == real
    assert Repo.get!(Inventory.ImagePlacement, placement.id) == placement
    assert Repo.get!(Inventory.Finding, fake.id).resolved_at == nil
    assert {:ok, %{evidence_status: :source_out_of_scope}} = Cases.get_case(cse.id)
    assert ReferenceData.active_counts() == catalog["counts"]
    assert Repo.aggregate(ReviewCase, :count) == 1
  end

  test "unknown rows on a legacy digest fail atomically rather than retiring unrelated inventory",
       %{catalog: catalog} do
    image = Repo.get_by!(Inventory.Image, repository: "registry.internal/app-a")
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {:ok, _} =
      Inventory.upsert_finding(
        image,
        %{
          cve: "CVE-2025-99999",
          package_name: "unrelated",
          package_version: "1",
          severity: "HIGH"
        },
        now
      )

    before = fingerprint()
    assert {:error, :unrelated_findings_on_legacy_image} = ReferenceData.install(catalog)
    assert fingerprint() == before
  end

  test "invalid catalogue and preview write nothing", %{catalog: catalog} do
    before = fingerprint()
    assert {:ok, %{history_deleted: false}} = ReferenceData.preview(catalog)
    assert {:error, :invalid_catalog} = ReferenceData.install(Map.put(catalog, "advisories", []))
    assert fingerprint() == before
  end

  test "reference records do not fabricate deployed versions, fixes or production evidence", %{
    catalog: catalog
  } do
    {:ok, result} = ReferenceData.install(catalog)

    finding =
      Repo.one!(
        from f in Inventory.Finding,
          where: f.image_id == ^result.image_id,
          order_by: f.id,
          limit: 1
      )

    assert finding.package_version == "Not assessed (public reference)"
    assert finding.fix == nil
    assert finding.description =~ "CVSS 3.1:"
    assert finding.url =~ "https://nvd.nist.gov/vuln/detail/CVE-"

    {:ok, %{snapshot: snapshot}} =
      Cases.open_case(finding.id,
        owner: ReferenceData.owner(),
        environment: ReferenceData.environment()
      )

    assert snapshot.payload["source"] == "nvd_public_reference"
    assert snapshot.payload["coverage"]["kind"] == "public_reference_only"
    assert Repo.aggregate(Triage.Exposure.Evidence, :count) == 3
  end

  test "altered reference occurrences fail without overwriting operator data", %{catalog: catalog} do
    {:ok, result} = ReferenceData.install(catalog)

    finding =
      Repo.one!(
        from f in Inventory.Finding,
          where: f.image_id == ^result.image_id,
          order_by: f.id,
          limit: 1
      )

    Repo.update!(
      Inventory.Finding.changeset(finding, %{
        resolved_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })
    )

    before = fingerprint()
    assert {:error, :modified_reference_finding} = ReferenceData.install(catalog)
    assert fingerprint() == before
  end

  test "extra reference-like data cannot silently break the requested histogram", %{
    catalog: catalog
  } do
    {:ok, result} = ReferenceData.install(catalog)

    finding =
      Repo.one!(
        from f in Inventory.Finding,
          where: f.image_id == ^result.image_id,
          order_by: f.id,
          limit: 1
      )

    Repo.insert!(
      Inventory.Finding.changeset(%Inventory.Finding{}, %{
        image_id: result.image_id,
        cve: "CVE-2025-9999999",
        package_name: "operator addition",
        package_version: finding.package_version,
        description: finding.description,
        severity: "HIGH",
        first_seen: finding.first_seen,
        last_seen: finding.last_seen
      })
    )

    before = fingerprint()
    assert {:error, :modified_reference_finding} = ReferenceData.install(catalog)
    assert fingerprint() == before
  end

  defp fingerprint do
    for schema <- [
          Inventory.Image,
          Inventory.ImagePlacement,
          Inventory.Finding,
          Inventory.FindingEvent,
          Triage.Intel.NewsItem
        ] do
      {schema, Repo.all(from r in schema, order_by: r.id)}
    end
  end
end
