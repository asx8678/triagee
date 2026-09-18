defmodule Triage.ReferenceCatalogTest do
  use ExUnit.Case, async: true
  alias Triage.{CveCatalog, ReferenceCatalog}

  setup_all do
    {:ok, catalog} = ReferenceCatalog.read()
    %{catalog: catalog}
  end

  test "95 unique real records exactly match their NVD receipts and metric bands", %{
    catalog: catalog
  } do
    assert {:ok, ^catalog} = ReferenceCatalog.validate(catalog)
    assert length(Enum.uniq_by(catalog["advisories"], & &1["cve"])) == 95

    assert Enum.frequencies_by(catalog["advisories"], & &1["severity"]) == %{
             "CRITICAL" => 30,
             "HIGH" => 40,
             "MEDIUM" => 20,
             "LOW" => 5
           }

    assert Enum.all?(
             catalog["advisories"],
             &String.starts_with?(&1["url"], "https://nvd.nist.gov/vuln/detail/CVE-")
           )

    refute Enum.any?(catalog["advisories"], &String.contains?(&1["description"], "Synthetic"))
  end

  test "normalization can be reproduced without network", %{catalog: catalog} do
    sources = Map.new(catalog["sources"], &{&1["url"], &1["body"]})

    assert {:ok, fetched} =
             CveCatalog.fetch(
               request: fn url -> {:ok, %{status: 200, body: Map.fetch!(sources, url)}} end,
               pause: fn _ -> :ok end
             )

    assert fetched["advisories"] == catalog["advisories"]
    assert {:ok, _} = ReferenceCatalog.validate(fetched)
  end

  test "errors, redirects, invalid JSON and incomplete buckets fail closed" do
    for response <- [
          {:error, :timeout},
          {:ok, %{status: 302, body: "redirect"}},
          {:ok, %{status: 200, body: "bad"}},
          {:ok, %{status: 200, body: "{\"vulnerabilities\":[]}"}}
        ] do
      assert {:error, {:bucket_unavailable, "CRITICAL"}} =
               CveCatalog.fetch(request: fn _ -> response end, pause: fn _ -> :ok end)
    end
  end

  test "invalid, duplicated, tampered and missing receipt data is rejected", %{catalog: catalog} do
    [first | tail] = catalog["advisories"]

    for bad <- [
          nil,
          %{},
          Map.put(catalog, "advisories", tail),
          Map.put(catalog, "advisories", [first, first | Enum.drop(tail, 1)]),
          Map.put(catalog, "advisories", [Map.put(first, "severity", "LOW") | tail]),
          Map.put(catalog, "advisories", [Map.put(first, "description", "invented") | tail]),
          Map.put(catalog, "sources", []),
          Map.put(catalog, "fetched_at", "not a date")
        ] do
      assert {:error, :invalid_catalog} = ReferenceCatalog.validate(bad)
    end

    [source | others] = catalog["sources"]

    assert {:error, :invalid_catalog} =
             ReferenceCatalog.validate(
               Map.put(catalog, "sources", [Map.put(source, "sha256", "bad") | others])
             )
  end

  test "malformed metrics and rejected CVEs are not normalized", %{catalog: catalog} do
    source = hd(catalog["sources"]) |> Map.fetch!("body") |> Jason.decode!()
    row = hd(source["vulnerabilities"])
    assert CveCatalog.normalize(put_in(row, ["cve", "vulnStatus"], "Rejected")) == nil

    assert CveCatalog.normalize(
             put_in(row, ["cve", "metrics"], %{"cvssMetricV31" => [%{"cvssData" => "bad"}]})
           ) == nil

    assert CveCatalog.normalize(%{"cve" => "bad"}) == nil
    assert CveCatalog.select(%{}, "HIGH", 40) == {:error, :invalid_entries}
  end

  test "failed catalogue replacement never overwrites a prior file", %{catalog: catalog} do
    path = Path.join(System.tmp_dir!(), "triage-catalog-test-#{Ecto.UUID.generate()}.json")
    on_exit(fn -> File.rm(path) end)
    File.write!(path, "keep me")

    assert {:error, :invalid_catalog} =
             ReferenceCatalog.write(path, Map.put(catalog, "advisories", []))

    assert File.read!(path) == "keep me"
    assert :ok = ReferenceCatalog.write(path, catalog)
    assert {:ok, ^catalog} = ReferenceCatalog.read(path)
  end
end
