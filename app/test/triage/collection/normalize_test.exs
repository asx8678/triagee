defmodule Triage.Collection.NormalizeTest do
  use ExUnit.Case, async: true

  alias Triage.Collection.{Config, Normalize}

  test "reversed accumulators preserve image, finding, suppression and warning order" do
    ctx = context()
    first = Normalize.build(%{ctx | inventory: Map.take(ctx.inventory, ["a"])})
    second = Normalize.build(%{ctx | inventory: Map.take(ctx.inventory, ["b"])})
    report = Normalize.build(ctx)

    assert Enum.map(report.images, & &1.digest) == ["a", "b"]
    assert report.images == first.images ++ second.images
    assert report.findings == first.findings ++ second.findings
    assert report.suppressed == first.suppressed ++ second.suppressed
    assert report.warnings == first.warnings ++ second.warnings
    assert Enum.map(report.findings, & &1.cve) == ["CVE-a-open", "CVE-b-open"]
    assert Enum.map(report.suppressed, & &1.cve) == ["CVE-a-suppressed", "CVE-b-suppressed"]
    assert Enum.map(report.warnings, &String.first/1) == ["a", "b"]
    assert report.failures == []
  end

  test "crawl diagnostics precede normalization diagnostics in their original order" do
    ctx = %{
      context()
      | warnings: ["warning two", "warning one"],
        failures: ["failure two", "failure one"]
    }

    complete = Normalize.build(ctx)
    assert Enum.take(complete.warnings, 2) == ["warning one", "warning two"]
    assert complete.failures == ["failure one", "failure two"]

    incomplete = Normalize.build(%{ctx | details: %{}})

    assert incomplete.failures == [
             "failure one",
             "failure two",
             "a: detail missing; completeness not implied",
             "b: detail missing; completeness not implied"
           ]

    assert incomplete.incomplete
  end

  test "record limits retain the ordered prefix and an explicit failure" do
    ctx = context()
    report = Normalize.build(%{ctx | config: %{ctx.config | max_records: 1}})
    assert Enum.map(report.images, & &1.digest) == ["a"]
    assert report.findings == []
    assert report.suppressed == []
    assert report.incomplete
    assert List.last(report.failures) =~ "remaining records not normalized"
  end

  defp context do
    {:ok, config} = Config.new(endpoint: "http://127.0.0.1", environment: "test")

    %{
      config: config,
      scope: "full",
      status_marker: nil,
      owners: ["team"],
      requested_owners: nil,
      warnings: [],
      failures: [],
      requests: 0,
      duration_ms: 0,
      inventory: Map.new(["b", "a"], &{&1, entry(&1)}),
      details: Map.new(["b", "a"], &{&1, detail(&1)})
    }
  end

  defp entry(digest) do
    %{
      digest: digest,
      owners: MapSet.new(["team"]),
      api_ids: MapSet.new([digest]),
      placements: MapSet.new([%{owner: "team", namespace: "ns"}]),
      image: %{"metrics" => %{"vulnerabilities" => 3, "vulnerabilitiesSuppressed" => 1}}
    }
  end

  defp detail(digest) do
    open = finding("CVE-#{digest}-open")

    %{
      "vulnerabilities" => [open, open],
      "excludedVulnerabilities" => [finding("CVE-#{digest}-suppressed")]
    }
  end

  defp finding(cve) do
    %{"vuln" => cve, "packageName" => "package", "packageVersion" => "1", "severity" => "HIGH"}
  end
end
