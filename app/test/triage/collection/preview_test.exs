defmodule Triage.Collection.PreviewTest do
  use ExUnit.Case, async: true

  alias Triage.Collection.{Preview, Report}

  defp report(findings, suppressed \\ []) do
    %Report{
      scope: "full",
      environment: "prod",
      engine: "Grype",
      status_marker: nil,
      owners: ["team-a"],
      images: [
        %{
          digest: "digest-a",
          api_ids: [],
          owners: ["team-a"],
          placements: [%{namespace: "ns", owner: "team-a", environment: "prod"}],
          repository: "app",
          tag: "1",
          description: nil,
          usage: nil,
          sbom_tool: nil,
          status: nil
        }
      ],
      findings: findings,
      suppressed: suppressed,
      warnings: [],
      failures: [],
      requests: 1,
      duration_ms: 1,
      raw: %{},
      blockers: []
    }
  end

  defp finding(severity, opts \\ []) do
    %{
      digest: "digest-a",
      cve: Keyword.get(opts, :cve, "CVE-1"),
      package_name: "busybox",
      package_version: "1.0",
      severity: severity,
      base_severity: Keyword.get(opts, :base_severity, nil),
      source: Keyword.get(opts, :source, nil),
      package_type: nil,
      purl: nil,
      package_cpe: nil,
      fix: nil,
      url: nil,
      description: nil,
      attributed_on: nil,
      metadata: nil,
      suppressed: Keyword.get(opts, :suppressed, false),
      identity_complete?: true
    }
  end

  test "measurements are never presented as a snapshot" do
    assert {:error, blockers} = Preview.to_snapshot(report([finding("LOW")]))
    assert Enum.any?(blockers, &String.contains?(&1, "first_seen"))
  end

  test "UNKNOWN and NEGLIGIBLE are blockers, never mapped to LOW" do
    assert {:error, blockers} = Preview.to_snapshot(report([finding("UNKNOWN")]))
    assert Enum.any?(blockers, &String.contains?(&1, "UNKNOWN"))

    assert {:error, blockers} = Preview.to_snapshot(report([finding("NEGLIGIBLE")]))
    assert Enum.any?(blockers, &String.contains?(&1, "NEGLIGIBLE"))
  end

  test "a base severity that cannot be represented is a blocker" do
    assert {:error, blockers} =
             Preview.to_snapshot(report([finding("HIGH", base_severity: "CRITICAL")]))

    assert Enum.any?(blockers, &String.contains?(&1, "base_severity"))
  end

  test "an incomplete report is never previewable" do
    incomplete = %{report([finding("LOW")]) | failures: ["missing"]}
    assert {:error, blockers} = Preview.to_snapshot(incomplete)
    assert Enum.any?(blockers, &String.contains?(&1, "incomplete"))
  end

  test "there is no public lossless-success builder that bypasses the guards" do
    Code.ensure_loaded!(Preview)
    refute function_exported?(Preview, :build_snapshot, 1)

    # Even a fully supported, complete report is refused without historical provenance.
    honest = report([finding("LOW")])
    assert honest.failures == []
    assert {:error, blockers} = Preview.to_snapshot(honest)
    assert Enum.any?(blockers, &String.contains?(&1, "first_seen"))
  end

  test "any unsupported metadata the importer would drop is a blocker" do
    assert {:error, blockers} =
             Preview.to_snapshot(report([finding("HIGH", source: "nvd:cpe")]))

    assert Enum.any?(blockers, &String.contains?(&1, "unsupported metadata"))
  end

  test "actionable? is false without historical provenance or when incomplete" do
    honest = report([finding("LOW")])
    refute Report.actionable?(honest)

    with_provenance = %{
      honest
      | historical_provenance: %{
          "first_seen" => "2026-01-01T00:00:00Z",
          "last_seen" => "2026-01-01T00:00:00Z"
        }
    }

    assert Report.complete?(with_provenance)
    refute Report.actionable?(with_provenance)

    incomplete = %{with_provenance | failures: ["missing"], incomplete: true}
    refute Report.actionable?(incomplete)
  end
end
