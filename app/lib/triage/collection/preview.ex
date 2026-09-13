defmodule Triage.Collection.Preview do
  @moduledoc """
  Optional snapshot preview for the historical importer.

  There is no valid snapshot builder in this PR6 scope. `to_snapshot/1` always
  returns a controlled historical-provenance blocker and never a snapshot, so a
  report (including one with a forged `historical_provenance` value) cannot be
  presented as an honest historical snapshot. The remaining blockers still
  describe every field the importer would drop.

  Blockers are returned for any UNKNOWN/NEGLIGIBLE/unsupported severity, any
  missing required identity, any metadata that cannot be represented losslessly,
  and any missing historical provenance. UNKNOWN is never mapped to LOW and is
  never dropped; `first_seen`/`last_seen` are never invented.
  """

  alias Triage.Collection.Report

  @supported ~w(CRITICAL HIGH MEDIUM LOW)
  @dropped_finding_fields [
    {:base_severity, "base_severity"},
    {:source, "source"},
    {:package_type, "package_type"},
    {:purl, "purl"},
    {:package_cpe, "package_cpe"},
    {:attributed_on, "attributed_on"}
  ]
  @dropped_image_fields [{:usage, "usage"}, {:sbom_tool, "sbom_tool"}, {:status, "status"}]

  @no_snapshot_blocker "$: no controller-verified historical provenance; measurements are not snapshots"

  @doc """
  Always returns `{:error, blockers}` including a controlled historical-provenance
  blocker. No snapshot is ever built in this scope.
  """
  def to_snapshot(%Report{} = report) do
    {:error, Enum.uniq([@no_snapshot_blocker | blockers(report)])}
  end

  def to_snapshot(_other), do: {:error, ["$: not a collection report"]}

  @doc "Returns every blocker that prevents an honest, lossless snapshot."
  def blockers(%Report{} = report) do
    completeness = if Report.complete?(report), do: [], else: ["$: report is incomplete"]

    provenance = provenance_blockers(report)

    findings = (report.findings || []) ++ (report.suppressed || [])

    finding_blockers =
      Enum.flat_map(findings, fn finding ->
        missing_identity(finding) ++ severity_blocker(finding) ++ metadata_blockers(finding)
      end)

    image_blockers =
      Enum.flat_map(report.images || [], fn image ->
        Enum.flat_map(@dropped_image_fields, fn {field, label} ->
          value = Map.get(image, field)

          if is_nil(value) do
            []
          else
            ["$: image metadata #{label} is unsupported and would be dropped"]
          end
        end)
      end)

    Enum.uniq(completeness ++ provenance ++ finding_blockers ++ image_blockers)
  end

  defp missing_identity(finding) do
    if is_nil(finding.cve) or is_nil(finding.package_name) or is_nil(finding.package_version) do
      ["$: finding with missing identity cannot be previewed"]
    else
      []
    end
  end

  defp severity_blocker(finding) do
    if finding.severity in @supported do
      []
    else
      [
        "$: severity #{finding.severity || "nil"} for #{finding.cve} is preserved but not losslessly importable"
      ]
    end
  end

  defp metadata_blockers(finding) do
    field_blockers =
      Enum.flat_map(@dropped_finding_fields, fn {field, label} ->
        value = Map.get(finding, field)

        if is_nil(value) do
          []
        else
          ["$: #{label} #{value} for #{finding.cve} is unsupported metadata"]
        end
      end)

    metadata =
      case Map.get(finding, :metadata) do
        value when is_map(value) and map_size(value) > 0 ->
          ["$: unrepresentable raw metadata for #{finding.cve} would be dropped"]

        _other ->
          []
      end

    field_blockers ++ metadata
  end

  defp provenance_blockers(%Report{historical_provenance: nil}) do
    ["$: no historical first_seen/last_seen available; measurements are not snapshots"]
  end

  defp provenance_blockers(%Report{historical_provenance: provenance}) when is_map(provenance) do
    missing =
      Enum.filter(["first_seen", "last_seen"], fn key ->
        not is_binary(Map.get(provenance, key))
      end)

    if missing == [] do
      []
    else
      ["$: historical provenance is missing #{Enum.join(missing, ", ")}"]
    end
  end

  defp provenance_blockers(_report) do
    ["$: historical provenance is malformed; measurements are not snapshots"]
  end
end
