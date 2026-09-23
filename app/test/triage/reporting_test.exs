defmodule Triage.ReportingTest do
  use Triage.DataCase, async: false

  import Triage.Fixtures
  alias Triage.{Reporting, Repo, Workspace}
  alias Triage.Decisions.Decision

  @now ~U[2026-09-23 12:00:00Z]
  @all %{token_id: 1, user_id: 1, label: "test", grants: :all}

  setup do
    reset_inventory!()

    image = image!("reporting-partial")
    prod = placement!(image, "alpha", "prod")
    stage = placement!(image, "alpha", "staging")
    finding = finding!(image, "CVE-2099-8101", severity: "HIGH", fix: "2.0.0")

    finding!(image, finding.cve,
      severity: "LOW",
      package_name: "transitive",
      package_version: "0.9"
    )

    other_image = image!("reporting-other")
    other = placement!(other_image, "beta", "prod")
    finding!(other_image, "CVE-2099-8102", severity: "CRITICAL")

    retired_image = image!("reporting-retired")
    placement!(retired_image, "alpha", "prod", false)
    finding!(retired_image, "CVE-2099-8103", severity: "HIGH")

    accept!(finding.cve, prod.id, 5)

    %{cve: finding.cve, prod: prod, stage: stage, other: other}
  end

  test "summary and CVE rows distinguish CVEs, targets and partial whitelisting", c do
    assert {:ok, summary} = Reporting.fetch(:summary, %{}, @all, @now)
    data = summary["data"]
    assert data["active_cves"] == 2
    assert data["active_targets"] == 3
    assert data["whitelisted_targets"] == 1
    assert data["partially_whitelisted_cves"] == 1
    assert data["fully_whitelisted_cves"] == 0
    assert data["needs_decision_cves"] == 2
    assert data["expiring_whitelist_targets"] == 1
    assert summary["meta"]["source_coverage"] == "unknown"
    assert summary["meta"]["consistency"] == "per_response"

    assert {:ok, page} =
             Reporting.fetch(:cves, %{"whitelist_coverage" => "partial"}, @all, @now)

    assert [%{"cve" => cve, "active_targets" => 2, "whitelisted_targets" => 1}] =
             page["data"]

    assert cve == c.cve
  end

  test "summary caps high-cardinality dimensions and reports truncation" do
    image = image!("reporting-many-teams")

    for index <- 1..101 do
      placement!(
        image,
        "bulk-team-#{String.pad_leading(Integer.to_string(index), 3, "0")}",
        "prod"
      )
    end

    finding!(image, "CVE-2099-8199", severity: "MEDIUM")

    assert {:ok, summary} = Reporting.fetch(:summary, %{}, @all, @now)
    assert length(summary["data"]["by_team"]) == 100

    assert summary["data"]["breakdown_truncated"] == %{
             "teams" => true,
             "environments" => false
           }
  end

  test "CVE search and severity select CVEs without shrinking coverage denominators", c do
    sibling_image = image!("reporting-filtered-sibling")
    sibling = placement!(sibling_image, "alpha", "qa")

    finding!(sibling_image, c.cve,
      severity: "LOW",
      package_name: "qa-only-package",
      package_version: "1.0"
    )

    for params <- [%{"q" => "qa-only-package"}, %{"severity" => "LOW"}] do
      assert {:ok, page} = Reporting.fetch(:cves, params, @all, @now)

      assert [
               %{
                 "cve" => cve,
                 "active_targets" => 3,
                 "whitelisted_targets" => 1,
                 "whitelist_coverage" => "partial"
               }
             ] = page["data"]

      assert cve == c.cve
    end

    assert {:ok, summary} =
             Reporting.fetch(:summary, %{"q" => "qa-only-package"}, @all, @now)

    assert summary["data"]["active_cves"] == 1
    assert summary["data"]["active_targets"] == 3
    assert summary["data"]["partially_whitelisted_cves"] == 1

    assert {:ok, targets} =
             Reporting.fetch(:targets, %{"q" => "qa-only-package"}, @all, @now)

    assert [%{"placement_id" => id}] = targets["data"]
    assert id == Integer.to_string(sibling.id)
  end

  test "target output uses effective evidence-bound state and bounded signed cursors", c do
    assert {:ok, first} =
             Reporting.fetch(:targets, %{"limit" => "1", "active" => "true"}, @all, @now)

    assert length(first["data"]) == 1
    assert is_binary(first["pagination"]["next_cursor"])

    assert {:ok, second} =
             Reporting.fetch(
               :targets,
               %{
                 "limit" => "1",
                 "active" => "true",
                 "cursor" => first["pagination"]["next_cursor"]
               },
               @all,
               @now
             )

    refute hd(first["data"])["placement_id"] == hd(second["data"])["placement_id"] and
             hd(first["data"])["cve"] == hd(second["data"])["cve"]

    assert {:error, %{code: "invalid_cursor"}} =
             Reporting.fetch(
               :targets,
               %{"limit" => "2", "cursor" => first["pagination"]["next_cursor"]},
               @all,
               @now
             )

    assert {:ok, whitelisted} =
             Reporting.fetch(:targets, %{"whitelisted" => "true"}, @all, @now)

    assert [%{"cve" => cve, "placement_id" => id, "whitelisted" => true} = row] =
             whitelisted["data"]

    assert cve == c.cve
    assert id == Integer.to_string(c.prod.id)
    assert row["coverage_state"] == "covered"
    assert row["detail_path"] =~ "focus_target=#{c.prod.id}"
    refute Map.has_key?(row, "reason")
    refute Map.has_key?(row, "actor")
  end

  test "exact grants apply to rows, aggregates, options and package detail", c do
    access = %{token_id: 2, user_id: 1, label: "alpha prod", grants: [{"alpha", "prod"}]}

    assert {:ok, summary} = Reporting.fetch(:summary, %{}, access, @now)
    assert summary["data"]["active_targets"] == 1
    assert summary["data"]["active_cves"] == 1

    assert {:ok, targets} = Reporting.fetch(:targets, %{}, access, @now)
    assert [%{"placement_id" => id}] = targets["data"]
    assert id == Integer.to_string(c.prod.id)

    assert {:error, %{status: 403}} =
             Reporting.fetch(
               :targets,
               %{"team" => "alpha", "environment" => "staging"},
               access,
               @now
             )

    assert {:ok, options} = Reporting.fetch(:options, %{}, access, @now)
    assert options["data"]["pairs"] == [%{"team" => "alpha", "environment" => "prod"}]

    assert {:ok, packages} =
             Reporting.fetch(
               :packages,
               %{"cve" => c.cve, "placement_id" => Integer.to_string(c.prod.id)},
               access,
               @now
             )

    assert packages["pagination"]["total"] == 2

    assert {:error, %{status: 404}} =
             Reporting.fetch(
               :packages,
               %{"cve" => c.cve, "placement_id" => Integer.to_string(c.stage.id)},
               access,
               @now
             )
  end

  test "invalid and contradictory parameters fail closed without widening" do
    for params <- [
          %{"unknown" => "value"},
          %{"active" => "yes"},
          %{"expires_within_days" => "7"},
          %{"limit" => "1000"},
          %{"cve" => "not-a-cve"}
        ] do
      assert {:error, %{status: 400}} = Reporting.fetch(:targets, params, @all, @now)
    end
  end

  test "workspace and reporting use the same target predicate", c do
    workspace = Workspace.page(%{"mode" => "accepted"}, @now)
    assert Enum.map(workspace.page_rows, & &1.cve) == [c.cve]

    assert {:ok, report} = Reporting.fetch(:targets, %{"whitelisted" => "true"}, @all, @now)

    assert Enum.map(report["data"], &{&1["cve"], &1["placement_id"]}) == [
             {c.cve, Integer.to_string(c.prod.id)}
           ]
  end

  defp accept!(cve, placement_id, days) do
    [target] = Workspace.targets(%{"cve" => cve, "placement_ids" => [placement_id]}, @now)

    Repo.insert!(%Decision{
      cve: cve,
      placement_id: placement_id,
      decision: "accepted_risk",
      reason: "Reporting fixture acceptance",
      actor: "fixture",
      decided_at: DateTime.add(@now, -1, :day),
      expires_at: DateTime.add(@now, days, :day),
      metadata: %{
        "packet_hash" => target.packet_hash,
        "expiry_boundary" => "exclusive",
        "target" => %{
          "team" => target.placement.owner,
          "environment" => target.placement.environment
        }
      }
    })
  end
end
