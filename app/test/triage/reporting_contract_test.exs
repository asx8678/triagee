defmodule Triage.ReportingContractTest do
  use ExUnit.Case, async: true

  @openapi Path.expand("../../docs/openapi/grafana-v1.yaml", __DIR__)
  @dashboard Path.expand("../../priv/grafana/triage-reporting-dashboard.json", __DIR__)
  @router Path.expand("../../lib/triage_web/router.ex", __DIR__)

  @routes [
    "/api/v1/summary",
    "/api/v1/cves",
    "/api/v1/cves/{cve}",
    "/api/v1/targets",
    "/api/v1/targets/{placement_id}/packages",
    "/api/v1/options"
  ]

  test "OpenAPI documents every versioned reporting route as GET-only" do
    contract = File.read!(@openapi)
    router = File.read!(@router)

    for route <- @routes do
      assert contract =~ "  #{route}:"
    end

    for route <- [
          ~s(get "/summary"),
          ~s(get "/cves"),
          ~s(get "/cves/:cve"),
          ~s(get "/targets"),
          ~s(get "/targets/:placement_id/packages"),
          ~s(get "/options")
        ] do
      assert router =~ route
    end

    refute contract =~ "\n    post:"
    refute contract =~ "\n    put:"
    refute contract =~ "\n    patch:"
    refute contract =~ "\n    delete:"
    assert contract =~ "reportingBearer"
    assert contract =~ "per_response"
  end

  test "Grafana starter is valid JSON and contains no credential or fixed service URL" do
    dashboard = @dashboard |> File.read!() |> Jason.decode!()
    encoded = Jason.encode!(dashboard)

    assert dashboard["uid"] == "triage-reporting-v1"
    assert dashboard["refresh"] == "1m"
    assert length(dashboard["panels"]) >= 6
    assert encoded =~ "/api/v1/summary"
    assert encoded =~ "/api/v1/targets"
    refute encoded =~ "Authorization"
    refute encoded =~ "Bearer "
    refute encoded =~ "trg_"
    refute encoded =~ "http://"
    refute encoded =~ "https://"
  end
end
