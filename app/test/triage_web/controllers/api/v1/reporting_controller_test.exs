defmodule TriageWeb.Api.V1.ReportingControllerTest do
  use TriageWeb.ConnCase, async: false

  import Triage.Fixtures
  alias Triage.Accounts.ReportingTokens
  alias Triage.Decisions.Decision
  alias Triage.{Repo, Workspace}

  setup do
    previous = Application.get_env(:triage, :reporting_api)
    Application.put_env(:triage, :reporting_api, enabled: true, rate_limit: 120)
    on_exit(fn -> Application.put_env(:triage, :reporting_api, previous) end)

    Triage.DataCase.reset_inventory!()
    image = image!("api-controller")
    prod = placement!(image, "alpha", "prod")
    stage = placement!(image, "alpha", "staging")
    finding = finding!(image, "CVE-2099-8201", severity: "HIGH")
    accept!(finding.cve, prod.id)

    user = account_fixture(:viewer)

    {:ok, %{token: token}} =
      ReportingTokens.issue(user, %{
        label: "controller",
        expires_at:
          DateTime.utc_now() |> DateTime.add(3_600, :second) |> DateTime.truncate(:second),
        scopes: [{"alpha", "prod"}]
      })

    %{token: token, cve: finding.cve, prod: prod, stage: stage}
  end

  test "API is bearer-only JSON and disabled mode is an honest 503", c do
    assert %{"error" => %{"code" => "unauthenticated"}} =
             c.conn |> get("/api/v1/summary") |> json_response(401)

    assert %{"error" => %{"code" => "unauthenticated"}} =
             c.conn
             |> put_req_header("authorization", "Bearer malformed")
             |> get("/api/v1/summary")
             |> json_response(401)

    Application.put_env(:triage, :reporting_api, enabled: false, rate_limit: 120)

    conn =
      c.conn
      |> put_req_header("authorization", "Bearer " <> c.token)
      |> get("/api/v1/summary")

    assert %{"error" => %{"code" => "reporting_disabled"}} = json_response(conn, 503)
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "rate limits are per token and return an explicit retry boundary", c do
    Application.put_env(:triage, :reporting_api, enabled: true, rate_limit: 1)

    assert c.conn
           |> put_req_header("authorization", "Bearer " <> c.token)
           |> get("/api/v1/summary")
           |> json_response(200)

    conn =
      c.conn
      |> put_req_header("authorization", "Bearer " <> c.token)
      |> get("/api/v1/summary")

    assert %{"error" => %{"code" => "rate_limited"}} = json_response(conn, 429)
    assert [retry_after] = get_resp_header(conn, "retry-after")
    assert {seconds, ""} = Integer.parse(retry_after)
    assert seconds in 1..60
  end

  test "summary, target, package and options routes enforce the token's exact pair", c do
    before_count = Repo.aggregate(Decision, :count)

    summary = api_get(c.conn, c.token, "/api/v1/summary")
    assert summary["data"]["active_targets"] == 1
    assert summary["data"]["whitelisted_targets"] == 1

    targets = api_get(c.conn, c.token, "/api/v1/targets?whitelisted=true")
    assert [%{"placement_id" => id, "whitelisted" => true}] = targets["data"]
    assert id == Integer.to_string(c.prod.id)

    detail =
      api_get(
        c.conn,
        c.token,
        "/api/v1/cves/#{c.cve}?team=alpha&environment=prod"
      )

    target_query = detail["data"]["targets_path"] |> URI.parse() |> Map.fetch!(:query)

    assert URI.decode_query(target_query) == %{
             "active" => "true",
             "cve" => c.cve,
             "team" => "alpha",
             "environment" => "prod"
           }

    packages =
      api_get(c.conn, c.token, "/api/v1/targets/#{c.prod.id}/packages?cve=#{c.cve}")

    assert packages["pagination"]["total"] == 1

    options = api_get(c.conn, c.token, "/api/v1/options")
    assert options["data"]["pairs"] == [%{"environment" => "prod", "team" => "alpha"}]

    conn =
      c.conn
      |> put_req_header("authorization", "Bearer " <> c.token)
      |> get("/api/v1/targets?team=alpha&environment=staging")

    assert %{"error" => %{"code" => "forbidden_scope"}} = json_response(conn, 403)
    assert Repo.aggregate(Decision, :count) == before_count
  end

  test "unknown parameters and unsupported methods never widen or mutate", c do
    conn =
      c.conn
      |> put_req_header("authorization", "Bearer " <> c.token)
      |> get("/api/v1/targets?unknown=value")

    assert %{"error" => %{"code" => "unknown_parameter"}} = json_response(conn, 400)

    conn =
      c.conn
      |> put_req_header("authorization", "Bearer " <> c.token)
      |> post("/api/v1/targets", %{})

    assert conn.status in [404, 405]
  end

  defp api_get(conn, token, path) do
    conn
    |> put_req_header("authorization", "Bearer " <> token)
    |> get(path)
    |> json_response(200)
  end

  defp accept!(cve, placement_id) do
    [target] = Workspace.targets(%{"cve" => cve, "placement_ids" => [placement_id]})

    Repo.insert!(%Decision{
      cve: cve,
      placement_id: placement_id,
      decision: "accepted_risk",
      reason: "Controller fixture acceptance",
      actor: "fixture",
      decided_at: DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second),
      expires_at: DateTime.utc_now() |> DateTime.add(30, :day) |> DateTime.truncate(:second),
      metadata: %{"packet_hash" => target.packet_hash, "expiry_boundary" => "exclusive"}
    })
  end
end
