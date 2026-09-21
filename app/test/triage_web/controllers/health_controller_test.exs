defmodule TriageWeb.HealthControllerTest do
  use TriageWeb.ConnCase, async: true

  test "anonymous readiness reveals only status" do
    response = build_conn() |> get("/health")
    assert json_response(response, 200) == %{"status" => "ok"}
  end
end
