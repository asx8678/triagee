defmodule TriageWeb.ClassifierLiveTest do
  use TriageWeb.ConnCase, async: false
  @moduletag authenticated: :reviewer
  import Phoenix.LiveViewTest

  test "old classifier links redirect into scoped Review", %{conn: conn} do
    assert conn
           |> get("/classifier?cve=CVE-2099-1234&team=alpha&environment=prod")
           |> redirected_to(302) ==
             "/?environment=prod&item=CVE-2099-1234&page=review&team=alpha"

    assert conn |> get("/classifier") |> redirected_to(302) == "/?page=review"
  end

  test "the separate classifier is absent from navigation", %{conn: conn} do
    {:ok, view, _} = live(conn, "/")
    refute has_element?(view, "#workspace-nav-classifier")
    refute has_element?(view, "#classifier-link")
    assert has_element?(view, "#workspace-nav-findings", "Review")
  end
end
