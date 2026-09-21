defmodule TriageWeb.WorkspaceRedirectControllerTest do
  use TriageWeb.ConnCase, async: true
  @moduletag authenticated: :reviewer

  test "nested and list query parameters never reach scalar URL encoding", %{conn: conn} do
    for key <- ~w(team environment q severity owner),
        suffix <- ["[]=invalid", "[nested]=invalid"] do
      response = get(conn, "/findings?#{key}#{suffix}")
      destination = redirected_to(response, 302)
      assert URI.decode_query(URI.parse(destination).query) == %{"page" => "inventory"}
    end
  end

  test "valid owner is retained when a malformed team is discarded", %{conn: conn} do
    destination = conn |> get("/findings?team[]=bad&owner=alpha") |> redirected_to(302)

    assert URI.decode_query(URI.parse(destination).query) == %{
             "page" => "inventory",
             "team" => "alpha"
           }
  end

  test "valid team wins over legacy owner and unknown keys are not forwarded", %{conn: conn} do
    destination =
      conn |> get("/findings?team=alpha&owner=beta&unknown[]=bad") |> redirected_to(302)

    assert URI.decode_query(URI.parse(destination).query) == %{
             "page" => "inventory",
             "team" => "alpha"
           }
  end
end
