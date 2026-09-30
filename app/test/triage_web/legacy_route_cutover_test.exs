defmodule TriageWeb.LegacyRouteCutoverTest do
  @moduledoc """
  Retired screen URLs must redirect into the single workspace. The retired
  LiveViews themselves have been deleted; only these bookmarks remain.
  """
  use TriageWeb.ConnCase, async: true

  @moduletag authenticated: :reviewer

  @retired [
    {"/findings", %{"page" => "inventory"}},
    {"/findings/1", %{"page" => "inventory"}},
    {"/cves/CVE-2099-1001", %{"page" => "inventory", "inspect" => "CVE-2099-1001"}},
    {"/triage", %{"page" => "review"}},
    {"/triage/history", %{"page" => "timeline"}},
    {"/triage/CVE-2099-1001", %{"page" => "review", "item" => "CVE-2099-1001"}},
    {"/cases", %{"page" => "review"}},
    {"/cases/1", %{"page" => "review"}},
    {"/cases/1/exception", %{"page" => "review"}},
    {"/whats-new", %{"page" => "timeline"}},
    {"/intel", %{"page" => "overview"}},
    {"/statistics", %{"page" => "overview"}},
    {"/imports", %{"page" => "overview"}},
    {"/replay", %{"page" => "overview"}},
    {"/replay/history", %{"page" => "overview"}}
  ]

  for {path, destination} <- @retired do
    test "#{path} redirects to its exact workspace destination and preserves supported scope", %{
      conn: conn
    } do
      path = unquote(path)
      destination = unquote(Macro.escape(destination))
      assert redirected_query(conn, path) == destination

      scoped =
        redirected_query(
          conn,
          path <> "?owner=alpha&environment=prod&q=openssl&severity=HIGH&after=99&suppressed=1"
        )

      assert scoped ==
               Map.merge(destination, %{
                 "team" => "alpha",
                 "environment" => "prod",
                 "q" => "openssl",
                 "severity" => "HIGH"
               })
    end
  end

  test "nested legacy query values are discarded without crashing or smuggling workspace state",
       %{
         conn: conn
       } do
    assert redirected_query(
             conn,
             "/findings?owner[]=alpha&team[x]=beta&environment[]=prod&q[x]=test&severity[]=HIGH&page=review&inspect=forged"
           ) == %{"page" => "inventory"}
  end

  test "explicit team takes precedence over the old owner alias", %{conn: conn} do
    assert redirected_query(conn, "/cases?team=beta&owner=alpha") == %{
             "page" => "review",
             "team" => "beta"
           }
  end

  test "production mounts only workspace LiveViews" do
    routes = Phoenix.Router.routes(TriageWeb.Router)
    live_routes = Enum.filter(routes, &(&1.plug == Phoenix.LiveView.Plug))

    assert Enum.sort(Enum.map(live_routes, & &1.path)) == [
             "/",
             "/timeline",
             "/workspace"
           ]

    for route <- live_routes do
      assert {TriageWeb.WorkspaceLive, _, _, _} = route.metadata.phoenix_live_view
    end

    for {path, _destination} <- @retired do
      info = Phoenix.Router.route_info(TriageWeb.Router, "GET", path, "www.example.com")
      assert info.plug == TriageWeb.WorkspaceRedirectController
      assert info.plug_opts == :show
    end
  end

  defp redirected_query(conn, path) do
    response = get(conn, path)
    uri = response |> redirected_to(302) |> URI.parse()
    assert uri.path == "/"
    assert uri.host == nil
    assert uri.fragment == nil
    refute response.resp_body =~ "data-phx-main"
    URI.decode_query(uri.query)
  end
end
