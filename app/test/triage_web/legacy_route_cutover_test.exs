defmodule TriageWeb.LegacyRouteCutoverTest do
  @moduledoc """
  Public-route assertions deliberately use the real endpoint, never LegacyUICase.
  The legacy harness preserves component/domain coverage, not public availability.
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

  test "production mounts only workspace LiveViews, never the legacy test router" do
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

    refute Enum.any?(routes, &(&1.plug == TriageWeb.LegacyUIRouter))

    for {path, _destination} <- @retired do
      info = Phoenix.Router.route_info(TriageWeb.Router, "GET", path, "www.example.com")
      assert info.plug == TriageWeb.WorkspaceRedirectController
      assert info.plug_opts == :show
    end
  end

  test "legacy harness keeps the complete retired LiveView route map only for regression tests" do
    expected = %{
      "/" => TriageWeb.FindingLive.Index,
      "/findings" => TriageWeb.FindingLive.Index,
      "/findings/:id" => TriageWeb.FindingLive.Show,
      "/cves/:id" => TriageWeb.CveLive.Show,
      "/triage" => TriageWeb.GuidedReviewLive,
      "/triage/history" => TriageWeb.TriageLive,
      "/triage/:cve" => TriageWeb.GuidedReviewLive,
      "/cases" => TriageWeb.CaseLive.Index,
      "/cases/:id" => TriageWeb.CaseLive.Show,
      "/cases/:id/exception" => TriageWeb.ExceptionLive,
      "/whats-new" => TriageWeb.WhatsNewLive,
      "/timeline" => TriageWeb.TimelineLive,
      "/intel" => TriageWeb.IntelLive,
      "/statistics" => TriageWeb.StatisticsLive,
      "/imports" => TriageWeb.ImportLive,
      "/replay" => TriageWeb.ReplayLive,
      "/replay/history" => TriageWeb.ReplayHistoryLive
    }

    actual =
      Map.new(Phoenix.Router.routes(TriageWeb.LegacyUIRouter), fn route ->
        assert route.plug == Phoenix.LiveView.Plug
        {view, _, _, _} = route.metadata.phoenix_live_view
        {route.path, view}
      end)

    assert actual == expected
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
