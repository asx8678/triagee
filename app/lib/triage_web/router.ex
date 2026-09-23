defmodule TriageWeb.Router do
  use TriageWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {TriageWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug TriageWeb.Auth, :fetch_current_user
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :reporting_api do
    plug TriageWeb.ReportingAuth
  end

  scope "/", TriageWeb do
    pipe_through :api
    get "/health", HealthController, :show
  end

  scope "/api/v1", TriageWeb.Api.V1 do
    pipe_through [:api, :reporting_api]

    get "/summary", ReportingController, :summary
    get "/cves", ReportingController, :cves
    get "/cves/:cve", ReportingController, :cve
    get "/targets", ReportingController, :targets
    get "/targets/:placement_id/packages", ReportingController, :packages
    get "/options", ReportingController, :options
  end

  scope "/", TriageWeb do
    pipe_through :browser
    get "/login", SessionController, :new
    post "/login", SessionController, :create
    post "/login/skip", SessionController, :skip
    delete "/logout", SessionController, :delete
  end

  pipeline :authenticated do
    plug TriageWeb.Auth, :require_authenticated_user
  end

  scope "/", TriageWeb do
    pipe_through [:browser, :authenticated]

    live_session :authenticated, on_mount: [{TriageWeb.Auth, :require_authenticated_user}] do
      live "/", WorkspaceLive
      live "/workspace", WorkspaceLive
      live "/timeline", WorkspaceLive, :timeline
    end

    get "/classifier", WorkspaceRedirectController, :classifier
    get "/triage", WorkspaceRedirectController, :show
    get "/triage/history", WorkspaceRedirectController, :show
    get "/triage/:cve", WorkspaceRedirectController, :show
    get "/intel", WorkspaceRedirectController, :show

    get "/cves/:id", WorkspaceRedirectController, :show

    get "/findings", WorkspaceRedirectController, :show
    get "/findings/:id", WorkspaceRedirectController, :show

    get "/cases", WorkspaceRedirectController, :show
    get "/cases/:id", WorkspaceRedirectController, :show
    get "/cases/:id/exception", WorkspaceRedirectController, :show

    get "/whats-new", WorkspaceRedirectController, :show
    get "/statistics", WorkspaceRedirectController, :show
    get "/replay", WorkspaceRedirectController, :show
    get "/replay/history", WorkspaceRedirectController, :show
    get "/imports", WorkspaceRedirectController, :show
  end

  # Other scopes may use custom stacks.
  # scope "/api", TriageWeb do
  #   pipe_through :api
  # end
end
