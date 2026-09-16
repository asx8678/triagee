defmodule TriageWeb.Router do
  use TriageWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {TriageWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", TriageWeb do
    pipe_through :browser

    get "/", PageController, :home

    live "/triage", TriageLive
    live "/intel", IntelLive

    live "/cves/:id", CveLive.Show

    live "/findings", FindingLive.Index
    live "/findings/:id", FindingLive.Show

    live "/cases", CaseLive.Index
    live "/cases/:id", CaseLive.Show
    live "/cases/:id/exception", ExceptionLive

    live "/whats-new", WhatsNewLive
    live "/timeline", TimelineLive
    live "/statistics", StatisticsLive
    live "/replay", ReplayLive
    live "/replay/history", ReplayHistoryLive
    live "/imports", ImportLive
  end

  # Other scopes may use custom stacks.
  # scope "/api", TriageWeb do
  #   pipe_through :api
  # end
end
