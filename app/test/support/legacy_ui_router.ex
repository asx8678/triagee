defmodule TriageWeb.LegacyUIRouter do
  @moduledoc """
  Test-only route map for retained legacy LiveView/component regression coverage.

  Nothing forwards to this router from the application. Public bookmarks must
  continue to redirect through TriageWeb.Router; this map only lets tests exercise
  the old UI's URL validation, patches, navigation, uploads and domain actions.
  """
  use TriageWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {TriageWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  scope "/", TriageWeb do
    pipe_through :browser

    live "/", FindingLive.Index, :index
    live "/triage", GuidedReviewLive
    live "/triage/history", TriageLive
    live "/triage/:cve", GuidedReviewLive
    live "/intel", IntelLive
    live "/cves/:id", CveLive.Show, :show
    live "/findings", FindingLive.Index, :index
    live "/findings/:id", FindingLive.Show, :show
    live "/cases", CaseLive.Index, :index
    live "/cases/:id", CaseLive.Show, :show
    live "/cases/:id/exception", ExceptionLive
    live "/whats-new", WhatsNewLive
    live "/timeline", TimelineLive
    live "/statistics", StatisticsLive
    live "/replay", ReplayLive
    live "/replay/history", ReplayHistoryLive
    live "/imports", ImportLive
  end
end
