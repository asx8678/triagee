defmodule TriageWeb.WorkspaceRedirectController do
  @moduledoc "Retired UI bookmarks lead to the single workspace, never old LiveViews."
  use TriageWeb, :controller

  def show(conn, params) do
    scope = Map.take(params, ~w(team environment q severity))
    scope = if params["owner"], do: Map.put_new(scope, "team", params["owner"]), else: scope

    destination =
      case conn.path_info do
        ["triage", "history"] -> %{"page" => "timeline"}
        ["triage", cve] -> %{"page" => "review", "item" => cve}
        ["triage"] -> %{"page" => "review"}
        ["cves", cve] -> %{"page" => "inventory", "inspect" => cve}
        ["findings" | _] -> %{"page" => "inventory"}
        ["cases" | _] -> %{"page" => "review"}
        [page] when page in ["timeline", "whats-new"] -> %{"page" => "timeline"}
        _ -> %{"page" => "overview"}
      end

    redirect(conn, to: TriageWeb.WorkspaceLive.workspace_path(scope, destination))
  end
end
