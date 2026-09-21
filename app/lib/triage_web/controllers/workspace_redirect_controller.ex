defmodule TriageWeb.WorkspaceRedirectController do
  @moduledoc "Retired UI bookmarks lead to the single workspace, never old LiveViews."
  use TriageWeb, :controller

  def show(conn, params) do
    scope =
      params
      |> Map.take(~w(team environment q severity))
      |> Map.filter(fn {_key, value} -> is_binary(value) end)

    scope =
      if is_binary(params["owner"]),
        do: Map.put_new(scope, "team", params["owner"]),
        else: scope

    destination = destination(conn.path_info)

    redirect(conn, to: TriageWeb.WorkspaceLive.workspace_path(scope, destination))
  end

  defp destination(path_info) do
    case path_info do
      ["triage", "history"] -> %{"page" => "timeline"}
      ["triage", cve] -> %{"page" => "review", "item" => cve}
      ["triage"] -> %{"page" => "review"}
      ["cves", cve] -> %{"page" => "inventory", "inspect" => cve}
      ["findings" | _] -> %{"page" => "inventory"}
      ["cases" | _] -> %{"page" => "review"}
      [page] when page in ["timeline", "whats-new"] -> %{"page" => "timeline"}
      _ -> %{"page" => "overview"}
    end
  end
end
