defmodule TriageWeb.WorkspaceLive.Params do
  @moduledoc """
  URL parameters and paths for `TriageWeb.WorkspaceLive`.

  `page` values are public bookmarks and keep their original names:

  | `page`       | Screen                                   |
  |--------------|------------------------------------------|
  | `findings`   | Review (queue); `review` is its detail   |
  | `exceptions` | Risk decisions                           |
  | `daily`      | Timeline (detections and actions)        |
  | `timeline`   | Observation chart (`/timeline`)          |
  | `inventory`  | Vulnerabilities                          |
  | `overview`   | Overview                                 |
  | `news`       | News                                     |
  """
  alias TriageWeb.TimelineFilters

  @pages ~w(findings exceptions daily overview inventory review timeline news)
  @keys ~w(page team environment mode q severity sort offset item inspect tab batch weeks tview risk_q risk_status risk_team risk_environment risk_page focus_target)

  def pages, do: @pages

  def history_scope_label("exceptions", params) do
    team = String.trim(params["risk_team"] || "")
    environment = String.trim(params["risk_environment"] || "")

    "#{if team == "", do: "all teams", else: team} in #{if environment == "", do: "all environments", else: environment}"
  end

  def history_scope_label(_page, _params), do: "all teams in all environments"

  def page_title(page) do
    cond do
      page in ~w(findings review) -> "Review"
      page == "exceptions" -> "Risk decisions"
      page == "daily" -> "Timeline"
      page == "inventory" -> "Vulnerabilities"
      true -> String.capitalize(page)
    end
  end

  def normalize_valid_params(params) do
    if valid_params?(params),
      do: Map.take(params, @keys -- ~w(weeks tview)),
      else: %{}
  end

  def normalize_timeline_params(params, true) do
    params
    |> Map.put("page", "timeline")
    |> Map.put("team", params["team"] || params["owner"] || "")
  end

  def normalize_timeline_params(params, false), do: params

  # T03/A002: the retired read-only inspector dialog is gone; its deep links
  # (inspect=CVE) converge on the same shared actionable detail.
  def normalize_inspect_deep_link(%{"inspect" => cve} = params),
    do:
      params |> Map.put("page", "review") |> Map.put("item", cve) |> Map.drop(["inspect", "tab"])

  def normalize_inspect_deep_link(params), do: params

  def preserve_invalid_focus(_params, %{"focus_target" => value}, true),
    do: %{"page" => "review", "focus_target" => value}

  def preserve_invalid_focus(params, _raw_params, _invalid?), do: params

  def valid_params?(params) do
    Enum.all?(Map.take(params, @keys -- ~w(weeks tview)), fn {_k, v} ->
      is_binary(v) and byte_size(v) <= 2000
    end) and valid_views?(params)
  end

  defp valid_views?(params) do
    Enum.all?(
      [
        {"page", @pages},
        {"mode", ~w(active all history needs urgent unknown accepted progress fixed)},
        {"tab", ~w(summary assets history evidence)},
        {"sort", ~w(priority age)},
        {"severity", ~w(CRITICAL HIGH MEDIUM LOW)}
      ],
      fn {key, allowed} -> params[key] in [nil, ""] or params[key] in allowed end
    ) and valid_focus_target?(params["focus_target"])
  end

  defp valid_focus_target?(nil), do: true
  defp valid_focus_target?(""), do: true

  defp valid_focus_target?(value) when is_binary(value) do
    case Integer.parse(value) do
      {id, ""} when id > 0 -> true
      _ -> false
    end
  end

  defp valid_focus_target?(_value), do: false

  def workspace_path(params, changes \\ %{}) do
    query =
      params
      |> Map.merge(changes)
      |> Map.take(@keys)
      |> Map.filter(fn {_k, v} -> is_binary(v) and v != "" end)
      |> URI.encode_query()

    "/?" <> query
  end

  def nav_path(params, "timeline"),
    do:
      TimelineFilters.path(TimelineFilters.defaults(), %{
        owner: params["team"],
        environment: params["environment"]
      })

  def nav_path(params, "exceptions"),
    do: workspace_path(Map.take(params, ~w(team environment)), %{"page" => "exceptions"})

  def nav_path(params, page),
    do: workspace_path(Map.take(params, ~w(team environment)), %{"page" => page})

  def nav_active?("findings", page), do: page in ~w(findings review)
  def nav_active?("daily", page), do: page in ~w(daily timeline)
  def nav_active?(nav_page, page), do: nav_page == page

  def drill(params, mode, extra \\ %{}),
    do:
      workspace_path(
        Map.take(params, ~w(team environment)),
        Map.merge(
          %{"page" => if(mode == "needs", do: "review", else: "inventory"), "mode" => mode},
          extra
        )
      )

  def review_path(params, cve),
    do:
      workspace_path(params, %{"page" => "review", "item" => cve, "inspect" => nil, "tab" => nil})
end
