defmodule TriageWeb.WorkspaceLive.Params do
  @moduledoc """
  URL parameters and paths for `TriageWeb.WorkspaceLive`.

  `page` values are public bookmarks and keep their original names:

  | `page`       | Screen                                   |
  |--------------|------------------------------------------|
  | `findings`   | Triage (list); `review` is one CVE       |
  | `daily`      | Timeline (detections and actions)        |
  | `timeline`   | Observation chart (`/timeline`)          |
  | `statistics` | Statistics and its CSV export            |

  The retired `overview`, `inventory`, `exceptions` and `news` pages open Triage.
  """
  alias TriageWeb.TimelineFilters

  @pages ~w(findings daily review timeline statistics)
  @retired_pages ~w(overview inventory exceptions news)
  # Lists Triage offers; older drilldown modes open the default list.
  @triage_modes ~w(needs active accepted)
  @keys ~w(page team environment mode q severity sort offset item inspect tab batch weeks tview focus_target period)

  def pages, do: @pages

  def history_scope_label(_page, _params), do: "all teams in all environments"

  def page_title(page) do
    cond do
      page in ~w(findings review) -> "Triage"
      page == "daily" -> "Timeline"
      true -> String.capitalize(page)
    end
  end

  def normalize_retired_page(%{"page" => page} = params) when page in @retired_pages do
    params = Map.put(params, "page", "findings")
    if params["mode"] in @triage_modes, do: params, else: Map.delete(params, "mode")
  end

  def normalize_retired_page(params), do: params

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
        {"page", @pages ++ @retired_pages},
        {"mode", ~w(active all history needs urgent unknown accepted progress fixed)},
        {"tab", ~w(summary assets history evidence)},
        {"sort", ~w(priority age)},
        {"severity", ~w(CRITICAL HIGH MEDIUM LOW)},
        {"period", Map.keys(Triage.Statistics.periods())}
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

  def nav_path(params, page),
    do: workspace_path(Map.take(params, ~w(team environment)), %{"page" => page})

  def nav_active?("findings", page), do: page in ~w(findings review)
  def nav_active?("daily", page), do: page in ~w(daily timeline)
  def nav_active?(nav_page, page), do: nav_page == page

  def drill(params, mode, extra \\ %{}),
    do:
      workspace_path(
        Map.take(params, ~w(team environment q)),
        Map.merge(%{"page" => "findings", "mode" => mode}, extra)
      )

  def review_path(params, cve),
    do:
      workspace_path(params, %{"page" => "review", "item" => cve, "inspect" => nil, "tab" => nil})
end
