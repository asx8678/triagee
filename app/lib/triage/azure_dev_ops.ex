defmodule Triage.AzureDevOps do
  @moduledoc "Explicit, server-side Azure DevOps work item creation. No automatic POST retries."
  def create(cve, targets, operation) do
    config =
      Map.new(~w(ADO_ORG_URL ADO_PROJECT ADO_PAT ADO_WORK_ITEM_TYPE), &{&1, System.get_env(&1)})

    if Enum.any?(config, fn {_, value} -> value in [nil, ""] end) do
      {:error,
       "Azure DevOps is not configured. Set ADO_ORG_URL, ADO_PROJECT, ADO_PAT and ADO_WORK_ITEM_TYPE on the server."}
    else
      send_ticket(config, cve, targets, operation)
    end
  end

  def backlog, do: System.get_env("ADO_BACKLOG") || "1 backlog"
  def team, do: System.get_env("ADO_TEAM") || "Configured backlog team"

  def rationale,
    do:
      "Remediate the reported vulnerable components to reduce security risk. Review severity, exposure and available fixes in the evidence below; scanner detection alone does not prove exploitability."

  defp routing_fields do
    # Teams own area paths; System.AssignedTo only accepts individual identities.
    case System.get_env("ADO_AREA_PATH") do
      value when value in [nil, ""] -> []
      value -> [%{op: "add", path: "/fields/System.AreaPath", value: value}]
    end
  end

  def payload(cve, targets, operation) do
    html = description(cve, targets, operation)

    [
      %{op: "add", path: "/fields/System.Title", value: "#{cve} needs to be fixed"},
      %{op: "add", path: "/fields/System.Description", value: html}
    ] ++ routing_fields()
  end

  defp description(cve, targets, operation) do
    details =
      Enum.map_join(targets, "", fn target ->
        deployment =
          fields([
            {"Deployment", target.placement.id},
            {"Team", target.placement.owner},
            {"Environment", target.placement.environment},
            {"Namespace", target.placement.namespace},
            {"Image", target.image.id},
            {"Image digest", target.image.digest},
            {"Exposure", target.exposure}
          ])

        findings =
          Enum.map_join(target.findings, "", fn finding ->
            "<ul>" <>
              fields(
                Enum.map(
                  [
                    {:package_name, "Package"},
                    {:package_version, "Package version"},
                    {:severity, "Severity"},
                    {:fix, "Available fix"},
                    {:first_seen, "First observed"},
                    {:last_seen, "Last observed"}
                  ],
                  fn {key, label} -> {label, Map.get(finding, key)} end
                )
              ) <>
              "</ul>" <> paragraph(Map.get(finding, :description))
          end)

        "<h3>Affected deployment</h3><ul>" <> deployment <> "</ul>" <> findings
      end)

    "<h2>Summary</h2><p>" <>
      escape(cve) <>
      " was reported in the selected deployment scopes.</p>" <>
      "<h2>Why this needs to be fixed</h2><p>" <>
      escape(rationale()) <>
      "</p><h2>Affected components and details</h2>" <>
      details <>
      "<h2>Reference</h2><p>https://nvd.nist.gov/vuln/detail/" <>
      escape(cve) <>
      "</p><ul>" <> fields([{"Request reference", operation}]) <> "</ul>"
  end

  defp fields(values) do
    Enum.map_join(values, "", fn {label, value} ->
      case readable(value) do
        "" -> ""
        text -> "<li><strong>" <> escape(label) <> ":</strong> " <> escape(text) <> "</li>"
      end
    end)
  end

  defp paragraph(value) do
    case readable(value) do
      "" -> ""
      text -> "<p>" <> escape(text) <> "</p>"
    end
  end

  defp readable(nil), do: ""
  defp readable(value) when is_binary(value), do: String.trim(value)
  defp readable(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp readable(%Date{} = value), do: Date.to_iso8601(value)
  defp readable(value) when is_number(value) or is_atom(value), do: to_string(value)
  defp readable(_), do: ""
  defp escape(value), do: value |> Phoenix.HTML.html_escape() |> Phoenix.HTML.safe_to_string()

  defp send_ticket(config, cve, targets, operation) do
    org = String.trim_trailing(config["ADO_ORG_URL"], "/")

    if URI.parse(org).scheme != "https" do
      {:error, "ADO_ORG_URL must use HTTPS."}
    else
      url =
        org <>
          "/" <>
          URI.encode_www_form(config["ADO_PROJECT"]) <>
          "/_apis/wit/workitems/$" <>
          URI.encode_www_form(config["ADO_WORK_ITEM_TYPE"]) <> "?api-version=7.1"

      case Req.post(Req.new(Application.get_env(:triage, :ado_req_options, [])),
             url: url,
             auth: {:basic, ":" <> config["ADO_PAT"]},
             headers: [{"content-type", "application/json-patch+json"}],
             body: Jason.encode!(payload(cve, targets, operation)),
             retry: false,
             redirect: false,
             receive_timeout: 15_000
           ) do
        {:ok, %{status: status, body: %{"id" => id}}} when status in 200..299 ->
          {:ok,
           org <> "/" <> URI.encode_www_form(config["ADO_PROJECT"]) <> "/_workitems/edit/#{id}"}

        {:ok, %{status: status}} ->
          {:error,
           "Azure DevOps rejected ticket creation (HTTP #{status}). No local decision saved."}

        {:error, _} ->
          {:error,
           "Azure DevOps response unavailable. Check Azure DevOps before retrying; a ticket may have been created."}
      end
    end
  end
end
