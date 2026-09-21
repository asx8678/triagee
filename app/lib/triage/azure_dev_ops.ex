defmodule Triage.AzureDevOps do
  @moduledoc "Explicit, server-side Azure DevOps work item creation. No automatic POST retries."
  @doc "Low-level transport; callers must durably claim an operation before calling."
  def create(cve, targets, operation) do
    with {:ok, destination} <- destination() do
      create_payload(destination, payload(cve, targets, operation))
    end
  end

  @doc "Non-secret destination captured with the immutable operation payload."
  def destination do
    config =
      Map.new(~w(ADO_ORG_URL ADO_PROJECT ADO_PAT ADO_WORK_ITEM_TYPE), &{&1, System.get_env(&1)})

    org = String.trim_trailing(config["ADO_ORG_URL"] || "", "/")
    uri = URI.parse(org)

    cond do
      Enum.any?(config, fn {_, value} -> value in [nil, ""] end) ->
        {:error,
         "Azure DevOps is not configured. Set ADO_ORG_URL, ADO_PROJECT, ADO_PAT and ADO_WORK_ITEM_TYPE on the server."}

      uri.scheme != "https" or is_nil(uri.host) or not is_nil(uri.userinfo) or
        not is_nil(uri.query) or not is_nil(uri.fragment) ->
        {:error, "ADO_ORG_URL must be an HTTPS URL without credentials, query or fragment."}

      true ->
        {:ok,
         %{
           "org" => org,
           "project" => config["ADO_PROJECT"],
           "type" => config["ADO_WORK_ITEM_TYPE"]
         }}
    end
  end

  def marker(operation), do: "triage-operation-" <> operation

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
      %{op: "add", path: "/fields/System.Description", value: html},
      %{op: "add", path: "/fields/System.Tags", value: marker(operation)}
    ] ++ routing_fields()
  end

  defp description(cve, targets, operation) do
    details = Enum.map_join(targets, "", &deployment_description/1)

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

  defp deployment_description(target) do
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

  def create_payload(destination, payload) do
    with :ok <- configured_destination(destination) do
      case request(destination, :post, "/workitems/$" <> path_segment(destination["type"]),
             headers: [{"content-type", "application/json-patch+json"}],
             body: Jason.encode!(payload)
           ) do
        {:ok, %{status: status, body: %{"id" => id}}}
        when status in 200..299 and is_integer(id) and id > 0 ->
          {:ok, ticket_url(destination, id)}

        _ ->
          # Even a rejected/malformed response cannot safely authorize another POST.
          {:error, :remote_outcome_unknown}
      end
    end
  end

  @doc "Read-only WIQL search followed by an exact tag check via GET. No match is NOT proof of absence."
  def reconcile(destination, marker) do
    with :ok <- configured_destination(destination),
         true <- Regex.match?(~r/^triage-operation-[0-9a-f-]{36}$/, marker),
         {:ok, %{status: 200, body: %{"workItems" => items}}} when is_list(items) <-
           request(destination, :post, "/wiql",
             json: %{
               "query" =>
                 "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS '#{marker}'"
             }
           ) do
      verify_matches(destination, marker, items)
    else
      _ -> {:error, :reconciliation_unavailable}
    end
  end

  defp verify_matches(destination, marker, [%{"id" => id}]) when is_integer(id) and id > 0 do
    case request(destination, :get, "/workitems/#{id}", []) do
      {:ok, %{status: 200, body: %{"id" => ^id, "fields" => %{"System.Tags" => tags}}}}
      when is_binary(tags) ->
        if marker in Enum.map(String.split(tags, ";"), &String.trim/1),
          do: {:ok, ticket_url(destination, id)},
          else: {:error, :reconciliation_required}

      _ ->
        {:error, :reconciliation_unavailable}
    end
  end

  defp verify_matches(_destination, _marker, _items), do: {:error, :reconciliation_required}

  defp configured_destination(expected) do
    case destination() do
      {:ok, ^expected} -> :ok
      _ -> {:error, :configuration_changed}
    end
  end

  defp ticket_url(destination, id), do: base_url(destination) <> "/_workitems/edit/#{id}"

  defp base_url(destination),
    do: destination["org"] <> "/" <> path_segment(destination["project"])

  defp path_segment(value), do: URI.encode(value, &URI.char_unreserved?/1)

  defp request(destination, method, path, options) do
    Req.request(
      Req.new(Application.get_env(:triage, :ado_req_options, [])),
      Keyword.merge(options,
        method: method,
        url: base_url(destination) <> "/_apis/wit" <> path <> "?api-version=7.1",
        auth: {:basic, ":" <> System.get_env("ADO_PAT", "")},
        retry: false,
        redirect: false,
        receive_timeout: 15_000
      )
    )
  rescue
    # Never expose adapter exceptions: they can contain the PAT or request headers.
    _ -> {:error, :transport_unavailable}
  end
end
