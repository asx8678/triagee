defmodule Triage.AzureDevOps do
  @moduledoc """
  Explicit, server-side Azure DevOps access: work item creation with no
  automatic POST retries, and a read-only fetch of one repository file.
  """
  @doc "Low-level transport; callers must durably claim an operation before calling."
  def create(cve, targets, operation) do
    with {:ok, destination} <- destination() do
      create_payload(destination, payload(cve, targets, operation))
    end
  end

  @org_url_error "ADO_ORG_URL must be an HTTPS URL without credentials, query or fragment."

  defp valid_org?(org) do
    uri = URI.parse(org)

    uri.scheme == "https" and not is_nil(uri.host) and is_nil(uri.userinfo) and
      is_nil(uri.query) and is_nil(uri.fragment)
  end

  @doc "The organization URL from `ADO_ORG_URL`, or why it cannot be used."
  def organization do
    org = String.trim_trailing(System.get_env("ADO_ORG_URL") || "", "/")

    cond do
      org == "" -> {:error, "ADO_ORG_URL is not set."}
      not valid_org?(org) -> {:error, @org_url_error}
      true -> {:ok, org}
    end
  end

  @doc "Non-secret destination captured with the immutable operation payload."
  def destination do
    config =
      Map.new(~w(ADO_ORG_URL ADO_PROJECT ADO_PAT ADO_WORK_ITEM_TYPE), &{&1, System.get_env(&1)})

    org = String.trim_trailing(config["ADO_ORG_URL"] || "", "/")

    cond do
      Enum.any?(config, fn {_, value} -> value in [nil, ""] end) ->
        {:error,
         "Azure DevOps is not configured. Set ADO_ORG_URL, ADO_PROJECT, ADO_PAT and ADO_WORK_ITEM_TYPE on the server."}

      not valid_org?(org) ->
        {:error, @org_url_error}

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

  @doc "The optional backlog and team display labels; `nil` when not set."
  def display_labels do
    %{backlog: label("ADO_BACKLOG"), team: label("ADO_TEAM")}
  end

  defp label(variable) do
    case System.get_env(variable) do
      value when value in [nil, ""] -> nil
      value -> value
    end
  end

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
        {"Team", target.placement.owner},
        {"Environment", target.placement.environment},
        {"Namespace", target.placement.namespace},
        {"Image", image_name(target.image)},
        {"Image digest", target.image.digest},
        {"Exposure", exposure_label(target.exposure)}
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

  defp image_name(%{repository: repository, tag: tag})
       when is_binary(repository) and repository != "" and is_binary(tag) and tag != "",
       do: repository <> ":" <> tag

  defp image_name(%{repository: repository}) when is_binary(repository), do: repository
  defp image_name(_image), do: nil

  defp exposure_label("internet_exposed"), do: "External (reachable from the internet)"
  defp exposure_label("internal"), do: "Internal"
  defp exposure_label(_unknown), do: "Unknown"

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

  @max_file_bytes 1_000_000

  @doc """
  Reads one text file from an Azure Repos Git repository. Nothing is ever
  written to the repository, and the token needs only the Code (Read) scope:
  `ADO_WHITELIST_PAT` when set, otherwise `ADO_PAT`.

  `source` is the non-secret location: `"org"`, `"project"`, `"repository"`,
  `"path"` and an optional `"branch"` (the default branch when absent).
  Returns `{:ok, %{content: text, commit: id}}`, or `{:error, reason}` with
  `:unauthorized`, `:not_found`, `:not_a_file`, `:too_large` or `:unavailable`.
  """
  def repository_file(source) do
    url =
      source["org"] <>
        "/" <>
        path_segment(source["project"]) <>
        "/_apis/git/repositories/" <> path_segment(source["repository"]) <> "/items"

    Req.new(Application.get_env(:triage, :ado_req_options, []))
    |> Req.request(
      method: :get,
      url: url,
      params: file_params(source),
      auth: {:basic, ":" <> repository_token()},
      retry: false,
      redirect: false,
      receive_timeout: 15_000
    )
    |> file_response()
  rescue
    # Never expose adapter exceptions: they can contain the token or request headers.
    _ -> {:error, :unavailable}
  end

  @doc "The browser address of the same file, for a link. Holds no secret."
  def repository_file_url(source) do
    version = if source["branch"], do: [{"version", "GB" <> source["branch"]}], else: []

    source["org"] <>
      "/" <>
      path_segment(source["project"]) <>
      "/_git/" <>
      path_segment(source["repository"]) <>
      "?" <> URI.encode_query([{"path", source["path"]}] ++ version)
  end

  @doc "Whether a token for reading the repository is present."
  def repository_token?, do: repository_token() != ""

  defp repository_token do
    case System.get_env("ADO_WHITELIST_PAT") do
      value when value in [nil, ""] -> System.get_env("ADO_PAT", "")
      value -> value
    end
  end

  defp file_params(source) do
    base = [
      {"path", source["path"]},
      {"includeContent", "true"},
      {"$format", "json"},
      {"api-version", "7.1"}
    ]

    case source["branch"] do
      branch when branch in [nil, ""] ->
        base

      branch ->
        base ++
          [{"versionDescriptor.version", branch}, {"versionDescriptor.versionType", "branch"}]
    end
  end

  # A rejected token is answered with 401/403, or with a sign-in page as 203 or
  # a redirect. A folder has no content.
  defp file_response({:ok, %{status: 200, body: %{"content" => content} = item}})
       when is_binary(content),
       do: file_content(content, item["commitId"])

  defp file_response({:ok, %{status: 200, body: content}}) when is_binary(content),
    do: file_content(content, nil)

  defp file_response({:ok, %{status: 200}}), do: {:error, :not_a_file}

  defp file_response({:ok, %{status: status}}) when status in [203, 302, 401, 403],
    do: {:error, :unauthorized}

  defp file_response({:ok, %{status: 404}}), do: {:error, :not_found}
  defp file_response(_other), do: {:error, :unavailable}

  defp file_content(content, commit) do
    cond do
      byte_size(content) > @max_file_bytes -> {:error, :too_large}
      not String.valid?(content) -> {:error, :not_a_file}
      true -> {:ok, %{content: content, commit: commit}}
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
