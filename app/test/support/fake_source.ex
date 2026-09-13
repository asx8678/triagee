defmodule Triage.Collection.FakeSource do
  @moduledoc """
  Test-only stand-in for the security GraphQL API, served by the existing
  `Bandit` dependency on a fresh loopback port.

  It reproduces the real quirks that matter for collection:

    * unauthenticated requests get a 302 (not a 401);
    * `vulnerabilities` is empty unless `engine: "Grype"` is passed;
    * owner-scoped queries never populate `vulnerabilities`;
    * metrics count suppressed findings too;
    * fixtures are mutable so a test can simulate rotation, drift and errors.

  Raw override hooks let tests inject malformed upstream shapes that the
  normal fixtures cannot express: `owners_raw`, `inventory_raw` (owner => raw
  entry list) and `detail_raw` (api id => raw detail object list).
  """

  @behaviour Plug

  import Plug.Conn

  @impl true
  def init(agent), do: agent

  @impl true
  def call(conn, agent) do
    {:ok, body, conn} = read_body(conn)
    query = parse_query(body)

    Agent.get_and_update(agent, fn state ->
      state = %{state | requests: state.requests + 1, current: state.current + 1}
      state = %{state | max_concurrent: max(state.max_concurrent, state.current)}
      {state, state}
    end)

    try do
      state = Agent.get(agent, & &1)
      if state.delay_ms > 0, do: Process.sleep(state.delay_ms)
      respond(conn, state, query)
    after
      Agent.update(agent, fn state -> %{state | current: state.current - 1} end)
    end
  end

  defp respond(conn, state, query) do
    cond do
      state.require_auth or
          (is_integer(state.fail_auth_after) and state.requests > state.fail_auth_after) ->
        conn
        |> put_resp_header("location", "https://oauth2-proxy.test/oauth2/start")
        |> send_resp(302, "")

      is_integer(state.fail_status) ->
        send_resp(conn, state.fail_status, "upstream boom")

      state.graphql_errors ->
        send_json(conn, %{"errors" => [%{"message" => "resolver failed"}]})

      String.contains?(query, "lastClusterScan") ->
        send_json(conn, %{
          "data" => %{"status" => %{"lastClusterScan" => state.last_cluster_scan}}
        })

      String.contains?(query, "owner {") ->
        owners =
          case Map.get(state, :owners_raw) do
            list when is_list(list) ->
              list

            _other ->
              state.images |> Enum.map(& &1.owner) |> Enum.uniq() |> Enum.map(&%{"id" => &1})
          end

        send_json(conn, %{"data" => %{"owner" => owners}})

      match = Regex.run(~r/image\s*\(\s*id:\s*"([^"]+)"/, query) ->
        [_all, id] = match
        image = Enum.find(state.images, &(&1.id == id))

        cond do
          Map.has_key?(Map.get(state, :detail_raw, %{}), id) ->
            send_json(conn, %{"data" => %{"image" => Map.get(state.detail_raw, id)}})

          image ->
            with_vulns = Regex.match?(~r/engine:\s*"Grype"/, query)
            send_json(conn, %{"data" => %{"image" => [image_json(image, with_vulns)]}})

          true ->
            send_json(conn, %{"data" => %{"image" => []}})
        end

      match = Regex.run(~r/image\s*\(\s*owner:\s*"([^"]+)"/, query) ->
        [_all, owner] = match

        list =
          case Map.get(state, :inventory_raw, %{})[owner] do
            raw when is_list(raw) ->
              raw

            _other ->
              state.images
              |> Enum.filter(&(&1.owner == owner))
              |> Enum.map(&image_json(&1, false))
          end

        send_json(conn, %{"data" => %{"image" => list}})

      true ->
        send_json(conn, %{"errors" => [%{"message" => "unexpected query"}]})
    end
  end

  defp parse_query(body) do
    case Jason.decode(body) do
      {:ok, %{"query" => query}} when is_binary(query) -> query
      _other -> ""
    end
  end

  defp send_json(conn, payload) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, Jason.encode!(payload))
  end

  defp image_json(image, with_vulns) do
    %{
      "id" => image.id,
      "digest" => image.digest,
      "description" => image.description,
      "repository" => image.description |> to_string() |> String.split(":") |> hd(),
      "tag" => "latest",
      "usage" => "runtime",
      "softwareBillOfMaterialCreatedBy" => "syft 1.43.0",
      "usedInNamespaces" => image.namespaces,
      "metrics" => metrics(image),
      "vulnerabilities" =>
        if(with_vulns, do: Enum.map(image.vulnerabilities, &vuln_json/1), else: []),
      "excludedVulnerabilities" =>
        if(with_vulns, do: Enum.map(image.excluded, &vuln_json/1), else: [])
    }
  end

  defp metrics(image) do
    %{
      "status" => "Analyzed",
      "vulnerabilities" => image.claimed,
      "vulnerabilitiesSuppressed" => length(image.excluded),
      "vulnerableComponents" =>
        image.vulnerabilities |> Enum.map(& &1.packageName) |> Enum.uniq() |> length()
    }
  end

  defp vuln_json(vuln) do
    %{
      "vuln" => vuln.vuln,
      "description" => "desc #{vuln.vuln}",
      "fix" => Map.get(vuln, :fix, ""),
      "severity" => vuln.severity,
      "baseSeverity" => vuln.baseSeverity,
      "url" => "https://example.test/#{vuln.vuln}",
      "source" => Map.get(vuln, :source, "nvd:cpe"),
      "packageName" => vuln.packageName,
      "packageVersion" => vuln.packageVersion,
      "packageType" => Map.get(vuln, :packageType, "apk"),
      "packagePath" => "pkg:apk/alpine/#{vuln.packageName}@#{vuln.packageVersion}",
      "packageCpe" => "cpe:2.3:a:#{vuln.packageName}",
      "attributedOn" => Map.get(vuln, :attributedOn, "2026-09-01T00:00:00Z"),
      "extra" => Map.get(vuln, :extra, %{})
    }
  end
end
