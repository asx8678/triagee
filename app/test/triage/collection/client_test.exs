defmodule Triage.Collection.ClientTest do
  use ExUnit.Case, async: false

  alias Triage.Collection.{Client, Config, Transport}
  alias Triage.Collection.Errors

  defmodule InjectedTransport do
    def post(_state, _body, opts) do
      case Application.get_env(:triage_collection_test, :injected_response) do
        nil ->
          {:ok, %{status: 200, headers: %{}, body: Jason.encode!(%{"data" => %{"ok" => true}})}}

        response ->
          response.(opts)
      end
    end
  end

  defp start_source(state \\ %{}) do
    base = %{
      images: [],
      requests: 0,
      current: 0,
      max_concurrent: 0,
      require_auth: false,
      fail_auth_after: nil,
      fail_status: nil,
      graphql_errors: false,
      delay_ms: 0,
      last_cluster_scan: "2026-09-03T12:00:00Z"
    }

    agent = start_supervised!({Agent, fn -> Map.merge(base, state) end}, id: unique(:agent))
    port = free_port!()

    start_supervised!(
      {Bandit, plug: {Triage.Collection.FakeSource, agent}, port: port, ip: {127, 0, 0, 1}},
      id: unique(:bandit)
    )

    %{agent: agent, url: "http://127.0.0.1:#{port}/graphql"}
  end

  defp unique(prefix), do: :"#{prefix}_#{System.unique_integer([:positive])}"

  defp free_port! do
    {:ok, socket} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end

  defp client(url, overrides \\ []) do
    cfg_opts =
      Keyword.merge([endpoint: url, environment: "test"], overrides)

    {:ok, config} = Config.new(cfg_opts)
    state = Transport.Req.new(config)
    {Client.new(config, Transport.Req, state, []), config}
  end

  defp requests(agent), do: Agent.get(agent, & &1.requests)

  test "a 302 auth redirect is terminal and is never followed" do
    %{agent: agent, url: url} = start_source(%{require_auth: true})
    {client, _config} = client(url)

    assert {:error, %Errors.RedirectError{}} =
             Client.query(client, "{ status { lastClusterScan } }", "status")

    assert requests(agent) == 1
  end

  test "301/302/307 are terminal redirects without retry" do
    %{agent: agent, url: url} = start_source(%{fail_status: 307})
    {client, _config} = client(url, max_retries: 3)

    assert {:error, %Errors.RedirectError{status: 307}} =
             Client.query(client, "{ status { lastClusterScan } }", "status")

    assert requests(agent) == 1
  end

  test "401 and 403 are terminal auth failures" do
    for status <- [401, 403] do
      %{agent: agent, url: url} = start_source(%{fail_status: status})
      {client, _config} = client(url, max_retries: 3)

      assert {:error, %Errors.AuthError{status: ^status}} =
               Client.query(client, "{ status { lastClusterScan } }", "status")

      assert requests(agent) == 1
    end
  end

  test "retryable statuses are bounded retries then a sanitized terminal error" do
    %{agent: agent, url: url} = start_source(%{fail_status: 503})
    {client, _config} = client(url, max_retries: 2, request_timeout_ms: 1_000)

    assert {:error, %Errors.TransportError{}} =
             Client.query(client, "{ status { lastClusterScan } }", "status")

    # 1 initial + 2 retries
    assert requests(agent) == 3
  end

  test "GraphQL error objects are terminal and not retried" do
    %{agent: agent, url: url} = start_source(%{graphql_errors: true})
    {client, _config} = client(url, max_retries: 3)

    assert {:error, %Errors.GraphQLError{}} =
             Client.query(client, "{ status { lastClusterScan } }", "status")

    assert requests(agent) == 1
  end

  test "a returned body over the byte budget is rejected even from an injected transport" do
    {:ok, config} =
      Config.new(
        endpoint: "http://127.0.0.1:1/graphql",
        environment: "test",
        max_response_bytes: 100
      )

    client = Client.new(config, InjectedTransport, :state, [])

    Application.put_env(:triage_collection_test, :injected_response, fn _opts ->
      body = Jason.encode!(%{"data" => %{"large" => String.duplicate("x", 1_000)}})
      {:ok, %{status: 200, headers: %{}, body: body}}
    end)

    on_exit(fn -> Application.delete_env(:triage_collection_test, :injected_response) end)

    assert {:error, %Errors.ResponseBudgetError{}} =
             Client.query(client, "{ x }", "injected")
  end

  test "a payload deeper than the depth budget is rejected client-side" do
    {:ok, config} =
      Config.new(
        endpoint: "http://127.0.0.1:1/graphql",
        environment: "test",
        max_payload_depth: 2
      )

    client = Client.new(config, InjectedTransport, :state, [])

    deep = %{"a" => %{"b" => %{"c" => %{"d" => 1}}}}

    Application.put_env(:triage_collection_test, :injected_response, fn _opts ->
      {:ok, %{status: 200, headers: %{}, body: Jason.encode!(%{"data" => deep})}}
    end)

    on_exit(fn -> Application.delete_env(:triage_collection_test, :injected_response) end)

    assert {:error, %Errors.ResponseBudgetError{}} = Client.query(client, "{ x }", "injected")
  end

  test "raw transport reasons and credentials never leak into errors" do
    {:ok, config} = Config.new(endpoint: "http://127.0.0.1:1/graphql", environment: "test")
    client = Client.new(config, InjectedTransport, :state, [])

    Application.put_env(:triage_collection_test, :injected_response, fn _opts ->
      {:error, {:token, "SYNTHETIC_SECRET"}}
    end)

    on_exit(fn -> Application.delete_env(:triage_collection_test, :injected_response) end)

    assert {:error, %Errors.TransportError{} = error} = Client.query(client, "{ x }", "injected")
    refute error.message =~ "SYNTHETIC_SECRET"
    refute inspect(error.reason) =~ "SYNTHETIC_SECRET"
    assert error.reason == :transport
  end

  test "an injected error struct message is sanitized" do
    {:ok, config} = Config.new(endpoint: "http://127.0.0.1:1/graphql", environment: "test")
    client = Client.new(config, InjectedTransport, :state, [])

    Application.put_env(:triage_collection_test, :injected_response, fn _opts ->
      {:error,
       %Errors.GraphQLError{message: "token=SYNTHETIC_SECRET Authorization: Bearer ABC123"}}
    end)

    on_exit(fn -> Application.delete_env(:triage_collection_test, :injected_response) end)

    assert {:error, %Errors.GraphQLError{} = error} = Client.query(client, "{ x }", "injected")
    refute error.message =~ "SYNTHETIC_SECRET"
    refute error.message =~ "ABC123"
  end

  test "a response larger than the byte budget is rejected by the transport before decode" do
    big = String.duplicate("x", 200_000)

    %{agent: agent, url: url} =
      start_source(%{
        images: [image("img-1", "digest-a", "team-a", [], [], 0, big)],
        graphql_errors: false
      })

    {client, _config} = client(url, max_response_bytes: 1_000, max_retries: 0)

    assert {:error, %Errors.ResponseBudgetError{}} =
             Client.query(client, Triage.Collection.Query.image_list_query("team-a"), "images")

    assert requests(agent) == 1
  end

  test "cancellation is terminal and bounded" do
    %{agent: agent, url: url} = start_source()
    {:ok, config} = Config.new(endpoint: url, environment: "test")
    state = Transport.Req.new(config)
    client = Client.new(config, Transport.Req, state, signal: fn -> true end)

    assert {:error, %Errors.CancelledError{}} =
             Client.query(client, "{ status { lastClusterScan } }", "status")

    assert requests(agent) == 0
  end

  test "cancellation interrupts a retry wait instead of sleeping through it" do
    %{agent: agent, url: url} = start_source(%{fail_status: 503})

    {:ok, config} =
      Config.new(endpoint: url, environment: "test", max_retries: 3, request_timeout_ms: 1_000)

    state = Transport.Req.new(config)
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    client =
      Client.new(config, Transport.Req, state,
        signal: fn ->
          n = Agent.get_and_update(counter, fn n -> {n >= 2, n + 1} end)
          n
        end
      )

    assert {:error, %Errors.CancelledError{}} =
             Client.query(client, "{ status { lastClusterScan } }", "status")

    # One request was admitted, then the retry wait was interrupted.
    assert requests(agent) == 1
  end

  test "a stalling signal callback cannot stall past the outer deadline" do
    %{url: url} = start_source()
    {:ok, config} = Config.new(endpoint: url, environment: "test", total_deadline_ms: 150)
    state = Transport.Req.new(config)

    client =
      Client.new(config, Transport.Req, state,
        signal: fn ->
          Process.sleep(5_000)
          false
        end
      )

    assert {:error, error} = Client.query(client, "{ status { lastClusterScan } }", "status")
    assert match?(%Errors.CancelledError{}, error) or match?(%Errors.RequestBudgetError{}, error)
  end

  test "a crashing signal callback is isolated and does not leak into the caller" do
    %{agent: agent, url: url} = start_source()
    {:ok, config} = Config.new(endpoint: url, environment: "test")
    state = Transport.Req.new(config)

    client =
      Client.new(config, Transport.Req, state, signal: fn -> raise "boom SYNTHETIC_SECRET" end)

    # The callback message is never echoed; an unproven signal fails safe.
    assert {:error, %Errors.CancelledError{}} =
             Client.query(client, "{ status { lastClusterScan } }", "status")

    assert requests(agent) == 0
  end

  test "a slow response times out and is retried within the deadline" do
    %{agent: agent, url: url} = start_source(%{delay_ms: 400})
    {client, _config} = client(url, request_timeout_ms: 50, max_retries: 1)

    assert {:error, %Errors.TransportError{}} =
             Client.query(client, "{ status { lastClusterScan } }", "status")

    assert requests(agent) == 2
  end

  test "a tiny deadline bounds retries and backoff" do
    %{agent: agent, url: url} = start_source(%{fail_status: 503})

    {client, _config} =
      client(url, request_timeout_ms: 1_000, max_retries: 3, total_deadline_ms: 20)

    assert {:error, %Errors.RequestBudgetError{}} =
             Client.query(client, "{ status { lastClusterScan } }", "status")

    # The budget is what stops this, so no retry is ever issued: at most the first
    # attempt. It is an upper bound because a 20 ms deadline can expire under load
    # before the first attempt is even handed to the transport.
    assert requests(agent) <= 1
  end

  defp image(id, digest, owner, vulns, excluded, claimed, description) do
    %{
      id: id,
      digest: digest,
      description: description,
      owner: owner,
      namespaces: [%{"id" => "ns-#{owner}", "owner" => owner}],
      vulnerabilities: vulns,
      excluded: excluded,
      claimed: claimed
    }
  end
end
