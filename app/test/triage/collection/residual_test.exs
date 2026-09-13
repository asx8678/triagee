defmodule Triage.Collection.ResidualTest do
  use ExUnit.Case, async: false

  alias Triage.Collection
  alias Triage.Collection.{Client, Config, Errors, Preview, Report, Transport}

  defmodule HeaderProbe do
    @behaviour Plug
    import Plug.Conn

    @impl true
    def init(agent), do: agent

    @impl true
    def call(conn, agent) do
      {:ok, _body, conn} = read_body(conn)
      Agent.update(agent, fn _ -> conn.req_headers end)

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(200, Jason.encode!(%{"data" => %{"status" => %{"lastClusterScan" => "x"}}}))
    end
  end

  defp unique(prefix), do: :"#{prefix}_#{System.unique_integer([:positive])}"

  defp free_port! do
    {:ok, socket} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end

  defp base_state do
    %{
      images: [],
      requests: 0,
      current: 0,
      max_concurrent: 0,
      require_auth: false,
      fail_auth_after: nil,
      fail_status: nil,
      graphql_errors: false,
      delay_ms: 0,
      last_cluster_scan: "2026-09-03T12:00:00Z",
      owners_raw: nil,
      inventory_raw: %{},
      detail_raw: %{}
    }
  end

  defp start_source(state \\ %{}) do
    agent =
      start_supervised!({Agent, fn -> Map.merge(base_state(), state) end}, id: unique(:agent))

    port = free_port!()

    start_supervised!(
      {Bandit, plug: {Triage.Collection.FakeSource, agent}, port: port, ip: {127, 0, 0, 1}},
      id: unique(:bandit)
    )

    %{agent: agent, url: "http://127.0.0.1:#{port}/graphql"}
  end

  defp uid(n), do: "00000000-0000-4000-8000-" <> String.pad_leading(to_string(n), 12, "0")

  defp vuln(name, pkg, version, severity) do
    %{
      vuln: name,
      severity: severity,
      baseSeverity: severity,
      packageName: pkg,
      packageVersion: version,
      source: "nvd:cpe",
      fix: nil
    }
  end

  defp image(id, digest, owner, vulns, excluded, claimed) do
    %{
      id: id,
      digest: digest,
      description: "app:1",
      owner: owner,
      namespaces: [%{"id" => "ns-#{owner}", "owner" => owner}],
      vulnerabilities: vulns,
      excluded: excluded,
      claimed: claimed
    }
  end

  defp run(url, overrides \\ []) do
    {run_opts, config_overrides} = Keyword.split(overrides, [:owners, :max_images, :signal])
    base = [endpoint: url, environment: "test"]
    {:ok, config} = Config.new(Keyword.merge(base, config_overrides))
    state = Transport.Req.new(config)

    Collection.run([config: config, transport: {Transport.Req, state}] ++ run_opts)
  end

  test "(1) forged transport headers are rejected and the wire keeps only fixed json headers" do
    agent = start_supervised!({Agent, fn -> [] end}, id: unique(:headers))
    port = free_port!()

    start_supervised!({Bandit, plug: {HeaderProbe, agent}, port: port, ip: {127, 0, 0, 1}},
      id: unique(:probe)
    )

    url = "http://127.0.0.1:#{port}/graphql"
    {:ok, config} = Config.new(endpoint: url, environment: "test")
    state = Transport.Req.new(config)

    forged = %{state | headers: [{"Authorization", "Bearer SYNTHETIC_SECRET"}]}

    assert {:error, %Errors.InvalidOptionsError{}} = Transport.Req.post(forged, "{}", [])
    assert Agent.get(agent, & &1) == []

    assert {:ok, %{status: 200}} =
             Transport.Req.post(
               state,
               Jason.encode!(%{query: "{ status { lastClusterScan } }"}),
               []
             )

    headers = Agent.get(agent, & &1)
    assert Enum.any?(headers, fn {k, v} -> k == "content-type" and v =~ "application/json" end)
    assert Enum.any?(headers, fn {k, v} -> k == "accept" and v =~ "application/json" end)
    refute Enum.any?(headers, fn {k, _v} -> String.downcase(k) == "authorization" end)
  end

  test "(2) a forged transport error state yields a constant sanitized error" do
    {:ok, config} = Config.new(endpoint: "http://127.0.0.1:1/graphql", environment: "test")
    state = Transport.Req.new(config)
    forged = %{state | error: %Errors.DisabledError{message: "token=SYNTHETIC_SECRET"}}

    assert {:error, %Errors.InvalidOptionsError{message: message}} =
             Transport.Req.post(forged, "{}", [])

    assert message == "transport state is invalid"
    refute message =~ "SYNTHETIC_SECRET"
  end

  test "(3) an in-flight request is cancelled rather than awaited" do
    src =
      start_source(%{
        images: [image(uid(1), "digest-a", "team-a", [], [], 0)],
        delay_ms: 2_000
      })

    {:ok, config} =
      Config.new(
        endpoint: src.url,
        environment: "test",
        total_deadline_ms: 10_000,
        request_timeout_ms: 10_000
      )

    state = Transport.Req.new(config)
    {:ok, counter} = Agent.start_link(fn -> 0 end)
    signal = fn -> Agent.get_and_update(counter, fn n -> {n >= 1, n + 1} end) end
    client = Client.new(config, Transport.Req, state, signal: signal)

    {elapsed, result} =
      :timer.tc(fn -> Client.query(client, "{ status { lastClusterScan } }", "status") end)

    assert {:error, %Errors.CancelledError{}} = result
    assert div(elapsed, 1000) < 1_500
  end

  test "(4) a stalling signal never outlives the remaining deadline" do
    src = start_source()
    {:ok, config} = Config.new(endpoint: src.url, environment: "test", total_deadline_ms: 20)
    state = Transport.Req.new(config)

    client =
      Client.new(config, Transport.Req, state,
        signal: fn ->
          Process.sleep(5_000)
          false
        end
      )

    {elapsed, result} =
      :timer.tc(fn -> Client.query(client, "{ status { lastClusterScan } }", "status") end)

    assert match?({:error, %Errors.CancelledError{}}, result) or
             match?({:error, %Errors.RequestBudgetError{}}, result)

    assert div(elapsed, 1000) < 200
  end

  test "(5) an aggregate response-byte budget is enforced at collection time, before decode" do
    vulns = for i <- 1..4, do: vuln("CVE-A#{i}", String.duplicate("p", 40), "1", "LOW")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", vulns, [], 4)]})

    assert {:error, %Errors.ResponseBudgetError{message: message}} =
             run(src.url, max_text_bytes: 10_000, max_total_bytes: 50)

    assert message =~ "aggregate response byte budget"
  end

  test "(5) several individually-small responses still trip the aggregate response cap" do
    images =
      for i <- 1..3 do
        image(uid(i), "digest-#{i}", "team-a", [vuln("CVE-#{i}", "pkg-#{i}", "1", "LOW")], [], 1)
      end

    src = start_source(%{images: images})

    assert {:error, %Errors.ResponseBudgetError{}} =
             run(src.url, max_text_bytes: 10_000, max_total_bytes: 20)

    assert Agent.get(src.agent, & &1.requests) == 1
  end

  test "(6) max_images budgets detail ids, not digests, and never queries a second id at cap 1" do
    wrong = %{
      "id" => uid(2),
      "digest" => "digest-wrong",
      "metrics" => %{"vulnerabilities" => 0},
      "vulnerabilities" => [],
      "excludedVulnerabilities" => [],
      "description" => "app:1"
    }

    src =
      start_source(%{
        images: [
          image(uid(1), "digest-shared", "team-a", [], [], 0),
          image(uid(2), "digest-shared", "team-a", [], [], 0)
        ],
        detail_raw: %{uid(2) => [wrong]}
      })

    assert {:ok, report} = run(src.url, owners: ["team-a"], max_images: 1)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "max_images"))
    refute Enum.any?(report.failures, &String.contains?(&1, "did not match the inventory digest"))
    assert Agent.get(src.agent, & &1.requests) == 3
  end

  test "(7) sanitize_message returns a constant for non-binary input" do
    assert Errors.sanitize_message({:token, "SYNTHETIC_SECRET"}) == "invalid message"
    assert Errors.sanitize_message(%{"token" => "SYNTHETIC_SECRET"}) == "invalid message"
    refute Errors.sanitize_message({:token, "SYNTHETIC_SECRET"}) =~ "SYNTHETIC_SECRET"
  end

  test "(8) reasons are coerced to a closed atom set" do
    assert Errors.safe_reason(:token) == :transport
    assert Errors.safe_reason({:token, "SYNTHETIC_SECRET"}) == :transport
    assert Errors.safe_reason(:timeout) == :timeout
    assert Errors.safe_reason(:status) == :status
  end

  test "(9) an invalid upstream id is never echoed into report failures" do
    broken = %{
      id: "not-a-uuid-SYNTHETIC_SECRET",
      digest: "digest-a",
      description: "app:1",
      owner: "team-a",
      namespaces: [],
      vulnerabilities: [],
      excluded: [],
      claimed: 0
    }

    src = start_source(%{images: [broken]})
    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "malformed image id"))
    refute Enum.any?(report.failures, &String.contains?(&1, "SYNTHETIC_SECRET"))
    refute Enum.any?(report.failures, &String.contains?(&1, "not-a-uuid"))
  end

  test "(10) actionable? is always false and to_snapshot always returns a provenance blocker" do
    report = %Report{
      scope: "full",
      environment: "test",
      engine: "Grype",
      historical_provenance: true,
      blockers: [],
      failures: [],
      incomplete: false
    }

    refute Report.actionable?(report)

    report2 = %{
      report
      | historical_provenance: %{
          "first_seen" => "2026-01-01T00:00:00Z",
          "last_seen" => "2026-01-01T00:00:00Z"
        }
    }

    refute Report.actionable?(report2)
    assert {:error, blockers} = Preview.to_snapshot(report2)
    assert Enum.any?(blockers, &String.contains?(&1, "historical provenance"))
  end

  test "(11) the aggregate budget stops stage one before any detail request" do
    entry = fn digest ->
      %{"id" => uid(1), "digest" => digest, "usedInNamespaces" => []}
    end

    src =
      start_source(%{
        inventory_raw: %{
          "team-a" => [entry.("digest-a")],
          "team-b" => [entry.("digest-b")],
          "team-c" => [entry.("digest-c")]
        }
      })

    marker_body =
      Jason.encode!(%{
        "data" => %{"status" => %{"lastClusterScan" => "2026-09-03T12:00:00Z"}}
      })

    inventory_body = Jason.encode!(%{"data" => %{"image" => [entry.("digest-a")]}})

    # Marker plus two inventories fit; the third inventory response is the one
    # that would exceed the aggregate budget.
    budget = byte_size(marker_body) + 2 * byte_size(inventory_body) + 1

    assert {:error, %Errors.ResponseBudgetError{message: message}} =
             run(src.url,
               owners: ["team-a", "team-b", "team-c"],
               max_total_bytes: budget
             )

    assert message =~ "aggregate"
    # Marker + three inventory list requests; stage two (detail) never ran.
    assert Agent.get(src.agent, & &1.requests) == 4
  end

  test "(12) concurrent detail responses cannot overshoot the aggregate reservation" do
    entries =
      for i <- 1..4 do
        %{"id" => uid(i), "digest" => "digest-#{i}", "usedInNamespaces" => []}
      end

    src = start_source(%{inventory_raw: %{"team-a" => entries}, delay_ms: 50})

    marker_body =
      Jason.encode!(%{
        "data" => %{"status" => %{"lastClusterScan" => "2026-09-03T12:00:00Z"}}
      })

    inventory_body = Jason.encode!(%{"data" => %{"image" => entries}})

    # Allows the marker and inventory reads, but not a single detail response.
    budget = byte_size(marker_body) + byte_size(inventory_body) + 1

    assert {:error, %Errors.ResponseBudgetError{}} =
             run(src.url, owners: ["team-a"], concurrency: 4, max_total_bytes: budget)

    # Marker + inventory + four concurrent detail requests.
    assert Agent.get(src.agent, & &1.requests) == 6
    assert Agent.get(src.agent, & &1.max_concurrent) >= 2
  end

  test "(13) malformed Client.new/query inputs are controlled with zero requests" do
    src = start_source()

    {:ok, config} = Config.new(endpoint: src.url, environment: "test")
    state = Transport.Req.new(config)
    good = Client.new(config, Transport.Req, state, [])

    malformed_new = [
      Client.new(config, Transport.Req, state, :not_a_keyword),
      Client.new(config, Transport.Req, state, %{signal: :not_a_function}),
      Client.new(config, Transport.Req, state, signal: fn value -> value end)
    ]

    forged_state = [
      %{good | counter: make_ref()},
      %{good | budget: :not_atomics},
      %{good | budget: :atomics.new(1, signed: false)},
      %{good | config: %{}},
      %{good | transport_state: %{}}
    ]

    for client <- malformed_new ++ forged_state do
      assert {:error, %{message: message}} =
               Client.query(client, "{ status { lastClusterScan } }", "status")

      assert is_binary(message)
    end

    forged_error = %{good | error: %RuntimeError{message: "token=SYNTHETIC_SECRET"}}

    assert {:error, %Errors.TransportError{} = error} =
             Client.query(forged_error, "{ status { lastClusterScan } }", "status")

    refute error.message =~ "SYNTHETIC_SECRET"

    assert {:error, %Errors.InvalidOptionsError{}} =
             Client.query(:not_a_client, "{ status { lastClusterScan } }", "status")

    assert Agent.get(src.agent, & &1.requests) == 0
  end
end
