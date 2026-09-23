defmodule Triage.IntelTransportTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Triage.Intel.Client

  setup do
    previous_intel = Application.get_env(:triage, :intel)
    previous_req = Req.default_options()
    Application.put_env(:triage, :intel, enabled: true, sources: [:kev, :nvd])

    on_exit(fn ->
      Req.default_options(previous_req)

      if previous_intel,
        do: Application.put_env(:triage, :intel, previous_intel),
        else: Application.delete_env(:triage, :intel)
    end)
  end

  # A KEV body that satisfies the catalogue contract (declared count matches),
  # so transport-limit tests exercise the parse path production uses.
  defp kev_cap_body do
    Jason.encode!(%{
      "vulnerabilities" => [%{"cveID" => "CVE-2026-1001", "dateAdded" => "2026-01-02"}],
      "count" => 1
    })
  end

  test "runtime cap is used for real Req streaming and final admission, with a safe diagnostic" do
    body = kev_cap_body()
    max = byte_size(body)
    Application.put_env(:triage, :intel, enabled: true, max_response_bytes: max)
    respond(200, body)
    assert {:ok, [%{external_id: "CVE-2026-1001"}]} = Client.fetch(:kev)
    assert_received {:request, request}

    initial = {request, Req.Response.new(body: "")}
    assert {:cont, state} = request.into.({:data, body}, initial)
    assert {:halt, {_request, response}} = request.into.({:data, "private-secret"}, state)
    assert response.body == :triage_response_too_large
    respond(200, response.body)

    log =
      capture_log(fn ->
        assert Client.fetch(:kev) == {:error, {:response_too_large, max}}
      end)

    assert log =~ "source=kev max_bytes=#{max}"
    refute log =~ "private-secret"

    Application.put_env(:triage, :intel, enabled: true, max_response_bytes: max - 1)
    respond(200, body)
    assert Client.fetch(:kev) == {:error, {:response_too_large, max - 1}}
    Application.put_env(:triage, :intel, enabled: true, max_response_bytes: max + 1)
    assert {:ok, [%{external_id: "CVE-2026-1001"}]} = Client.fetch(:kev)
  end

  test "injected bodies use the same cap and it cannot change during a fetch" do
    body = kev_cap_body()
    max = byte_size(body)
    Application.put_env(:triage, :intel, max_response_bytes: max)

    changing = %{
      req: fn _ ->
        Application.put_env(:triage, :intel, max_response_bytes: max - 1)
        {:ok, body}
      end
    }

    assert {:ok, [%{external_id: "CVE-2026-1001"}]} = Client.fetch(:kev, changing)

    assert Client.fetch(:kev, %{req: fn _ -> {:ok, body} end}) ==
             {:error, {:response_too_large, max - 1}}

    log =
      capture_log(fn ->
        assert Client.fetch({:nvd, "CVE-2024-3094"}, %{req: fn _ -> {:ok, body} end}) ==
                 {:error, {:response_too_large, max - 1}}
      end)

    assert log =~ "source=nvd max_bytes=#{max - 1}"
  end

  test "invalid limits and malformed transports make zero requests" do
    transport = %{req: fn _ -> flunk("invalid limit reached transport") end}

    for bad <- [0, -1, nil, "8", :infinity] do
      Application.put_env(:triage, :intel, enabled: true, max_response_bytes: bad)
      assert Client.fetch(:kev, transport) == {:error, {:invalid_config, :max_response_bytes}}
      assert Client.fetch(:kev) == {:error, {:invalid_config, :max_response_bytes}}
    end

    Application.put_env(:triage, :intel, enabled: true)

    for bad <- [nil, false, %{}] do
      assert Client.fetch(:kev, bad) == {:error, :no_transport}
    end

    refute_received {:request, _}
  end

  # Exercise the real Req pipeline and its options, without any socket/network.
  defp respond(status, body, headers \\ []) do
    Process.put(
      {__MODULE__, :response},
      Req.Response.new(status: status, body: body, headers: headers)
    )

    Req.default_options(adapter: __MODULE__)
  end

  @doc false
  def run(request) do
    send(self(), {:request, request})
    {request, Process.get({__MODULE__, :response})}
  end

  test "real Req requests preserve the allowlisted URL and explicit safety options" do
    for {kind, url, entry} <- [
          {:kev, Client.kev_url(), %{"cveID" => "CVE-2024-3094"}},
          {{:nvd, "CVE-2024-3094"}, Client.nvd_url() <> "?cveId=CVE-2024-3094",
           %{"cve" => %{"id" => "CVE-2024-3094"}}}
        ] do
      respond(200, Jason.encode!(%{"vulnerabilities" => [entry], "count" => 1}), [
        {"content-type", "application/json"}
      ])

      assert {:ok, [%{external_id: "CVE-2024-3094"}]} = Client.fetch(kind)
      assert_received {:request, request}
      assert URI.to_string(request.url) == url
      assert request.options.redirect == false
      assert request.options.retry == false
      assert request.options.decode_body == false
      assert request.options.receive_timeout == 20_000
      assert request.options.connect_options[:timeout] == 20_000
    end
  end

  test "real Req redirects are refused once without following Location" do
    respond(302, "not JSON", [{"location", "https://untrusted.invalid/redirect"}])
    assert Client.fetch(:kev) == {:error, {:redirect_refused, 302}}
    assert_received {:request, _}
    refute_received {:request, _}
  end

  test "real Req status and size failures use the same normalization as injected transports" do
    respond(503, "private error body")
    assert Client.fetch(:kev) == {:error, {:http_status, 503}}
    assert_received {:request, _}
    refute_received {:request, _}

    respond(200, :binary.copy("x", 8_000_001))
    assert Client.fetch(:kev) == {:error, {:response_too_large, 8_000_000}}
  end
end
