defmodule Triage.IntelTransportTest do
  use ExUnit.Case, async: false

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
      respond(200, Jason.encode!(%{"vulnerabilities" => [entry]}), [
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
