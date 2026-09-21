defmodule TriageWeb.LegacyUIEndpoint do
  @moduledoc """
  In-process, test-only HTTP adapter for LegacyUIRouter. It starts no server and
  changes no application endpoint configuration. LiveView tokens use the running
  application endpoint, while their signed router is the isolated legacy map.
  """
  use Plug.Builder

  # VerifiedRoutes uses the test module's @endpoint, while LiveViewTest also
  # signs flash and isolated-mount tokens through it. Delegate to the running
  # endpoint so URL prefixes, static digests and token configuration stay real.
  defdelegate config(key), to: TriageWeb.Endpoint
  defdelegate config(key, default), to: TriageWeb.Endpoint
  defdelegate path(path), to: TriageWeb.Endpoint
  defdelegate url(), to: TriageWeb.Endpoint
  defdelegate script_name(), to: TriageWeb.Endpoint
  defdelegate static_path(path), to: TriageWeb.Endpoint
  defdelegate static_url(), to: TriageWeb.Endpoint
  defdelegate static_integrity(path), to: TriageWeb.Endpoint
  # LiveViewTest uploads join a real channel via the test module's @endpoint.
  defdelegate subscribe(topic), to: TriageWeb.Endpoint
  defdelegate unsubscribe(topic), to: TriageWeb.Endpoint

  plug(:endpoint_context)

  plug(Plug.Static,
    at: "/",
    from: :triage,
    gzip: false,
    only: TriageWeb.static_paths()
  )

  plug(Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Phoenix.json_library()
  )

  plug(Plug.Session,
    store: :cookie,
    key: "_triage_legacy_test_key",
    signing_salt: "legacy-ui-tests"
  )

  plug(TriageWeb.LegacyUIRouter)

  defp endpoint_context(conn, _opts) do
    conn
    |> Map.put(:secret_key_base, TriageWeb.Endpoint.config(:secret_key_base))
    |> Plug.Conn.put_private(:phoenix_endpoint, TriageWeb.Endpoint)
  end
end
