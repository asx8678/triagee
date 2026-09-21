defmodule TriageWeb.LegacyUIEndpointTest do
  # This exercises the harness itself without a sandbox or database fixtures.
  use ExUnit.Case, async: true
  use TriageWeb, :verified_routes

  import Phoenix.ConnTest
  import Phoenix.LiveViewTest

  alias TriageWeb.{Endpoint, LegacyUIEndpoint}

  @endpoint LegacyUIEndpoint

  test "URL, static and configuration helpers delegate to the running endpoint" do
    Code.ensure_loaded!(LegacyUIEndpoint)

    for {function, args} <- [
          {:config, [:live_view]},
          {:config, [:secret_key_base]},
          {:config, [:otp_app]},
          {:config, [:legacy_missing_key, :fallback]},
          {:path, ["/imports?source=legacy"]},
          {:url, []},
          {:script_name, []},
          {:static_path, ["/assets/examples/replay.json"]},
          {:static_url, []},
          {:static_integrity, ["/assets/examples/replay.json"]}
        ] do
      assert function_exported?(LegacyUIEndpoint, function, length(args))
      assert apply(LegacyUIEndpoint, function, args) == apply(Endpoint, function, args)
    end

    assert ~p"/imports" == Endpoint.path("/imports")
  end

  test "routed LiveView connects, uploads and rejects malformed JSON before database access" do
    conn = get(build_conn(), ~p"/imports")
    assert conn.private.phoenix_endpoint == Endpoint
    assert conn.private.phoenix_router == TriageWeb.LegacyUIRouter

    {:ok, view, _html} = live(conn)
    assert view.module == TriageWeb.ImportLive
    assert view.endpoint == Endpoint
    assert has_element?(view, "#import-upload-form")

    # A valid preview reads inventory. Malformed JSON still exercises the real
    # upload channel and consumption, but is rejected before any Repo call.
    json = "{invalid snapshot JSON"

    view
    |> file_input("#import-upload-form", :snapshot, [
      %{name: "preview.json", content: json, type: "application/json"}
    ])
    |> render_upload("preview.json")

    view |> form("#import-upload-form") |> render_submit()
    assert has_element?(view, "#import-error")
    refute has_element?(view, "#import-receipt")
    refute has_element?(view, "#import-preview-result")
  end

  test "isolated LiveView connects with the adapter endpoint and real token configuration" do
    {:ok, view, _html} = live_isolated(build_conn(), TriageWeb.ImportLive)
    assert view.endpoint == LegacyUIEndpoint
    assert has_element?(view, "#import-upload-form")
    view |> form("#import-upload-form") |> render_submit()
    assert has_element?(view, "#import-error")
  end

  test "LiveView flash tokens are compatible with the application endpoint" do
    flash = %{"info" => "Legacy navigation"}
    token = Phoenix.LiveView.Utils.sign_flash(LegacyUIEndpoint, flash)
    assert Phoenix.LiveView.Utils.verify_flash(Endpoint, token) == flash
    token = Phoenix.LiveView.Utils.sign_flash(Endpoint, flash)
    assert Phoenix.LiveView.Utils.verify_flash(LegacyUIEndpoint, token) == flash
  end

  test "replay download is served as a static fixture rather than sent to the router" do
    conn = get(build_conn(), "/assets/examples/replay.json")
    assert response(conn, 200) == File.read!("priv/static/assets/examples/replay.json")
    assert conn.halted
    refute Map.has_key?(conn.private, :phoenix_router)
  end
end
