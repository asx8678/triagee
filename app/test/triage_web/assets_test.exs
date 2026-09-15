defmodule TriageWeb.AssetsTest do
  @moduledoc """
  Narrow wiring tests for the shipped browser client bootstrap:
  the root layout must load the Phoenix / LiveView client distributions
  and the LiveSocket bootstrap as same-origin scripts (in order, with a
  CSRF token), and the endpoint must actually serve those files.
  """

  # Regenerating the shared vendor files on disk is not safe to run
  # concurrently with the tests that fetch them, so this case stays
  # synchronous (async tests from other modules must not interleave).
  use TriageWeb.ConnCase, async: false

  @vendor_scripts [
    "/assets/vendor/phoenix.js",
    "/assets/vendor/phoenix_html.js",
    "/assets/vendor/phoenix_live_view.js"
  ]
  @bootstrap_script "/assets/js/app.js"

  describe "asset generation" do
    test "mix assets.setup regenerates vendor files from the pinned deps" do
      Mix.Tasks.Assets.Setup.run([])

      for {dep, file} <- [
            {:phoenix, "phoenix.js"},
            {:phoenix_html, "phoenix_html.js"},
            {:phoenix_live_view, "phoenix_live_view.js"}
          ] do
        source = Path.join(["deps", to_string(dep), "priv", "static", file])
        dest = Path.join(["priv", "static", "assets", "vendor", file])

        assert File.exists?(source), "pinned dist missing for #{inspect(dep)}"
        assert File.exists?(dest)
        assert File.read!(dest) == File.read!(source)
      end
    end
  end

  describe "shipped stylesheet" do
    # A lone filter control used to stretch across the page because the whole
    # filter row flex-grows, so one short select rendered 100% wide. There is no
    # browser in this suite to measure a rendered width, so the guard pins the
    # rule that caps it.
    test "caps a filter fieldset so one select cannot span the page" do
      css = File.read!("priv/static/assets/css/app.css")

      [_, rule] =
        Regex.run(~r/\.filter-toolbar > \.fieldset[^{]*\{([^}]*)\}/, css)

      assert rule =~ "max-width: 24rem"

      # The free-text search is the one control allowed the extra room.
      assert css =~
               ~r/\.filter-toolbar \.fieldset:has\(input\[type="search"\]\) \{[^}]*max-width: none/
    end
  end

  describe "root layout script wiring" do
    test "renders the CSRF meta tag used by the LiveSocket bootstrap" do
      csrf_tags =
        build_conn()
        |> get("/")
        |> html_response(200)
        |> LazyHTML.from_fragment()
        |> LazyHTML.filter(~s(meta[name="csrf-token"]))
        |> Enum.to_list()

      assert [csrf_tag] = csrf_tags
      assert [token] = LazyHTML.attribute(csrf_tag, "content")
      assert is_binary(token) and token != ""
    end

    test "loads Phoenix client scripts and the bootstrap as same-origin scripts, in order" do
      srcs =
        build_conn()
        |> get("/")
        |> html_response(200)
        |> LazyHTML.from_fragment()
        |> LazyHTML.filter("script[src]")
        |> Enum.flat_map(&LazyHTML.attribute(&1, "src"))

      # document order matters: the vendor clients load before the bootstrap
      assert srcs == @vendor_scripts ++ [@bootstrap_script]

      # every script is same-origin; no remote/CDN sources
      assert Enum.all?(srcs, &String.starts_with?(&1, "/"))
    end
  end

  describe "served client files" do
    test "endpoint serves the pinned Phoenix distribution defining the Phoenix global" do
      conn = get(build_conn(), "/assets/vendor/phoenix.js")
      assert response(conn, 200) =~ "var Phoenix"
    end

    test "endpoint serves the pinned Phoenix HTML support script" do
      conn = get(build_conn(), "/assets/vendor/phoenix_html.js")
      assert response(conn, 200) =~ "phoenix.link.click"
    end

    test "endpoint serves the pinned LiveView distribution exporting LiveSocket" do
      conn = get(build_conn(), "/assets/vendor/phoenix_live_view.js")
      body = response(conn, 200)

      assert body =~ "var LiveView"
      assert body =~ "LiveSocket:"
      # the global LiveView dist is built against the Phoenix global
      assert body =~ "Phoenix."
    end

    test "endpoint serves the LiveSocket bootstrap wired to /live and the csrf meta" do
      body = response(get(build_conn(), "/assets/js/app.js"), 200)

      assert body =~ "LiveView.LiveSocket"
      assert body =~ ~s|"/live"|
      assert body =~ "Phoenix.Socket"
      assert body =~ "csrf-token"
      assert body =~ "_csrf_token"
      assert body =~ "liveSocket.connect()"
    end
  end
end
