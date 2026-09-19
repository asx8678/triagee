defmodule TriageWeb.AssetsTest do
  @moduledoc """
  Narrow wiring tests for the shipped browser client: the root layout must
  load the generated Tailwind stylesheet before the application stylesheet,
  the build behind that stylesheet must show repeat-build determinism when
  Mix.Task.rerun rebuilds over existing output (not from-scratch generation),
  and the layout must load the Phoenix / LiveView client
  distributions and the LiveSocket bootstrap as same-origin scripts (in
  order, with a CSRF token). The endpoint must actually serve all of it.
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
  @tailwind_source "assets/css/tailwind.css"
  @tailwind_output "priv/static/assets/css/tailwind.css"
  @application_stylesheet "priv/static/assets/css/app.css"

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

  # The stylesheet pair and the build behind it. The generated Tailwind output
  # is git-ignored output ("regenerate with mix assets.setup"), so these
  # assertions are about the wiring, the scan and the served bytes - not about
  # committing a build artifact.
  describe "stylesheet wiring" do
    test "loads only Tailwind and the workspace theme at both entry points" do
      hrefs =
        build_conn()
        |> get("/")
        |> html_response(200)
        |> LazyHTML.from_fragment()
        |> LazyHTML.filter("link[rel=stylesheet]")
        |> Enum.flat_map(&LazyHTML.attribute(&1, "href"))

      # The retired theme is never loaded into the single workspace.
      assert hrefs == [
               "/assets/css/tailwind.css",
               "/assets/css/workspace.css"
             ]

      workspace_hrefs =
        build_conn()
        |> get("/workspace")
        |> html_response(200)
        |> LazyHTML.from_fragment()
        |> LazyHTML.filter("link[rel=stylesheet]")
        |> Enum.flat_map(&LazyHTML.attribute(&1, "href"))

      assert workspace_hrefs == ["/assets/css/tailwind.css", "/assets/css/workspace.css"]
      workspace_css = response(get(build_conn(), "/assets/css/workspace.css"), 200)
      refute workspace_css =~ "-:scope"

      for selector <- [
            ".panel-body{",
            ".inspector-body{",
            ".modal-body{",
            "dialog.confirm { margin:auto; }"
          ] do
        assert workspace_css =~ selector
      end

      # both are same-origin: no CDN, no bundler output
      assert Enum.all?(hrefs, &String.starts_with?(&1, "/"))
    end

    test "the generated stylesheet is what the current sources compile to" do
      assert File.exists?(@tailwind_output), "run `mix assets.setup` first"
      built = File.read!(@tailwind_output)

      # Mix.Task.rerun rebuilds over the existing output: this checks
      # repeat-build determinism, not from-scratch generation.
      Mix.Task.rerun("tailwind", ["triage"])

      assert File.read!(@tailwind_output) == built,
             "the rebuild over the existing output changed bytes: " <>
               "priv/static/assets/css/tailwind.css is not byte-stable"
    end

    test "the CLI version and profile are pinned to the tracked source and output" do
      version = Application.fetch_env!(:tailwind, :version)
      assert is_binary(version) and version =~ ~r/^4\.\d+\.\d+$/

      profile = Application.fetch_env!(:tailwind, :triage)
      args = Keyword.fetch!(profile, :args)
      assets = Path.expand("assets")

      assert Path.expand(Keyword.fetch!(profile, :cd)) == assets
      assert "--input=#{Path.relative_to(Path.expand(@tailwind_source), assets)}" in args
      assert "--output=../#{@tailwind_output}" in args
    end

    test "the development watcher rebuilds the same profile" do
      # Configuration-level check only: the watcher is not started by the test
      # run, so this proves the wiring and not a live rebuild.
      dev =
        "config/dev.exs"
        |> File.read!()
        |> String.split("\n")
        |> Enum.reject(&Regex.match?(~r/^\s*#/, &1))
        |> Enum.join("\n")

      assert dev =~
               ~r/watchers:\s*\[\s*tailwind:\s*\{Tailwind,\s*:install_and_run,\s*\[:triage,\s*~w\(--watch\)\]\}/,
             "no dev rebuild when the source changes: wire the :triage Tailwind profile with --watch"
    end

    test "the source entrypoint scans lib/ and nothing else" do
      source = File.read!(@tailwind_source)

      # Comments are stripped first: a directive named in prose, or one that
      # has been commented out, must not count as live.
      live = Regex.replace(~r{/\*.*?\*/}s, source, "")

      # source(none) turns off Tailwind's automatic project-wide scan, so the
      # candidate set cannot silently grow to deps/, _build/ or the notes.
      assert live =~ ~s{@import "tailwindcss" source(none)}

      # Exactly one @source, and it points at lib/. Adding a second one
      # (deps/, _build/, the evidence notes) fails here instead of silently
      # widening the scan.
      assert Regex.scan(~r/@source\b[^;]*;/, live) == [[~s{@source "../../lib";}]]
    end

    test "serves the generated utilities, the theme bridge and the application stylesheet" do
      tailwind = response(get(build_conn(), "/assets/css/tailwind.css"), 200)
      version = Application.fetch_env!(:tailwind, :version)
      assert String.starts_with?(tailwind, "/*! tailwindcss v#{version} |")
      # @theme bridges the two scale names the generated components carry
      assert tailwind =~ "--color-error: #a02222"
      assert tailwind =~ "--color-base-content: #182539"
      # utilities a component actually passes are emitted, so the @source scan
      # really ran: size-5 on the validation icon, w-full on the controls
      assert tailwind =~ ".size-5 {"
      assert tailwind =~ ".w-full {"
      # the served bytes are the file: not a cached or transformed variant
      assert tailwind == File.read!(@tailwind_output)

      application = response(get(build_conn(), "/assets/css/app.css"), 200)
      assert application =~ ".triage-nav"
      assert application == File.read!(@application_stylesheet)
    end

    test "serves artwork for literal icon names in lib sources" do
      # Scans literal name="hero-..." occurrences, including @doc examples.
      # Dynamically supplied icon names are not covered by this check.
      css = File.read!(@tailwind_output) <> File.read!(@application_stylesheet)

      icons =
        "lib/**/*.{ex,heex,eex}"
        |> Path.wildcard()
        |> Enum.flat_map(fn path ->
          ~r/name="(hero-[a-z0-9-]+)"/
          |> Regex.scan(File.read!(path), capture: :all_but_first)
          |> List.flatten()
        end)
        |> Enum.uniq()

      # Literal icon names exist in the sources; an empty match must not pass
      refute icons == []

      # Comments are stripped so a selector named in prose cannot satisfy the
      # check, and the artwork itself is required, not just the name: the
      # shared rule that lists all three icons carries no mask-image, so
      # deleting a per-icon rule has to fail here.
      live = Regex.replace(~r{/\*.*?\*/}s, css, "")

      for icon <- icons do
        assert Regex.match?(
                 ~r/.#{Regex.escape(icon)}\s*\{[^}]*\bmask-image:\s*url\(['"]?data:image\/svg\+xml;/s,
                 live
               ),
               "CoreComponents.icon/1 renders #{icon} but no stylesheet rule draws it"
      end
    end
  end
end
