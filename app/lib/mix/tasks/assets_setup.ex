defmodule Mix.Tasks.Assets.Setup do
  @shortdoc "Copies the pinned Phoenix client scripts into priv/static/assets/vendor"

  @moduledoc """
  Copies the shipped browser distributions of the mix.lock-pinned Hex packages
  `:phoenix`, `:phoenix_html` and `:phoenix_live_view` into
  `priv/static/assets/vendor/`, where the root layout loads them as
  same-origin scripts before the `assets/js/app.js` LiveSocket bootstrap.

  The generated vendor directory is git-ignored output; this task makes it
  reproducible from a clean checkout and is wired into the `mix setup`,
  `mix test` and `mix precommit` aliases. It is idempotent — re-run any time:

      mix assets.setup

  It requires `mix deps.get` to have run first (as `mix setup` does).
  """

  use Mix.Task

  @vendor_files [
    {:phoenix, "phoenix.js"},
    {:phoenix_html, "phoenix_html.js"},
    {:phoenix_live_view, "phoenix_live_view.js"}
  ]

  @impl Mix.Task
  def run(_args) do
    deps_path = Mix.Project.config()[:deps_path] || "deps"
    dest_dir = Path.join([File.cwd!(), "priv", "static", "assets", "vendor"])
    File.mkdir_p!(dest_dir)

    for {dep, file} <- @vendor_files do
      source = Path.join([deps_path, to_string(dep), "priv", "static", file])

      unless File.exists?(source) do
        Mix.raise(
          "Missing Phoenix client asset #{source} for the pinned #{inspect(dep)} dep. " <>
            "Run `mix deps.get` first (or `mix setup`)."
        )
      end

      dest = Path.join(dest_dir, file)
      File.cp!(source, dest)
      Mix.shell().info("Copied #{source} -> #{dest}")
    end

    :ok
  end
end
