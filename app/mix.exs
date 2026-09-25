defmodule Triage.MixProject do
  use Mix.Project

  def project do
    [
      app: :triage,
      version: "0.1.0",
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      default_release: :triage,
      releases: releases(),
      compilers: [:phoenix_live_view] ++ Mix.compilers(),
      listeners: [Phoenix.CodeReloader],
      # Mix and ExUnit must be in the PLT: without them every `Mix.raise/1`,
      # `Mix.shell/0` and `Mix.Task.run/1` call inside a task, and every
      # `ExUnit.Callbacks`/`ExUnit.CaseTemplate` macro expansion in test/support,
      # is reported as a call to a function that does not exist.
      dialyzer: [plt_add_apps: [:mix, :ex_unit]]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {Triage.Application, []},
      extra_applications: [:logger, :runtime_tools, :xmerl]
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test, ci: :test]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:phoenix, "~> 1.8.13"},
      {:phoenix_ecto, "~> 4.5"},
      {:ecto_sql, "~> 3.13"},
      {:postgrex, ">= 0.0.0"},
      {:phoenix_html, "~> 4.1"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:phoenix_live_view, "~> 1.2.0"},
      {:lazy_html, ">= 0.1.0", only: :test},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_poller, "~> 1.0"},
      {:jason, "~> 1.2"},
      {:dns_cluster, "~> 0.3.0"},
      {:bandit, "~> 1.5"},
      {:req, "~> 0.5"},
      # Temporary immutable pin for upstream PR #230: released 1.6.0 lets the
      # Elixir CLI consume app arguments and halt Phoenix (upstream issue #229).
      {:burrito,
       github: "burrito-elixir/burrito", ref: "f2d437041418abb9073a6d7588d22835a04ee7cb", depth: 1},
      {:oban, "~> 2.19.0"},

      # Compiles assets/css/tailwind.css into the served stylesheet. A build
      # tool only: it ships no runtime code, and `mix assets.setup` drives it.
      {:tailwind, "~> 0.5", runtime: false},

      # Static analysis, development and test only and never part of a release:
      # credo for consistency, dialyxir for the type and pattern analysis that
      # would have caught this codebase's dead-branch defect on its own.
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to install project dependencies and perform other setup tasks, run:
  #
  #     $ mix setup
  #
  # See the documentation for `Mix` for more info on aliases.
  # Database-free runs neither prepare PostgreSQL nor start Triage.Application.
  # test_helper starts just the dependencies, PubSub and a non-listening endpoint.
  defp test_alias do
    if System.get_env("TRIAGE_SKIP_DB_SETUP") in ["1", "true"],
      do: ["assets.setup", "test --no-start --exclude db"],
      else: ["ecto.create --quiet", "ecto.migrate --quiet", "assets.setup", "test"]
  end

  # Keep the ordinary OTP/Docker release as the default. Burrito is opt-in.
  defp releases do
    [
      triage: [],
      triage_burrito: [
        steps: [:assemble, &Burrito.wrap/1],
        burrito: [
          targets: [
            linux_x86_64: [os: :linux, cpu: :x86_64],
            linux_arm64: [os: :linux, cpu: :aarch64],
            macos_x86_64: [os: :darwin, cpu: :x86_64],
            macos_arm64: [os: :darwin, cpu: :aarch64]
          ]
        ]
      ]
    ]
  end

  defp require_production(_args) do
    unless Mix.env() == :prod, do: Mix.raise("Build Burrito with MIX_ENV=prod")
  end

  defp aliases do
    # Only development convenience commands implicitly load synthetic data.
    # Test setup/reset must leave an empty inventory; SQL sandbox rollback
    # cannot hide rows seeded before a test transaction starts.
    seed_tasks = if Mix.env() == :dev, do: ["ecto.seed"], else: []

    [
      setup: ["deps.get", "ecto.setup"] ++ seed_tasks ++ ["assets.setup"],
      burrito: [&require_production/1, "assets.setup", "release triage_burrito --overwrite"],
      "ecto.setup": ["ecto.create", "ecto.migrate"],
      "ecto.seed": ["run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"] ++ seed_tasks,
      test: test_alias(),
      precommit: [
        "compile --warnings-as-errors",
        "deps.unlock --unused",
        "format",
        "assets.setup",
        "test"
      ],
      # The non-mutating counterpart of `precommit`, for CI and for checking a
      # tree without rewriting it: `format` rewrites files and
      # `deps.unlock --unused` edits mix.lock, so neither can be a gate that
      # fails on a dirty tree instead of silently fixing it. It also carries the
      # static analysis — `credo --strict` for consistency and `dialyzer` for
      # the type, pattern and dead-code analysis that found real defects here
      # (a missing error type in a spec, an unreachable clause, and a probe that
      # made a whole request path look dead).
      ci: [
        "compile --warnings-as-errors",
        "format --check-formatted",
        "deps.unlock --check-unused",
        "credo --strict",
        "assets.setup",
        "test",
        "dialyzer"
      ]
    ]
  end
end
