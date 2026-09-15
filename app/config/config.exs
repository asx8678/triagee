# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :triage,
  ecto_repos: [Triage.Repo],
  generators: [timestamp_type: :utc_datetime]

# Public vulnerability-intelligence cache/refresh policy.
# Disabled by default; the manual mix task refuses to fetch without an
# explicit `sources` allowlist and operational approval.
config :triage, :intel,
  enabled: false,
  sources: []

# Configure the endpoint
config :triage, TriageWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: TriageWeb.ErrorHTML, json: TriageWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Triage.PubSub,
  live_view: [signing_salt: "W0nEQma5"]

# Configure LiveView
config :phoenix_live_view,
  # the attribute set on all root tags. Used for Phoenix.LiveView.ColocatedCSS.
  root_tag_attribute: "phx-r"

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Compile Tailwind CSS from the source entrypoint in assets/css into the served
# static directory. The profile name `triage` is what `mix tailwind triage` and
# the development watcher select below.
config :tailwind,
  version: "4.1.18",
  triage: [
    args: ~w(--input=css/tailwind.css --output=../priv/static/assets/css/tailwind.css),
    cd: Path.expand("../assets", __DIR__)
  ]

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
