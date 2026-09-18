import Config

# The application is unauthenticated. Its listener therefore has a deliberately
# small runtime interface: only the two numeric loopback literals are accepted.
bind = System.get_env("TRIAGE_BIND", "127.0.0.1")

bind_ip =
  case bind do
    "127.0.0.1" ->
      {127, 0, 0, 1}

    "::1" ->
      {0, 0, 0, 0, 0, 0, 0, 1}

    _ ->
      raise "TRIAGE_BIND must be exactly 127.0.0.1 or ::1; public, hostname, and other IP binds are disabled"
  end

default_port = if config_env() == :test, do: "4002", else: "4000"
port_text = System.get_env("PORT", default_port)

port =
  if Regex.match?(~r/^\d+$/, port_text) do
    case Integer.parse(port_text) do
      {value, ""} when value >= 0 and value <= 65_535 -> value
      _ -> raise "PORT must be a decimal integer from 0 through 65535"
    end
  else
    raise "PORT must be a decimal integer from 0 through 65535"
  end

if System.get_env("PHX_SERVER") do
  config :triage, TriageWeb.Endpoint, server: true
end

config :triage, TriageWeb.Endpoint, http: [ip: bind_ip, port: port]

if config_env() == :dev do
  config :triage, TriageWeb.Endpoint,
    live_reload: [
      web_console_logger: true,
      patterns: [
        ~r"priv/static/(?!uploads/).*\.(js|css|png|jpeg|jpg|gif|svg)$"E,
        ~r"lib/triage_web/router\.ex$"E,
        ~r"lib/triage_web/(controllers|live|components)/.*\.(ex|heex)$"E
      ]
    ]
end

if config_env() == :prod do
  database_url =
    case System.get_env("DATABASE_URL") do
      value when is_binary(value) and value != "" ->
        value

      _ ->
        raise """
        environment variable DATABASE_URL is missing.
        For example: ecto://USER:PASS@HOST/DATABASE
        """
    end

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :triage, Triage.Repo,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    socket_options: maybe_ipv6

  secret_key_base =
    case System.get_env("SECRET_KEY_BASE") do
      value when is_binary(value) and value != "" ->
        value

      _ ->
        raise """
        environment variable SECRET_KEY_BASE is missing.
        You can generate one by calling: mix phx.gen.secret
        """
    end

  # PHX_HOST describes generated public URLs. It never controls the listener.
  host = System.get_env("PHX_HOST") || "example.com"

  config :triage, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :triage, TriageWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    secret_key_base: secret_key_base
end

# Optional guided-review integrations. Secrets stay server-side; no integration
# is enabled merely by visiting the queue. Team keys are exact inventory owners.
review_teams =
  case System.get_env("TRIAGE_AZURE_TEAMS_JSON") do
    nil ->
      %{}

    value ->
      case Jason.decode(value) do
        {:ok, teams} when is_map(teams) -> teams
        _ -> raise "TRIAGE_AZURE_TEAMS_JSON must be a JSON object keyed by inventory team"
      end
  end

config :triage, Triage.ReviewIntegrations,
  organization: System.get_env("TRIAGE_AZURE_ORGANIZATION"),
  token: System.get_env("TRIAGE_AZURE_PAT"),
  teams: review_teams,
  ai_executable: System.get_env("TRIAGE_AI_EXECUTABLE")
