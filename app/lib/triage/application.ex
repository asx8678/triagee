defmodule Triage.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children =
      [
        TriageWeb.Telemetry,
        Triage.Repo,
        Triage.Reporting.RateLimiter,
        {Task.Supervisor, name: Triage.KiroTasks},
        {DNSCluster, query: Application.get_env(:triage, :dns_cluster_query) || :ignore},
        {Phoenix.PubSub, name: Triage.PubSub},
        # Start a worker by calling: Triage.Worker.start_link(arg)
        # {Triage.Worker, arg},
        # Start to serve requests, typically the last entry
        TriageWeb.Endpoint
      ] ++ classifier_children()

    # No job processes start when the experiment is disabled (except manual tests).

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Triage.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp classifier_children do
    config = Application.get_env(:triage, Oban, [])

    if Triage.AiTriage.enabled?() or Triage.Classifier.enabled?() or config[:testing] == :manual,
      do: [{Oban, config}],
      else: []
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    TriageWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
