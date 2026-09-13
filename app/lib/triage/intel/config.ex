defmodule Triage.Intel.Config do
  @moduledoc """
  Public-intelligence runtime policy — explicit default-off network access.

  Everything is opt-in. Defaults:
    * `enabled: false`
    * `sources: []` — the allowlisted hosts are compiled into the client;
      config can at most enable/disable an already-known source adapter.
    * no credentials

  Reads happen only via the manual `mix triage.intel` task or an explicitly
  enabled scheduler — never on ordinary GET requests.
  """

  @spec enabled?() :: boolean()
  def enabled? do
    Application.get_env(:triage, :intel, [])
    |> Keyword.get(:enabled, false)
    |> Kernel.==(true)
  end

  @doc "Sources explicitly allowed, intersected with compiled-in adapters."
  def enabled_sources do
    Application.get_env(:triage, :intel, [])
    |> Keyword.get(:sources, [])
    |> Enum.filter(&(&1 in [:kev, :nvd]))
  end

  @doc """
  Whether one source may be refreshed: enabled AND named.

  `enabled: true` is not authorization for every adapter. The operator names the
  sources they approve and an unnamed source is refused, so the printed
  `sources: [...]` list is a real restriction rather than a display of intent.
  """
  def source_allowed?(source) when source in [:kev, :nvd] do
    enabled?() and source in enabled_sources()
  end

  def source_allowed?(_other), do: false
end
