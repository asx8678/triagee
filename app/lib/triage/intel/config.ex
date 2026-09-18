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

  @default_max_response_bytes 8_000_000

  @doc "Validated runtime byte cap shared by streaming and injected-response admission."
  @spec max_response_bytes() ::
          {:ok, pos_integer()} | {:error, {:invalid_config, :max_response_bytes}}
  def max_response_bytes do
    config = Application.get_env(:triage, :intel, [])

    max =
      if Keyword.keyword?(config),
        do: Keyword.get(config, :max_response_bytes, @default_max_response_bytes)

    if is_integer(max) and max > 0,
      do: {:ok, max},
      else: {:error, {:invalid_config, :max_response_bytes}}
  end

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
