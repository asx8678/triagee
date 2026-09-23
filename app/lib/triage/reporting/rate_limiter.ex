defmodule Triage.Reporting.RateLimiter do
  @moduledoc false
  use GenServer

  @window_seconds 60

  def start_link(_opts), do: GenServer.start_link(__MODULE__, %{}, name: __MODULE__)

  def check(token_id) when is_integer(token_id) do
    GenServer.call(__MODULE__, {:check, token_id, System.monotonic_time(:second)})
  catch
    :exit, _ -> {:error, :unavailable}
  end

  @impl true
  def init(_state), do: {:ok, %{counts: %{}}}

  @impl true
  def handle_call({:check, token_id, now}, _from, state) do
    limit = Application.get_env(:triage, :reporting_api, []) |> Keyword.get(:rate_limit, 120)
    window = div(now, @window_seconds)

    counts =
      state.counts
      |> Enum.filter(fn {_id, {recorded_window, _count}} -> recorded_window == window end)
      |> Map.new()

    {recorded_window, count} = Map.get(counts, token_id, {window, 0})
    count = if recorded_window == window, do: count + 1, else: 1
    counts = Map.put(counts, token_id, {window, count})

    reply =
      if count <= limit,
        do: :ok,
        else: {:error, max(1, @window_seconds - Integer.mod(now, @window_seconds))}

    {:reply, reply, %{state | counts: counts}}
  end
end
