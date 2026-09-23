defmodule Triage.ClassifierTestAdapter do
  @moduledoc false
  def install(callback) do
    Process.put(__MODULE__, callback)
    __MODULE__
  end

  def run(request), do: Process.get(__MODULE__).(request)
end
