defmodule Triage.Collection.Loopback do
  @moduledoc "Single compile-time source for the collection loopback gate. Runtime changes cannot enable it."

  @enabled Application.compile_env(:triage, [:collection, :loopback_transport], false)

  @spec enabled?() :: boolean()
  def enabled?, do: @enabled
end
