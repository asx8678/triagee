defmodule Triage.Accounts.Principal do
  @moduledoc "Opaque server-issued session authority. Never construct from browser identity fields."
  @derive {Inspect, except: [:token]}
  @enforce_keys [:token]
  defstruct [:token]
end
