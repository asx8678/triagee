defmodule Triage.Fixtures do
  @moduledoc """
  Shared test fixture entry point. Synthetic data only — see `Triage.Seeds`.
  """

  defdelegate seed(), to: Triage.Seeds
end
