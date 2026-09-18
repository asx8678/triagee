defmodule Triage.Inventory.CveDetail do
  @moduledoc false
  @type t :: %__MODULE__{cve: String.t(), occurrences: list(), placements: list()}
  defstruct [:cve, occurrences: [], placements: []]
end
