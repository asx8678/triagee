defmodule Triage.Collection.Live do
  @moduledoc """
  Separate live-collection entry. Always disabled.

  G01 is unresolved. This module accepts no endpoint, query, credential, or
  transport, so it cannot prove redirect handling and it is not an injectable
  network escape hatch. Redirect refusal remains the existing
  `Triage.Collection.Client` test evidence.
  """

  @doc "Refuses live collection. Performs no network call and no ingest."
  @spec run() :: {:error, :collection_disabled}
  def run, do: {:error, :collection_disabled}
end
