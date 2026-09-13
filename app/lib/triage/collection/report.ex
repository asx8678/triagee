defmodule Triage.Collection.Report do
  @moduledoc """
  Read-only normalized collection report.

  Not a historical snapshot: it records current measurements and never
  synthesizes `first_seen` or lifecycle history.

  `complete?/1` is false whenever anything could not be read or reconciled.
  `incomplete` is set for evidence that is present but not trustworthy (missing
  or malformed material, truncated budgets, contradictory claims), so a merely
  warned incompleteness still makes the report non-complete. `actionable?/1` is
  always false in this PR6 scope: no snapshot builder is in scope, so a report
  can never be actionable, and a forged `historical_provenance` boolean cannot
  flip it.
  """

  @enforce_keys [:scope, :environment, :engine]
  defstruct [
    :scope,
    :environment,
    :engine,
    :status_marker,
    :historical_provenance,
    owners: [],
    images: [],
    findings: [],
    suppressed: [],
    warnings: [],
    failures: [],
    requests: 0,
    duration_ms: 0,
    raw: %{},
    blockers: [],
    incomplete: false
  ]

  @type t :: %__MODULE__{}

  @doc "True when the requested scope was read and reconciled without failures or incomplete evidence."
  def complete?(%__MODULE__{failures: failures, incomplete: incomplete}) do
    failures == [] and incomplete != true
  end

  @doc """
  Always false. This PR6 scope has no controller-verified snapshot provenance,
  so no report (including one with a forged `historical_provenance: true`) is
  ever actionable.
  """
  def actionable?(%__MODULE__{}), do: false

  def finding_count(%__MODULE__{findings: findings}), do: length(findings)
  def suppressed_count(%__MODULE__{suppressed: suppressed}), do: length(suppressed)
end
