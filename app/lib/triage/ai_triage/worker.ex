defmodule Triage.AiTriage.Worker do
  @moduledoc "Explicit Review classification jobs; never automatically retry a model call."
  use Oban.Worker, queue: :classifier, max_attempts: 1
  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"run_id" => id}}), do: Triage.AiTriage.Runs.perform(id)
  @impl Oban.Worker
  def timeout(_job), do: 150_000
end
