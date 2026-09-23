defmodule Triage.Classifier.Worker do
  @moduledoc "Durable, single-attempt analysis. Terminal or uncertain results are never blindly resent."
  use Oban.Worker, queue: :classifier, max_attempts: 1
  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"run_id" => id}}), do: Triage.Classifier.perform(id)
  @impl Oban.Worker
  def timeout(_job), do: :timer.seconds(45)
end
