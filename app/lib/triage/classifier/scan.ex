defmodule Triage.Classifier.Scan do
  @moduledoc "Opt-in bounded discovery of approved snapshots, independent of browser navigation."
  use Oban.Worker, queue: :classifier, max_attempts: 1
  @impl Oban.Worker
  def perform(_job) do
    Triage.Classifier.recover_interrupted()
    Triage.Classifier.enqueue_approved()
    :ok
  end
end
