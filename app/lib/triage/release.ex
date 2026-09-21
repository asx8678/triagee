defmodule Triage.Release do
  @moduledoc "Database migrations for an assembled release; never seeds or resets data."

  def migrate do
    Application.load(:triage)

    for repo <- Application.fetch_env!(:triage, :ecto_repos) do
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end

    :ok
  end
end
