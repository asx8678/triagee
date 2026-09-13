defmodule Triage.Repo do
  use Ecto.Repo,
    otp_app: :triage,
    adapter: Ecto.Adapters.Postgres
end
