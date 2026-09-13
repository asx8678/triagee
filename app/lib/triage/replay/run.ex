defmodule Triage.Replay.Run do
  @moduledoc """
  Internal summary-only ledger schema. No caller-map changeset is exposed.
  Receipt and expiration times are local storage times, never source history.
  """
  use Ecto.Schema

  schema "replay_runs" do
    field :key_hash, :string
    field :input_sha256, :string
    field :summary, :map
    field :outcome, :string
    field :received_at, :utc_datetime_usec
    field :expires_at, :utc_datetime_usec
  end
end
