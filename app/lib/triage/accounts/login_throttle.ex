defmodule Triage.Accounts.LoginThrottle do
  @moduledoc "Database-backed per-account and per-peer fixed-window limits, shared by all nodes."
  import Ecto.Query
  alias Triage.Repo
  @window 900

  def allow?(email, peer) do
    window = div(System.system_time(:second), @window)
    # Retain only the current and preceding window; hashes avoid storing submitted identities/IPs.
    Repo.delete_all(from t in "account_login_attempts", where: t.window < ^(window - 1))
    account = hit("account:" <> email, window)
    address = hit("peer:" <> peer, window)
    account <= 10 and address <= 50
  end

  defp hit(key, window) do
    key = :crypto.hash(:sha256, key) |> Base.encode16(case: :lower)

    {1, [row]} =
      Repo.insert_all("account_login_attempts", [%{key: key, window: window, attempts: 1}],
        conflict_target: [:key, :window],
        on_conflict: [inc: [attempts: 1]],
        returning: [:attempts]
      )

    row.attempts
  end
end
