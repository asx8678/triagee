defmodule TriageWeb.ReportingAuth do
  @moduledoc false

  import Plug.Conn
  import Phoenix.Controller
  alias Triage.Accounts.ReportingTokens
  alias Triage.Reporting.RateLimiter

  def init(opts), do: opts

  def call(conn, _opts) do
    config = Application.get_env(:triage, :reporting_api, [])

    conn =
      conn
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("x-content-type-options", "nosniff")

    if Keyword.get(config, :enabled, false) do
      authenticate(conn)
    else
      reject(conn, 503, "reporting_disabled", "Reporting API is disabled")
    end
  end

  defp authenticate(conn) do
    with {:ok, raw} <- bearer(conn),
         {:ok, access} <- ReportingTokens.authenticate(raw),
         :ok <- RateLimiter.check(access.token_id) do
      assign(conn, :reporting_access, access)
    else
      {:error, retry_after} when is_integer(retry_after) ->
        conn
        |> put_resp_header("retry-after", Integer.to_string(retry_after))
        |> reject(429, "rate_limited", "Reporting request limit exceeded")

      {:error, :unavailable} ->
        reject(conn, 503, "reporting_unavailable", "Reporting API is unavailable")

      _ ->
        conn
        |> put_resp_header("www-authenticate", ~s(Bearer realm="triage-reporting"))
        |> reject(401, "unauthenticated", "A valid reporting bearer token is required")
    end
  end

  defp bearer(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] when token != "" -> {:ok, token}
      _ -> {:error, :unauthenticated}
    end
  end

  defp reject(conn, status, code, detail) do
    conn
    |> put_status(status)
    |> json(%{error: %{code: code, detail: detail}})
    |> halt()
  end
end
