defmodule TriageWeb.Api.V1.ReportingController do
  use TriageWeb, :controller

  alias Triage.Reporting

  def summary(conn, params), do: respond(conn, :summary, params)
  def cves(conn, params), do: respond(conn, :cves, params)
  def cve(conn, params), do: respond(conn, :cve, params)
  def targets(conn, params), do: respond(conn, :targets, params)
  def packages(conn, params), do: respond(conn, :packages, params)
  def options(conn, params), do: respond(conn, :options, params)

  defp respond(conn, kind, params) do
    case Reporting.fetch(kind, params, conn.assigns.reporting_access) do
      {:ok, body} -> json(conn, body)
      {:error, error} -> error(conn, error)
    end
  rescue
    _error in [DBConnection.ConnectionError, Postgrex.Error] ->
      error(conn, %{
        status: 503,
        code: "reporting_unavailable",
        detail: "Reporting data is temporarily unavailable"
      })
  end

  defp error(conn, %{status: status, code: code, detail: detail}) do
    conn |> put_status(status) |> json(%{error: %{code: code, detail: detail}})
  end
end
