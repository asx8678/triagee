defmodule TriageWeb.HealthController do
  @moduledoc "Minimal readiness response without configuration or inventory disclosure."
  use TriageWeb, :controller

  def show(conn, _params) do
    case Triage.Repo.query("SELECT 1", [], timeout: 1_000, pool_timeout: 1_000) do
      {:ok, _} -> json(conn, %{status: "ok"})
      {:error, _} -> unavailable(conn)
    end
  rescue
    _ -> unavailable(conn)
  end

  defp unavailable(conn),
    do: conn |> put_status(:service_unavailable) |> json(%{status: "unavailable"})
end
