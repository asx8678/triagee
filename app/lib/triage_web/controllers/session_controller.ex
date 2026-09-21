defmodule TriageWeb.SessionController do
  use TriageWeb, :controller
  alias Triage.Accounts

  def new(conn, _) do
    if conn.assigns.current_user,
      do: redirect(conn, to: "/"),
      else: render(conn, :new, form: Phoenix.Component.to_form(%{}, as: :session), error: nil)
  end

  def create(conn, %{"session" => %{"email" => email, "password" => password}}) do
    peer = conn.remote_ip |> :inet.ntoa() |> to_string()

    with {:ok, user} <- Accounts.authenticate(email, password, peer),
         {:ok, token} <- Accounts.create_session(user) do
      Accounts.revoke_session(get_session(conn, :user_token))

      conn
      |> configure_session(renew: true)
      |> clear_session()
      |> put_session(:user_token, token)
      |> put_session(:live_socket_id, Accounts.socket_id(token))
      |> redirect(to: "/")
    else
      {:error, :throttled} ->
        login_error(conn, 429, "Too many attempts. Try again in 15 minutes.")

      _ ->
        login_error(conn, 401, "Invalid email or password.")
    end
  end

  def create(conn, _), do: login_error(conn, 401, "Invalid email or password.")

  def delete(conn, _) do
    Accounts.revoke_session(get_session(conn, :user_token))
    conn |> configure_session(drop: true) |> clear_session() |> redirect(to: "/login")
  end

  defp login_error(conn, status, error) do
    conn
    |> put_status(status)
    |> render(:new, form: Phoenix.Component.to_form(%{}, as: :session), error: error)
  end
end
