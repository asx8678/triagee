defmodule TriageWeb.SessionController do
  use TriageWeb, :controller
  alias Triage.Accounts

  @loopback [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]

  if Application.compile_env(:triage, :build_environment, :prod) in [:dev, :test] do
    def skip(conn, _params) do
      cond do
        not local_skip?(conn) -> send_resp(conn, 404, "Not found")
        conn.assigns.current_user != nil -> redirect(conn, to: "/")
        true -> start_local_user(conn)
      end
    end

    defp start_local_user(conn) do
      case Accounts.create_local_skip_session(peer(conn)) do
        {:ok, token} ->
          start_session(conn, token)

        {:error, :throttled} ->
          login_error(conn, 429, "Too many attempts. Try again in 15 minutes.")

        _ ->
          login_error(conn, 503, "Local sign-in is unavailable. Please sign in.")
      end
    end

    defp local_skip?(conn) do
      # Direct means direct: a reverse proxy also connects from loopback, so a
      # forwarded header proves the request did not come from the operator's
      # own machine, and Skip must not appear for it.
      Accounts.local_login_skip_enabled?() and
        conn.remote_ip in @loopback and is_nil(forwarded_peer(conn))
    end
  else
    def skip(conn, _params), do: send_resp(conn, 404, "Not found")
    defp local_skip?(_conn), do: false
  end

  def new(conn, _) do
    if conn.assigns.current_user,
      do: redirect(conn, to: "/"),
      else: render_login(conn, nil)
  end

  def create(conn, %{"session" => %{"email" => email, "password" => password}}) do
    with {:ok, user} <- Accounts.authenticate(email, password, peer(conn)),
         {:ok, token} <- Accounts.create_session(user) do
      start_session(conn, token)
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

  defp start_session(conn, token) do
    Accounts.revoke_session(get_session(conn, :user_token))

    conn
    |> configure_session(renew: true)
    |> clear_session()
    |> put_session(:user_token, token)
    |> put_session(:live_socket_id, Accounts.socket_id(token))
    |> redirect(to: "/")
  end

  # The documented shared deployment fronts this loopback listener with a
  # TLS reverse proxy. A proxied login is throttled under the client address
  # the proxy appended — the rightmost X-Forwarded-For entry. Entries before it
  # are client-controlled and ignored, so a remote attacker can neither lock
  # out an identity they merely name nor shed their own; a request without the
  # header keeps its own transport address.
  defp peer(conn) do
    case forwarded_peer(conn) do
      nil -> conn.remote_ip |> :inet.ntoa() |> to_string()
      address -> address |> :inet.ntoa() |> to_string()
    end
  end

  defp forwarded_peer(%{remote_ip: remote_ip, req_headers: headers})
       when remote_ip in @loopback,
       do:
         headers
         |> Enum.find_value(fn
           {"x-forwarded-for", value} -> value
           _other -> nil
         end)
         |> last_address()

  defp forwarded_peer(_conn), do: nil

  defp last_address(value) when is_binary(value) do
    value |> String.split(",") |> List.last() |> String.trim() |> parse_address()
  end

  defp last_address(_other), do: nil

  defp parse_address(text) do
    case :inet.parse_address(to_charlist(text)) do
      {:ok, address} -> address
      _other -> nil
    end
  end

  defp login_error(conn, status, error) do
    conn
    |> put_status(status)
    |> render_login(error)
  end

  defp render_login(conn, error) do
    render(conn, :new,
      page_title: "Sign in",
      form: Phoenix.Component.to_form(%{}, as: :session),
      error: error,
      skip_login?: local_skip?(conn)
    )
  end
end
