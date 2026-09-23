defmodule TriageWeb.Auth do
  @moduledoc "HTTP and LiveView authorization, with a fresh server-side identity on every event."
  import Plug.Conn, except: [assign: 3]
  import Phoenix.Controller
  import Phoenix.Component, only: [assign: 3]
  alias Triage.Accounts

  @read_events ~w(refresh filter timeline-case plot_width scope search risk-filter select clear-selection review-selected cancel-risk expand queue-toggle density settings close-settings close-inspector dismiss-action-toast manual-close)

  def init(action), do: action
  def call(conn, action), do: apply(__MODULE__, action, [conn])

  def fetch_current_user(conn) do
    principal = Accounts.principal(get_session(conn, :user_token))

    user =
      case Accounts.authorize(principal, :read) do
        {:ok, user} -> user
        _ -> nil
      end

    conn
    |> Plug.Conn.assign(:current_user, user)
    |> Plug.Conn.assign(:current_principal, principal)
    |> Plug.Conn.assign(:current_scope, if(user, do: %{user: user}, else: nil))
  end

  def require_authenticated_user(%{assigns: %{current_user: nil}} = conn),
    do: conn |> redirect(to: "/login") |> halt()

  def require_authenticated_user(conn), do: conn

  def on_mount(:require_authenticated_user, _params, session, socket) do
    principal = Accounts.principal(session["user_token"])

    case Accounts.authorize(principal, :read) do
      {:ok, user} ->
        if Phoenix.LiveView.connected?(socket),
          do: Process.send_after(self(), :auth_revalidate, 60_000)

        socket =
          socket
          |> identity(user, principal)
          |> Phoenix.LiveView.attach_hook(:authorize_events, :handle_event, &authorize_event/3)
          |> Phoenix.LiveView.attach_hook(:authorize_params, :handle_params, &authorize_params/3)
          |> Phoenix.LiveView.attach_hook(:session_expiry, :handle_info, &authorize_info/2)

        {:cont, socket}

      _ ->
        {:halt, Phoenix.LiveView.redirect(socket, to: "/login")}
    end
  end

  defp authorize_event(event, _params, socket) do
    permission = if event in @read_events, do: :read, else: :review

    case Accounts.authorize(socket.assigns.current_principal, permission) do
      {:ok, user} ->
        {:cont, identity(socket, user, socket.assigns.current_principal)}

      {:error, :forbidden} ->
        {_, socket} = revalidate(socket)
        {:halt, Phoenix.LiveView.put_flash(socket, :error, "Reviewer role required.")}

      _ ->
        {:halt, Phoenix.LiveView.redirect(socket, to: "/login")}
    end
  end

  defp authorize_params(_params, _uri, socket), do: revalidate(socket)

  defp authorize_info(:auth_revalidate, socket) do
    Process.send_after(self(), :auth_revalidate, 60_000)
    {_, socket} = revalidate(socket)
    {:halt, socket}
  end

  defp authorize_info(_, socket), do: revalidate(socket)

  defp revalidate(socket) do
    case Accounts.authorize(socket.assigns.current_principal, :read) do
      {:ok, user} -> {:cont, identity(socket, user, socket.assigns.current_principal)}
      _ -> {:halt, Phoenix.LiveView.redirect(socket, to: "/login")}
    end
  end

  defp identity(socket, user, principal) do
    socket
    |> assign(:current_user, user)
    |> assign(:current_principal, principal)
    |> assign(:current_scope, %{user: user})
    |> assign(:can_review, Accounts.permitted?(user, :review))
  end
end
