defmodule TriageWeb.ConnCase do
  @moduledoc """
  This module defines the test case to be used by
  tests that require setting up a connection.

  Such tests rely on `Phoenix.ConnTest` and also
  import other functionality to make it easier
  to build common data structures and query the data layer.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use TriageWeb.ConnCase, async: true`, although
  this option is not recommended for other databases.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      @moduletag :db

      # The default endpoint for testing
      @endpoint TriageWeb.Endpoint

      use TriageWeb, :verified_routes

      # Import conveniences for testing with connections
      import Plug.Conn
      import Phoenix.ConnTest
      import Phoenix.LiveViewTest
      import TriageWeb.ConnCase
    end
  end

  setup tags do
    Triage.DataCase.setup_sandbox(tags)
    conn = Phoenix.ConnTest.build_conn()

    case tags[:authenticated] do
      role when role in [:viewer, :reviewer, :admin] ->
        user = account_fixture(role)
        {:ok, token} = Triage.Accounts.create_session(user)

        {:ok,
         conn: log_in_user(conn, token),
         user: user,
         user_token: token,
         principal: Triage.Accounts.principal(token)}

      nil ->
        {:ok, conn: conn}

      false ->
        {:ok, conn: conn}

      _ ->
        raise "Use an explicit authenticated: :viewer, :reviewer, or :admin tag"
    end
  end

  def account_fixture(role \\ :reviewer) do
    {:ok, user} =
      Triage.Accounts.create_user(%{
        email: "user-#{System.unique_integer([:positive])}@example.test",
        password: "test-only-password-long",
        role: to_string(role)
      })

    user
  end

  def log_in_user(conn, %Triage.Accounts.User{} = user) do
    {:ok, token} = Triage.Accounts.create_session(user)
    log_in_user(conn, token)
  end

  def log_in_user(conn, token) when is_binary(token) do
    Phoenix.ConnTest.init_test_session(conn, %{
      "user_token" => token,
      "live_socket_id" => Triage.Accounts.socket_id(token)
    })
  end
end
