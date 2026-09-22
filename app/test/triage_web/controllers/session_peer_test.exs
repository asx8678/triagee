defmodule TriageWeb.SessionPeerTest do
  use TriageWeb.ConnCase, async: false

  defp attempt(conn, email) do
    post(conn, ~p"/login", %{"session" => %{"email" => email, "password" => "wrong-password"}})
    |> response(401)
  end

  test "proxied logins throttle per forwarded client, not per proxy", %{conn: conn} do
    for i <- 1..50 do
      conn
      |> put_req_header("x-forwarded-for", "203.0.113.10")
      |> attempt("bulk-#{i}@example.test")
    end

    # Another client through the same proxy is untouched by the first client.
    conn
    |> put_req_header("x-forwarded-for", "198.51.100.20")
    |> attempt("fresh@example.test")

    # The exhausting client is throttled for the rest of the window.
    conn
    |> put_req_header("x-forwarded-for", "203.0.113.10")
    |> post(~p"/login", %{"session" => %{"email" => "bulk-1@example.test", "password" => "x"}})
    |> response(429)
  end

  test "client-supplied entries before the proxy's own are ignored", %{conn: conn} do
    for i <- 1..50 do
      conn
      |> put_req_header("x-forwarded-for", "1.2.3.4, 203.0.113.10")
      |> attempt("spoof-#{i}@example.test")
    end

    # The attacker cannot lock out an identity they merely named as a prefix.
    conn |> put_req_header("x-forwarded-for", "1.2.3.4") |> attempt("victim@example.test")

    # Their own rightmost entry is the one that got exhausted.
    conn
    |> put_req_header("x-forwarded-for", "9.9.9.9, 203.0.113.10")
    |> post(~p"/login", %{"session" => %{"email" => "spoof-1@example.test", "password" => "x"}})
    |> response(429)
  end

  test "direct requests without a forwarding header share the listener budget", %{conn: conn} do
    for i <- 1..50, do: attempt(conn, "direct-#{i}@example.test")

    conn
    |> post(~p"/login", %{"session" => %{"email" => "direct-1@example.test", "password" => "x"}})
    |> response(429)
  end

  describe "Skip needs a direct loopback peer" do
    setup do
      previous = Application.fetch_env!(:triage, :local_login_skip)
      Application.put_env(:triage, :local_login_skip, true)
      on_exit(fn -> Application.put_env(:triage, :local_login_skip, previous) end)
      :ok
    end

    test "a proxied loopback request is not offered or granted Skip", %{conn: conn} do
      conn = put_req_header(conn, "x-forwarded-for", "203.0.113.99")

      document =
        conn |> get(~p"/login") |> html_response(200) |> LazyHTML.from_document()

      assert Enum.empty?(LazyHTML.query(document, "#login-skip"))
      assert conn |> post(~p"/login/skip") |> response(404) == "Not found"
    end
  end
end
