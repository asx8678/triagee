defmodule TriageWeb.SessionSecurityTest do
  use TriageWeb.ConnCase

  test "session cookies have an explicit lifetime and browser protections", %{conn: conn} do
    conn = get(conn, ~p"/login")
    assert html_response(conn, 200)
    cookie = conn.resp_cookies["_triage_key"]
    assert cookie.http_only
    assert cookie.same_site == "Lax"
    assert cookie.max_age == 28_800
    assert String.starts_with?(cookie.value, "XCP.")
  end

  test "HTTPS session cookies are secure", %{conn: conn} do
    conn = get(conn, "https://www.example.com/login")

    assert Enum.any?(get_resp_header(conn, "set-cookie"), fn cookie ->
             String.starts_with?(cookie, "_triage_key=") and String.contains?(cookie, "secure")
           end)
  end

  test "tampered cookies do not restore session contents", %{conn: conn} do
    first = get(conn, ~p"/login")
    token = get_session(first, :_csrf_token)
    cookie = first.resp_cookies["_triage_key"].value

    second =
      build_conn()
      |> put_req_cookie("_triage_key", cookie <> "tampered")
      |> get(~p"/login")

    assert html_response(second, 200)
    refute get_session(second, :_csrf_token) == token
    assert second |> recycle() |> get(~p"/") |> redirected_to() == "/login"
  end
end
