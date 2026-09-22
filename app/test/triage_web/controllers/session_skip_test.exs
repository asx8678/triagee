defmodule TriageWeb.SessionSkipTest do
  use TriageWeb.ConnCase, async: false
  import Triage.Fixtures, only: [image!: 1, placement!: 3, finding!: 2]
  alias Triage.{Accounts, Decisions, Repo}
  alias Triage.Accounts.{LoginThrottle, Session, User}

  setup do
    previous = Application.fetch_env!(:triage, :local_login_skip)
    Application.put_env(:triage, :local_login_skip, true)
    on_exit(fn -> Application.put_env(:triage, :local_login_skip, previous) end)
    :ok
  end

  test "Skip is a separate CSRF-protected form and needs no credentials", %{conn: conn} do
    document = conn |> get(~p"/login") |> html_response(200) |> LazyHTML.from_document()

    for selector <- [
          "#login-skip-form[action='/login/skip'][method='post']",
          "#login-skip-form input[name='_csrf_token'][type='hidden']",
          "#login-skip-form #login-skip[type='submit']",
          "#login-skip-note"
        ] do
      assert Enum.count(LazyHTML.query(document, selector)) == 1
    end

    assert LazyHTML.text(LazyHTML.query(document, "#login-skip")) |> String.trim() ==
             "Continue as local user"

    assert LazyHTML.text(LazyHTML.query(document, "#login-skip-note")) ==
             "Development mode · no credentials needed"

    assert Enum.count(LazyHTML.query(document, "#login-panel form:first-of-type #login-skip")) ==
             1

    assert Enum.empty?(LazyHTML.query(document, "#login-form #login-skip"))
    assert Enum.empty?(LazyHTML.query(document, "#login-skip-form input[required]"))
  end

  test "Skip grants ordinary reviewer actions, never supplied admin identity", %{conn: conn} do
    admin = account_fixture(:admin)
    image = image!("skip-reviewer")
    placement = placement!(image, "local-team", "prod")
    finding = finding!(image, "CVE-2099-9191")
    conn = post(conn, ~p"/login/skip", %{email: admin.email, role: "admin", user_id: admin.id})
    assert redirected_to(conn) == "/"
    token = get_session(conn, :user_token)
    principal = Accounts.principal(token)
    assert {:ok, %{role: "reviewer", id: id, email: email}} = Accounts.authorize(principal, :read)
    refute id == admin.id
    assert email == "local-user@triage.test"
    assert {:ok, %{id: ^id}} = Accounts.authorize(principal, :review)
    assert {:error, :forbidden} = Accounts.authorize(principal, :admin)
    assert get_session(conn, :live_socket_id) == Accounts.socket_id(token)

    {:ok, view, _} = live(recycle(conn), "/?page=review&item=#{finding.cve}")
    assert has_element?(view, "#workspace-nav-findings")
    refute has_element?(view, "#viewer-read-only")
    # A fresh draft is neutral: the reviewer chooses action and targets (I05).
    assert has_element?(view, "#save-decision[disabled]", "Select an action")
    render_change(view, "target", %{"id" => to_string(placement.id)})
    render_hook(view, "save", %{"decision" => %{"action" => "fixed", "actor" => admin.email}})
    [decision] = Decisions.history_for_cve(finding.cve)
    assert decision.actor == email
    assert decision.metadata["user_id"] == id

    assert conn |> recycle() |> delete(~p"/logout") |> redirected_to() == "/login"
    assert {:error, :unauthenticated} = Accounts.authorize(principal, :read)
  end

  test "repeated Skip sign-ins reuse the regular user without resetting its password", %{
    conn: conn
  } do
    first = post(conn, ~p"/login/skip") |> get_session(:user_token)
    assert {:ok, a} = Accounts.authorize(Accounts.principal(first), :review)
    original = Repo.get!(User, a.id)
    second = post(build_conn(), ~p"/login/skip") |> get_session(:user_token)
    assert {:ok, b} = Accounts.authorize(Accounts.principal(second), :review)
    assert a.id == b.id
    refute first == second
    assert Repo.aggregate(User, :count) == 1
    assert Repo.get!(User, a.id).password_hash == original.password_hash
  end

  test "reserved accounts with different roles or disabled access are not adopted", %{conn: conn} do
    {:ok, user} =
      Accounts.create_user(%{
        email: "local-user@triage.test",
        role: "admin",
        password: "test-only-password-long"
      })

    for attrs <- [
          %{role: "admin", enabled: true},
          %{role: "viewer", enabled: true},
          %{role: "reviewer", enabled: false}
        ] do
      Repo.get!(User, user.id) |> Ecto.Changeset.change(attrs) |> Repo.update!()
      assert conn |> post(~p"/login/skip") |> html_response(503) =~ "Local sign-in is unavailable"
      stored = Repo.get!(User, user.id)
      assert stored.role == attrs.role
      assert stored.enabled == attrs.enabled
      assert stored.password_hash == user.password_hash
    end

    assert Repo.aggregate(Session, :count) == 0
  end

  test "disabled skip is hidden and rejects forged requests without creating accounts", %{
    conn: conn
  } do
    Application.put_env(:triage, :local_login_skip, false)
    before_count = Repo.aggregate(User, :count)
    document = conn |> get(~p"/login") |> html_response(200) |> LazyHTML.from_document()
    assert Enum.empty?(LazyHTML.query(document, "#login-skip"))
    assert conn |> post(~p"/login/skip") |> response(404) == "Not found"
    assert {:error, :disabled} = Accounts.create_local_skip_session("127.0.0.1")
    assert Repo.aggregate(User, :count) == before_count
  end

  test "non-loopback peers cannot skip by forging forwarding headers", %{conn: conn} do
    conn = %{conn | remote_ip: {203, 0, 113, 9}}
    conn = put_req_header(conn, "x-forwarded-for", "127.0.0.1")
    assert conn |> post(~p"/login/skip") |> response(404) == "Not found"
    assert Repo.aggregate(User, :count) == 0
  end

  test "already signed-in users keep their identity and token", %{conn: conn} do
    user = account_fixture(:reviewer)
    conn = log_in_user(conn, user)
    token = get_session(conn, :user_token)
    conn = post(conn, ~p"/login/skip")
    assert redirected_to(conn) == "/"
    assert get_session(conn, :user_token) == token
    assert Repo.aggregate(User, :count) == 1
    assert Repo.aggregate(Session, :count) == 1
  end

  test "local sign-in is throttled", %{conn: conn} do
    for _ <- 1..10, do: assert(LoginThrottle.allow?("local-skip", "127.0.0.1"))
    assert conn |> post(~p"/login/skip") |> html_response(429) =~ "Too many attempts"
    assert Repo.aggregate(User, :count) == 0
  end

  test "skip rejects missing CSRF tokens when protection is active", %{conn: conn} do
    conn = put_private(conn, :plug_skip_csrf_protection, false)
    assert_error_sent 403, fn -> post(conn, ~p"/login/skip") end
    assert Repo.aggregate(User, :count) == 0
  end

  test "only development enables Skip by default" do
    for env <- [:dev, :test, :prod] do
      config = Config.Reader.read!("config/config.exs", env: env)
      assert config[:triage][:build_environment] == env
      assert config[:triage][:local_login_skip] == (env == :dev)
    end
  end
end
