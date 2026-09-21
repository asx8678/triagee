defmodule TriageWeb.AuthTest do
  use TriageWeb.ConnCase, async: false
  import Ecto.Query
  import Triage.Fixtures
  alias Triage.{Accounts, Repo, Workspace}
  alias Triage.Accounts.{Session, User}
  alias Triage.Workspace.Drafts

  setup do
    Triage.DataCase.reset_inventory!()
    image = image!("auth-workspace")
    placement = placement!(image, "auth-team", "prod")
    finding = finding!(image, "CVE-2099-8181")
    %{cve: finding.cve, placement: placement}
  end

  test "anonymous HTTP and WebSocket mounts cannot reach workspace", %{conn: conn} do
    for path <- ["/", "/workspace", "/timeline", "/imports", "/cases/123"] do
      assert conn |> get(path) |> redirected_to() == "/login"
    end

    assert {:error, {:redirect, %{to: "/login"}}} = live(conn, "/")

    assert {:halt, socket} =
             TriageWeb.Auth.on_mount(
               :require_authenticated_user,
               %{},
               %{},
               %Phoenix.LiveView.Socket{}
             )

    assert socket.redirected == {:redirect, %{to: "/login", status: 302}}
    assert conn |> get("/login") |> html_response(200) =~ "login-form"
    assert conn |> get("/health") |> json_response(200) == %{"status" => "ok"}
  end

  test "login rotates session, failures stay generic, and logout revokes and disconnects sockets",
       %{conn: conn} do
    user = account_fixture(:reviewer)
    bad = post(conn, "/login", session: %{email: user.email, password: "bad"})
    assert html_response(bad, 401) =~ "Invalid email or password"

    logged =
      post(conn, "/login", session: %{email: user.email, password: "test-only-password-long"})

    assert redirected_to(logged) == "/"
    token = get_session(logged, :user_token)
    assert {:ok, _} = Accounts.authorize(Accounts.principal(token), :read)
    topic = Accounts.socket_id(token)
    :ok = TriageWeb.Endpoint.subscribe(topic)
    assert logged |> recycle() |> delete("/logout") |> redirected_to() == "/login"
    assert_receive %Phoenix.Socket.Broadcast{topic: ^topic, event: "disconnect"}
    assert {:error, :unauthenticated} = Accounts.authorize(Accounts.principal(token), :read)
  end

  @tag authenticated: :viewer
  test "viewer cannot forge mutation events including manual CVEs, news or drafts", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    assert has_element?(view, "#viewer-read-only")
    assert has_element?(view, "#save-decision[disabled]")

    for event <-
          ~w(draft target save confirm-risk confirm-ticket reconcile cancel-decision manual-open manual-fetch manual-save refresh-news) do
      render_hook(view, event, %{
        "decision" => %{"action" => "fixed", "actor" => "admin@example.test"},
        "id" => to_string(c.placement.id),
        "manual" => %{"cve" => c.cve}
      })
    end

    assert Repo.aggregate(Triage.Decisions.Decision, :count) == 0
    assert Repo.aggregate(Triage.Workspace.Draft, :count) == 0
    assert has_element?(view, "#flash-group", "Reviewer role required")
  end

  @tag authenticated: :reviewer
  test "forged actor is ignored and audit uses the verified account", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")

    render_hook(view, "save", %{
      "decision" => %{
        "action" => "fixed",
        "actor" => "forged@example.test",
        "user_id" => "999",
        "role" => "admin"
      }
    })

    [decision] = Repo.all(Triage.Decisions.Decision)
    assert decision.actor == c.user.email
    assert decision.metadata["identity"] != "self-declared"
  end

  @tag authenticated: :reviewer
  test "role is reloaded before every sensitive websocket event", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    Repo.update_all(from(u in User, where: u.id == ^c.user.id), set: [role: "viewer"])
    render_hook(view, "save", %{"decision" => %{"action" => "fixed"}})
    assert Repo.aggregate(Triage.Decisions.Decision, :count) == 0
    assert has_element?(view, "#flash-group", "Reviewer role required")
  end

  @tag authenticated: :reviewer
  test "session revoked after HTTP render cannot mount websocket", c do
    rendered = get(c.conn, "/")
    assert rendered.status == 200
    Accounts.revoke_session(c.user_token)
    assert {:error, {:redirect, %{to: "/login"}}} = live(rendered)
  end

  @tag authenticated: :reviewer
  test "revoked connected session is checked again before mutation", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    # Simulate revocation on another node before its disconnect broadcast arrives.
    Repo.update_all(from(s in Session, where: s.user_id == ^c.user.id),
      set: [revoked_at: DateTime.utc_now()]
    )

    render_hook(view, "save", %{"decision" => %{"action" => "fixed"}})
    assert_redirect(view, "/login")
    assert Repo.aggregate(Triage.Decisions.Decision, :count) == 0
  end

  @tag authenticated: :reviewer
  test "persistent draft survives remount with original operation and evidence; another user cannot see it",
       c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")

    render_hook(view, "draft", %{
      "decision" => %{"action" => "accepted_risk", "reason" => "My private assessment"}
    })

    {:ok, before} = Drafts.get(c.principal, c.cve)
    {:ok, restored, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    assert has_element?(restored, "textarea[name='decision[reason]']", "My private assessment")
    assert {:ok, ^before} = Drafts.get(c.principal, c.cve)
    other_conn = log_in_user(build_conn(), account_fixture(:reviewer))
    {:ok, other, _} = live(other_conn, "/?page=review&item=#{c.cve}")
    refute has_element?(other, "textarea[name='decision[reason]']", "My private assessment")
  end

  @tag authenticated: :reviewer
  test "inactive or deleted original targets mark a restored draft stale", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")

    render_hook(view, "draft", %{
      "decision" => %{"action" => "accepted_risk", "reason" => "Keep original scope"}
    })

    {:ok, original} = Drafts.get(c.principal, c.cve)

    Repo.update_all(from(p in Triage.Inventory.ImagePlacement, where: p.id == ^c.placement.id),
      set: [active: false]
    )

    {:ok, restored, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    assert has_element?(restored, "#workspace-stale")
    assert {:ok, ^original} = Drafts.get(c.principal, c.cve)
  end

  @tag authenticated: :reviewer
  test "failed draft persistence is visible and never reported durable", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    render_hook(view, "draft", %{"decision" => %{"reason" => String.duplicate("x", 2001)}})
    assert has_element?(view, "#draft-state", "NOT saved")
    assert has_element?(view, "#save-decision[disabled]")
    assert {:ok, nil} = Drafts.get(c.principal, c.cve)
    assert Repo.aggregate(Triage.Decisions.Decision, :count) == 0
  end

  @tag authenticated: :reviewer
  test "unknown ticket operations survive remount and forbid cancel or replacement", c do
    {:ok, view, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    render_hook(view, "draft", %{"decision" => %{"action" => "create_ticket"}})
    {:ok, original} = Drafts.get(c.principal, c.cve)

    Repo.insert!(%Triage.Workspace.TicketOperation{
      id: original.operation,
      cve: c.cve,
      target_ids: original.targets,
      versions: Map.new(original.versions, fn {id, value} -> {to_string(id), value} end),
      fields: %{"action" => "create_ticket", "actor" => c.user.email},
      identity: %{"user_id" => c.user.id, "identity" => "verified"},
      request_hash: "test-request",
      payload_hash: "test-payload",
      payload: [],
      destination: %{},
      marker: "triage-operation-#{original.operation}",
      state: "unknown"
    })

    {:ok, restored, _} = live(c.conn, "/?page=review&item=#{c.cve}")
    assert has_element?(restored, "#ticket-operation", original.operation)
    assert has_element?(restored, "#reconcile-ticket")
    assert has_element?(restored, "#cancel-decision[disabled]")
    assert has_element?(restored, "#save-decision[disabled]")
    render_hook(restored, "cancel-decision", %{})
    render_hook(restored, "reconcile", %{})
    render_hook(restored, "save", %{"decision" => %{"action" => "fixed"}})
    assert {:ok, ^original} = Drafts.get(c.principal, c.cve)
    assert Repo.aggregate(Triage.Workspace.TicketOperation, :count) == 1
    assert Repo.aggregate(Triage.Decisions.Decision, :count) == 0
  end

  @tag authenticated: :reviewer
  test "cross-user commit refreshes clean views and marks dirty views stale without rebasing",
       c do
    path = "/?page=review&item=#{c.cve}"
    {:ok, dirty, _} = live(c.conn, path)

    render_hook(dirty, "draft", %{
      "decision" => %{"action" => "accepted_risk", "reason" => "Preserve me"}
    })

    {:ok, original} = Drafts.get(c.principal, c.cve)
    other = account_fixture(:reviewer)
    {:ok, token} = Accounts.create_session(other)
    {:ok, clean, _} = live(log_in_user(build_conn(), token), path)
    targets = Workspace.targets(%{"cve" => c.cve})

    assert {:ok, _} =
             Triage.Workspace.Commit.save(
               c.cve,
               [c.placement.id],
               Map.new(targets, &{&1.id, &1.fingerprint}),
               Ecto.UUID.generate(),
               %{"action" => "fixed"},
               Accounts.principal(token)
             )

    assert has_element?(dirty, "#workspace-stale")
    assert has_element?(dirty, "textarea[name='decision[reason]']", "Preserve me")
    assert {:ok, ^original} = Drafts.get(c.principal, c.cve)
    assert has_element?(clean, ".fixed-banner")
    {:ok, restored, _} = live(c.conn, path)
    assert has_element?(restored, "#workspace-stale")
    assert {:ok, ^original} = Drafts.get(c.principal, c.cve)
    assert has_element?(restored, "#save-decision[disabled]")
  end
end
