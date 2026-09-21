defmodule Triage.ReviewActionsTest do
  use Triage.DataCase, async: false
  import Triage.Fixtures
  alias Triage.{Decisions, Workspace}
  alias Triage.Workspace.Commit

  setup do
    reset_inventory!()
    image = image!("review-actions")
    placement = placement!(image, "team", "prod")
    finding = finding!(image, "CVE-2099-8001", description: "<script>unsafe</script>")
    keys = ~w(ADO_ORG_URL ADO_PROJECT ADO_PAT ADO_WORK_ITEM_TYPE)
    previous = Map.new(keys, &{&1, System.get_env(&1)})
    Enum.each(keys, &System.delete_env/1)

    on_exit(fn ->
      Enum.each(previous, fn {k, v} ->
        if v, do: System.put_env(k, v), else: System.delete_env(k)
      end)

      Application.delete_env(:triage, :ado_req_options)
    end)

    %{cve: finding.cve, id: placement.id}
  end

  defp save(c, action, attrs \\ %{}) do
    versions = Map.new(Workspace.targets(%{"cve" => c.cve}), &{&1.id, &1.fingerprint})
    Commit.save(c.cve, [c.id], versions, Ecto.UUID.generate(), Map.put(attrs, "action", action))
  end

  test "fixed requires only the action and timestamps the decision", c do
    assert {:ok, [d]} = save(c, "fixed")
    assert d.reason == ""
    assert DateTime.to_date(d.decided_at) == Date.utc_today()
    assert d.metadata["fixed_at"]
    assert d.due_on == nil
    assert d.expires_at == nil
  end

  test "whitelist permits empty and short comments and defaults three calendar months", c do
    assert Commit.default_due_on(~D[2026-11-30]) == ~D[2027-02-28]
    assert Commit.default_due_on(~D[2027-11-30]) == ~D[2028-02-29]
    assert {:ok, [d]} = save(c, "accepted_risk", %{"reason" => ""})
    assert d.reason == ""
    assert d.due_on == Commit.default_due_on()
    assert Workspace.select(Workspace.targets(%{}, d.expires_at), "needs") != []
    assert {:ok, [d]} = save(c, "accepted_risk", %{"reason" => "x"})
    assert d.reason == "x"
  end

  test "unconfigured ticket creation does not save a decision", c do
    assert {:error, {:ticket, message}} = save(c, "create_ticket")
    assert message =~ "ADO_ORG_URL"
    assert Decisions.history_for_cve(c.cve) == []
  end

  defp configure do
    System.put_env(%{
      "ADO_ORG_URL" => "https://dev.azure.com/example",
      "ADO_PROJECT" => "Security",
      "ADO_PAT" => "test-only",
      "ADO_WORK_ITEM_TYPE" => "Task"
    })

    Application.put_env(:triage, :ado_req_options, plug: {Req.Test, __MODULE__})
  end

  test "ticket success records URL and replays without another POST", c do
    configure()

    Req.Test.expect(__MODULE__, fn conn ->
      assert conn.method == "POST"
      assert conn.request_path == "/example/Security/_apis/wit/workitems/$Task"
      assert Plug.Conn.get_req_header(conn, "content-type") == ["application/json-patch+json"]
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      [title, description, marker] = Jason.decode!(body)
      assert marker["path"] == "/fields/System.Tags"
      assert marker["value"] =~ "triage-operation-"
      assert title["value"] =~ c.cve
      assert description["value"] =~ "Package version"
      assert description["value"] =~ "<h2>Summary</h2>"
      assert description["value"] =~ "Why this needs to be fixed"
      refute description["value"] =~ "<pre>"
      refute description["value"] =~ "&quot;package_version&quot;"
      refute description["value"] =~ "%{"
      refute description["value"] =~ "=>"
      assert description["value"] =~ "&lt;script&gt;"
      Req.Test.json(conn, %{"id" => 42})
    end)

    versions = Map.new(Workspace.targets(), &{&1.id, &1.fingerprint})
    operation = Ecto.UUID.generate()
    args = [c.cve, [c.id], versions, operation, %{"action" => "create_ticket"}]
    assert {:ok, [d]} = apply(Commit, :save, args)
    assert d.metadata["ticket_url"] == "https://dev.azure.com/example/Security/_workitems/edit/42"
    assert Workspace.select(Workspace.targets(), "progress") != []
    assert {:ok, [^d]} = apply(Commit, :save, args)
  end

  test "ticket rejection leaves scope actionable", c do
    configure()
    Req.Test.expect(__MODULE__, fn conn -> Plug.Conn.send_resp(conn, 403, "denied") end)
    assert {:error, {:reconciliation_required, operation}} = save(c, "create_ticket")
    assert Triage.Repo.get!(Triage.Workspace.TicketOperation, operation).state == "unknown"
    assert Decisions.history_for_cve(c.cve) == []
  end
end
