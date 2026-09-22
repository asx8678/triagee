defmodule Triage.WorkspaceTicketOperationsTest do
  use Triage.DataCase, async: false
  import Triage.Fixtures
  alias Triage.{Accounts, AzureDevOps, Decisions, Workspace}
  alias Triage.Workspace.{Commit, TicketOperation}

  setup do
    reset_inventory!()
    Repo.delete_all(TicketOperation)
    image = image!("durable-ticket")
    target = placement!(image, "security", "prod")
    sibling = placement!(image, "security", "staging")
    finding = finding!(image, "CVE-2099-8123", description: "Original evidence")
    {user, principal} = principal("reviewer")
    keys = ~w(ADO_ORG_URL ADO_PROJECT ADO_PAT ADO_WORK_ITEM_TYPE ADO_AREA_PATH)
    previous = Map.new(keys, &{&1, System.get_env(&1)})
    options = Application.get_env(:triage, :ado_req_options)
    handler = Application.get_env(:triage, :workspace_ticket_test_adapter)

    System.put_env(%{
      "ADO_ORG_URL" => "https://dev.azure.com/test-only",
      "ADO_PROJECT" => "Security",
      "ADO_PAT" => "not-a-real-credential",
      "ADO_WORK_ITEM_TYPE" => "Task"
    })

    System.delete_env("ADO_AREA_PATH")

    on_exit(fn ->
      Enum.each(previous, fn {key, value} ->
        if value, do: System.put_env(key, value), else: System.delete_env(key)
      end)

      if options,
        do: Application.put_env(:triage, :ado_req_options, options),
        else: Application.delete_env(:triage, :ado_req_options)

      if handler,
        do: Application.put_env(:triage, :workspace_ticket_test_adapter, handler),
        else: Application.delete_env(:triage, :workspace_ticket_test_adapter)
    end)

    Phoenix.PubSub.subscribe(Triage.PubSub, "workspace:changes")

    %{
      cve: finding.cve,
      target: target,
      sibling: sibling,
      finding: finding,
      user: user,
      principal: principal,
      operation: Ecto.UUID.generate()
    }
  end

  defp principal(role) do
    # Provision only the account/session fixture; password authentication is tested by Accounts.
    user =
      Repo.insert!(%Accounts.User{
        email: "#{Ecto.UUID.generate()}@example.test",
        role: role,
        password_hash: <<0::256>>,
        password_salt: <<0::128>>,
        password_rounds: 600_000
      })

    {:ok, token} = Accounts.create_session(user)
    {user, Accounts.principal(token)}
  end

  defp versions(cve), do: Map.new(Workspace.targets(%{"cve" => cve}), &{&1.id, &1.fingerprint})
  defp attrs, do: %{"action" => "create_ticket", "actor" => "Forged actor"}

  defp save(c, before, id \\ nil, ids \\ nil),
    do: Commit.save(c.cve, ids || [c.target.id], before, id || c.operation, attrs(), c.principal)

  def run(request), do: Application.fetch_env!(:triage, :workspace_ticket_test_adapter).(request)

  defp adapter(fun) do
    Application.put_env(:triage, :workspace_ticket_test_adapter, fun)

    Application.put_env(:triage, :ado_req_options,
      adapter: __MODULE__,
      retry: true,
      redirect: true
    )
  end

  defp response(request, body), do: {request, %Req.Response{status: 200, body: body}}

  test "durable claim precedes HTTP, immutable payload and verified actor survive success and replay",
       c do
    before = versions(c.cve)
    test = self()

    adapter(fn request ->
      operation = Repo.get!(TicketOperation, c.operation)

      send(
        test,
        {:created, request.method, Repo.in_transaction?(), operation, request.body,
         request.options[:retry], request.options[:redirect]}
      )

      response(request, %{"id" => 42})
    end)

    assert {:ok, [decision]} = save(c, before)
    assert_receive {:created, :post, false, operation, body, false, false}
    assert operation.state == "pending"
    assert operation.identity == %{"identity" => "authenticated", "user_id" => c.user.id}
    assert operation.fields["actor"] == c.user.email
    assert operation.payload == Jason.decode!(IO.iodata_to_binary(body))
    assert operation.payload_hash == Workspace.hash({operation.destination, operation.payload})

    assert Enum.any?(
             operation.payload,
             &(&1["path"] == "/fields/System.Tags" and &1["value"] == operation.marker)
           )

    refute inspect(operation) =~ "not-a-real-credential"
    assert decision.actor == c.user.email
    assert decision.metadata["user_id"] == c.user.id
    assert decision.metadata["identity"] == "authenticated"
    assert decision.metadata["ticket_url"] =~ "/42"
    assert Repo.get!(TicketOperation, c.operation).state == "completed"
    cve = c.cve
    assert_receive {:workspace_changed, ^cve}
    assert {:ok, [^decision]} = save(c, before)
    refute_receive {:created, _, _, _, _, _, _}
    refute_receive {:workspace_changed, _}

    assert {:error, :operation_reused} =
             Commit.save(
               c.cve,
               [c.target.id],
               before,
               c.operation,
               %{"action" => "fixed"},
               c.principal
             )

    {_, other} = principal("reviewer")

    assert {:error, :operation_reused} =
             Commit.save(c.cve, [c.target.id], before, c.operation, attrs(), other)

    assert {:error, :operation_reused} = save(c, before, c.operation, [c.sibling.id])
  end

  test "remote-created timeout never retries, even with fresh IDs and overlapping target sets",
       c do
    before = versions(c.cve)
    test = self()

    adapter(fn request ->
      send(test, :remote_created_but_timeout)
      {request, %Req.TransportError{reason: :timeout}}
    end)

    id = c.operation
    assert {:error, {:reconciliation_required, ^id}} = save(c, before)
    assert_receive :remote_created_but_timeout
    assert Repo.get!(TicketOperation, id).state == "unknown"
    assert {:error, {:reconciliation_required, ^id}} = save(c, before)
    assert {:error, {:operation_pending, ^id}} = save(c, before, Ecto.UUID.generate())

    assert {:error, {:operation_pending, ^id}} =
             save(c, before, Ecto.UUID.generate(), [c.target.id, c.sibling.id])

    refute_receive :remote_created_but_timeout
    refute_receive {:workspace_changed, _}
    assert Repo.aggregate(Decisions.Decision, :count) == 0

    operation = Repo.get!(TicketOperation, id)

    adapter(fn request ->
      send(test, {:reconcile_request, request.method, request.url.path})

      case request.url.path do
        "/test-only/Security/_apis/wit/wiql" ->
          assert IO.iodata_to_binary(request.body) =~ operation.marker
          response(request, %{"workItems" => [%{"id" => 73}]})

        "/test-only/Security/_apis/wit/workitems/73" ->
          response(request, %{
            "id" => 73,
            "fields" => %{"System.Tags" => "security; " <> operation.marker}
          })
      end
    end)

    assert {:ok, [decision]} = Commit.reconcile(id, c.principal)
    assert decision.metadata["ticket_url"] =~ "/73"
    assert decision.metadata["reconciled_by_user_id"] == c.user.id
    assert_receive {:reconcile_request, :post, "/test-only/Security/_apis/wit/wiql"}
    assert_receive {:reconcile_request, :get, "/test-only/Security/_apis/wit/workitems/73"}
    assert {:ok, [^decision]} = save(c, before)
    refute_receive {:reconcile_request, _, _}
  end

  test "no match or ambiguous/partial marker matches never release the durable claim", c do
    before = versions(c.cve)
    adapter(fn request -> {request, %Req.TransportError{reason: :timeout}} end)
    id = c.operation
    assert {:error, {:reconciliation_required, ^id}} = save(c, before)

    for items <- [[], [%{"id" => 1}, %{"id" => 2}], [%{"id" => 1}]] do
      adapter(fn request ->
        if request.method == :get,
          do:
            response(request, %{"id" => 1, "fields" => %{"System.Tags" => "not-an-exact-marker"}}),
          else: response(request, %{"workItems" => items})
      end)

      assert {:error, {:reconciliation_required, ^id}} = Commit.reconcile(id, c.principal)
      assert {:error, {:operation_pending, ^id}} = save(c, before, Ecto.UUID.generate())
    end

    assert Repo.get!(TicketOperation, id).state == "unknown"
    refute_receive {:workspace_changed, _}
  end

  test "remote success survives local evidence conflict and explicit fresh review finalizes without network",
       c do
    before = versions(c.cve)

    adapter(fn request ->
      c.finding
      |> Ecto.Changeset.change(description: "Changed during remote request")
      |> Repo.update!()

      response(request, %{"id" => 51})
    end)

    id = c.operation
    assert {:error, {:finalization_conflict, ^id}} = save(c, before)
    operation = Repo.get!(TicketOperation, id)
    assert operation.state == "remote_created"
    assert operation.ticket_url =~ "/51"
    assert Repo.aggregate(Decisions.Decision, :count) == 0
    refute_receive {:workspace_changed, _}
    test = self()

    adapter(fn request ->
      send(test, :unexpected_network)
      response(request, %{"id" => 999})
    end)

    assert {:error, {:finalization_conflict, ^id}} = save(c, before)
    assert {:error, {:finalization_conflict, ^id}} = Commit.reconcile(id, c.principal)
    assert {:error, {:operation_pending, ^id}} = save(c, versions(c.cve), Ecto.UUID.generate())
    fresh = versions(c.cve)
    assert {:ok, [decision]} = Commit.reconcile(id, fresh, c.principal)

    assert decision.metadata["observed_evidence"]["findings"] |> hd() |> Map.fetch!("description") ==
             "Changed during remote request"

    assert decision.metadata["reconciled_by_user_id"] == c.user.id
    assert decision.metadata["reconciled_versions"][to_string(c.target.id)] == fresh[c.target.id]
    recovered = Repo.get!(TicketOperation, id)
    assert recovered.payload == operation.payload
    assert recovered.payload_hash == operation.payload_hash
    assert recovered.versions == operation.versions
    assert recovered.identity == operation.identity
    assert {:ok, [^decision]} = save(c, before)
    refute_receive :unexpected_network
  end

  test "local database commit failure preserves remote result and retry only finalizes locally",
       c do
    before = versions(c.cve)
    test = self()

    adapter(fn request ->
      send(test, :one_creation)
      # Inject a real local write failure, scoped to this sandbox transaction.
      Repo.query!(
        "ALTER TABLE advisory_decisions ADD CONSTRAINT reject_test_ticket CHECK (decision <> 'create_ticket') NOT VALID"
      )

      response(request, %{"id" => 58})
    end)

    id = c.operation
    assert {:error, {:finalization_conflict, ^id}} = save(c, before)
    assert_receive :one_creation
    assert Repo.get!(TicketOperation, id).state == "remote_created"
    assert Repo.aggregate(Decisions.Decision, :count) == 0
    refute_receive {:workspace_changed, _}
    Repo.query!("ALTER TABLE advisory_decisions DROP CONSTRAINT reject_test_ticket")
    assert {:ok, [decision]} = save(c, before)
    assert decision.metadata["ticket_url"] =~ "/58"
    assert Repo.get!(TicketOperation, id).state == "completed"
    refute_receive :one_creation
  end

  test "concurrent same-ID replay and overlapping new operation cannot issue a second POST", c do
    before = versions(c.cve)
    test = self()
    supervisor = start_supervised!({Task.Supervisor, []})

    adapter(fn request ->
      send(test, {:creation_waiting, self(), Repo.in_transaction?()})

      receive do
        :complete_creation -> response(request, %{"id" => 64})
      after
        5_000 -> {request, %Req.TransportError{reason: :timeout}}
      end
    end)

    task = Task.Supervisor.async_nolink(supervisor, fn -> save(c, before) end)
    assert_receive {:creation_waiting, worker, false}, 2_000
    id = c.operation
    assert {:error, {:reconciliation_required, ^id}} = save(c, before)
    assert {:error, {:operation_pending, ^id}} = save(c, before, Ecto.UUID.generate())
    assert Repo.get!(TicketOperation, id).state == "pending"
    send(worker, :complete_creation)
    assert {:ok, [_]} = Task.await(task)
    refute_receive {:creation_waiting, _, _}
    assert Repo.aggregate(TicketOperation, :count) == 1
    assert Repo.aggregate(Decisions.Decision, :count) == 1
  end

  test "viewer, forged principal and revoked sessions cannot save or reconcile", c do
    {viewer, viewer_principal} = principal("viewer")
    before = versions(c.cve)

    assert {:error, :forbidden} =
             Commit.save(c.cve, [c.target.id], before, c.operation, attrs(), viewer_principal)

    assert {:error, :unauthenticated} =
             Commit.save(c.cve, [c.target.id], before, c.operation, attrs(), %{
               viewer
               | role: "admin"
             })

    assert {:error, :forbidden} = Commit.reconcile(c.operation, viewer_principal)
    assert {:error, :unauthenticated} = Commit.reconcile(c.operation, nil)
    Accounts.revoke_session(c.principal.token)
    assert {:error, :unauthenticated} = save(c, before)
    assert Repo.aggregate(TicketOperation, :count) == 0
    refute_receive {:workspace_changed, _}
  end

  test "non-ticket authenticated commits broadcast once, failures and replay do not", c do
    before = versions(c.cve)

    args = [
      c.cve,
      [c.target.id],
      before,
      c.operation,
      %{"action" => "fixed", "actor" => "forged"},
      c.principal
    ]

    assert {:ok, [decision]} = apply(Commit, :save, args)
    assert decision.actor == c.user.email
    assert decision.metadata["user_id"] == c.user.id
    cve = c.cve
    assert_receive {:workspace_changed, ^cve}
    assert {:ok, [^decision]} = apply(Commit, :save, args)

    assert {:error, :conflict} =
             Commit.save(
               c.cve,
               [c.target.id],
               before,
               Ecto.UUID.generate(),
               %{"action" => "fixed"},
               c.principal
             )

    refute_receive {:workspace_changed, _}
  end

  test "Azure project and work item type are path-encoded, not form-encoded", c do
    System.put_env("ADO_PROJECT", "Security Projects")
    System.put_env("ADO_WORK_ITEM_TYPE", "User Story")
    test = self()

    adapter(fn request ->
      send(test, {:encoded_path, request.url.path})
      response(request, %{"id" => 81})
    end)

    assert {:ok, [decision]} = save(c, versions(c.cve))

    assert_receive {:encoded_path,
                    "/test-only/Security%20Projects/_apis/wit/workitems/$User%20Story"}

    assert decision.metadata["ticket_url"] ==
             "https://dev.azure.com/test-only/Security%20Projects/_workitems/edit/81"
  end

  test "transport redacts exceptional outcomes and cannot override no-retry configuration", c do
    adapter(fn _request -> raise "sensitive not-a-real-credential" end)
    id = c.operation
    assert {:error, {:reconciliation_required, ^id}} = save(c, versions(c.cve))
    refute inspect(Repo.get!(TicketOperation, id)) =~ "not-a-real-credential"
    assert {:ok, summary} = Commit.operation(id, c.principal)

    assert Map.keys(summary) |> Enum.sort() == [
             :cve,
             :id,
             :marker,
             :state,
             :target_ids,
             :ticket_url
           ]

    {_, other} = principal("reviewer")
    assert {:error, :forbidden} = Commit.operation(id, other)
    {_, admin} = principal("admin")
    assert {:ok, ^summary} = Commit.operation(id, admin)
    assert {:ok, destination} = AzureDevOps.destination()
    System.put_env("ADO_PROJECT", "Different")
    assert {:error, :configuration_changed} = AzureDevOps.create_payload(destination, [])
  end

  test "the creation request matches the documented Azure DevOps REST contract", c do
    test = self()

    adapter(fn request ->
      send(
        test,
        {:contract,
         %{
           method: request.method,
           scheme: request.url.scheme,
           host: request.url.host,
           path: request.url.path,
           query: request.url.query,
           content_type: header(request, "content-type"),
           authorization: header(request, "authorization"),
           auth_option: request.options[:auth],
           patch: Jason.decode!(IO.iodata_to_binary(request.body))
         }}
      )

      response(request, %{"id" => 42})
    end)

    assert {:ok, [decision]} = save(c, versions(c.cve))
    assert_receive {:contract, contract}

    # POST {org}/{project}/_apis/wit/workitems/${type}?api-version=7.1 — the
    # documented work item creation route. Azure rejects any other media type
    # than JSON Patch and authenticates the PAT as the Basic-auth password.
    assert contract.method == :post
    assert contract.scheme == "https"
    assert contract.host == "dev.azure.com"
    assert contract.path == "/test-only/Security/_apis/wit/workitems/$Task"
    assert contract.query == "api-version=7.1"
    assert contract.content_type == "application/json-patch+json"

    expected_auth = "Basic " <> Base.encode64(":" <> System.get_env("ADO_PAT"))

    cond do
      contract.authorization ->
        assert contract.authorization == expected_auth

      contract.auth_option ->
        assert contract.auth_option == {:basic, ":" <> System.get_env("ADO_PAT")}

      true ->
        flunk("the creation request carried no authentication")
    end

    # A JSON Patch document: add operations against System fields only.
    assert is_list(contract.patch) and contract.patch != []

    assert Enum.all?(contract.patch, fn op ->
             op["op"] == "add" and String.starts_with?(op["path"], "/fields/System.")
           end)

    assert Enum.any?(contract.patch, fn op ->
             op["path"] == "/fields/System.Title" and op["value"] == "#{c.cve} needs to be fixed"
           end)

    assert decision.metadata["ticket_url"] ==
             "https://dev.azure.com/test-only/Security/_workitems/edit/42"
  end

  test "the ticket lifecycle issues only create and read requests, never update or delete", c do
    before = versions(c.cve)
    test = self()

    adapter(fn request ->
      send(test, {:surface, request.method, request.url.path})
      {request, %Req.TransportError{reason: :timeout}}
    end)

    id = c.operation
    assert {:error, {:reconciliation_required, ^id}} = save(c, before)

    operation = Repo.get!(TicketOperation, id)

    adapter(fn request ->
      send(test, {:surface, request.method, request.url.path})

      cond do
        String.ends_with?(request.url.path, "/_apis/wit/wiql") ->
          response(request, %{"workItems" => [%{"id" => 42}]})

        String.ends_with?(request.url.path, "/_apis/wit/workitems/42") ->
          response(request, %{
            "id" => 42,
            "fields" => %{"System.Tags" => "security; " <> operation.marker}
          })

        true ->
          response(request, %{"id" => 42})
      end
    end)

    assert {:ok, [decision]} = Commit.reconcile(id, c.principal)
    assert decision.metadata["ticket_url"] =~ "/42"

    # The complete request surface across creation and reconciliation:
    # one work item creation POST, one read-only WIQL search, one GET. Any
    # modification (PATCH on the work item) or deletion (DELETE, $destroy)
    # would have to appear here — and neither does.
    assert_receive {:surface, :post, "/test-only/Security/_apis/wit/workitems/$Task"}
    assert_receive {:surface, :post, "/test-only/Security/_apis/wit/wiql"}
    assert_receive {:surface, :get, "/test-only/Security/_apis/wit/workitems/42"}
    refute_receive {:surface, _, _}
  end

  # Req keeps headers downcased; both the map and pair-list shapes are handled
  # so the assertion fails on a missing header, not on representation.
  defp header(%{headers: headers}, name) when is_map(headers),
    do: headers |> Map.get(name, []) |> List.wrap() |> List.first()

  defp header(%{headers: headers}, name) do
    case List.keyfind(headers, name, 0) do
      {_key, value} -> value |> List.wrap() |> List.first()
      nil -> nil
    end
  end
end
