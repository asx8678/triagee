defmodule Triage.Workspace.Commit do
  @moduledoc "Explicit-placement decisions with local history and opt-in Azure DevOps ticket creation. No inventory writes."
  import Ecto.Query
  alias Triage.{Accounts, AzureDevOps, Decisions, Repo, Workspace}
  alias Triage.Decisions.Decision
  alias Triage.Workspace.TicketOperation

  @actions ~w(request_remediation investigate accepted_risk request_verification fixed create_ticket)
  # All tables read by Workspace.targets/2. DML participates even for new scopes.
  @tables "advisory_decisions, exposure_evidences, findings, image_placements, images, intel_advisories"
  def actions, do: @actions

  def default_due_on(today \\ Date.utc_today()) do
    month = today.month + 3
    year = today.year + div(month - 1, 12)
    month = rem(month - 1, 12) + 1
    first = Date.new!(year, month, 1)
    Date.new!(year, month, min(today.day, Date.days_in_month(first)))
  end

  def form(attrs) do
    attrs = Map.new(attrs, fn {k, v} -> {to_string(k), v} end)

    attrs =
      if attrs["action"] == "accepted_risk" and attrs["due_on"] in [nil, ""],
        do: Map.put(attrs, "due_on", Date.to_iso8601(default_due_on())),
        else: attrs

    attrs =
      if attrs["action"] in ["fixed", "create_ticket"],
        do: Map.drop(attrs, ["reason", "owner", "due_on"]),
        else: attrs

    types = %{action: :string, owner: :string, actor: :string, reason: :string, due_on: :date}

    {%{}, types}
    |> Ecto.Changeset.cast(attrs, Map.keys(types))
    |> Ecto.Changeset.update_change(:owner, &String.trim/1)
    |> Ecto.Changeset.update_change(:actor, &String.trim/1)
    |> Ecto.Changeset.update_change(:reason, &String.trim/1)
    |> Ecto.Changeset.validate_required(
      if attrs["action"] in ["fixed", "create_ticket", "accepted_risk"],
        do: [:action],
        else: Map.keys(types)
    )
    |> Ecto.Changeset.validate_inclusion(:action, @actions)
    |> Ecto.Changeset.validate_length(:owner, min: 1, max: 120)
    |> Ecto.Changeset.validate_length(:actor, min: 1, max: 120)
    |> Ecto.Changeset.validate_length(:reason, max: 2000)
  end

  @doc "Legacy trusted domain/CLI API. Self-declared, never an authenticated web entry point."
  def save(cve, ids, versions, operation, attrs),
    do: save_as(cve, ids, versions, operation, attrs, %{"identity" => "self-declared"})

  @doc "Authenticated save. Accounts revalidates the principal; submitted actor values are ignored."
  def save(cve, ids, versions, operation, attrs, principal) do
    with {:ok, user} <- Accounts.authorize(principal, :review) do
      attrs = Map.new(attrs, fn {key, value} -> {to_string(key), value} end)
      attrs = Map.put(attrs, "actor", user.email)

      save_as(cve, ids, versions, operation, attrs, %{
        "identity" => "authenticated",
        "user_id" => user.id
      })
    end
  end

  # Versions are server-captured fingerprints, never browser-proposed evidence.
  defp save_as(cve, target_ids, versions, operation_id, attrs, identity) do
    with true <- valid_binding?(cve, target_ids, versions, operation_id),
         {:ok, fields} <- Ecto.Changeset.apply_action(form(attrs), :insert),
         false <- Repo.in_transaction?() do
      ids = Enum.sort(Enum.uniq(target_ids))
      fields = Map.put_new(fields, :actor, "Local workspace")
      hash = Workspace.hash({cve, ids, Map.take(versions, ids), fields, identity})

      Repo.transaction(fn ->
        prepare_save!(cve, ids, versions, operation_id, fields, identity, hash)
      end)
      |> finish_save(cve)
    else
      false -> {:error, :invalid_targets}
      true -> {:error, :nested_transaction}
      error -> error
    end
  end

  defp prepare_save!(cve, ids, versions, operation_id, fields, identity, hash) do
    lock!()
    prior = decisions(operation_id)
    existing = Repo.get(TicketOperation, operation_id)

    cond do
      prior != [] ->
        if Enum.map(prior, & &1.placement_id) == ids and
             Enum.all?(prior, &(&1.metadata["request_hash"] == hash)),
           do: {:decisions, prior, false},
           else: Repo.rollback(:operation_reused)

      existing != nil ->
        if existing.request_hash == hash,
          do: {:resume, existing},
          else: Repo.rollback(:operation_reused)

      fields.action == "create_ticket" ->
        claim_ticket!(cve, ids, versions, operation_id, fields, identity, hash)

      true ->
        result = commit!(cve, ids, versions, operation_id, fields, hash, identity, nil)
        {:decisions, result, true}
    end
  end

  defp decisions(operation),
    do:
      Repo.all(from d in Decision, where: d.operation_id == ^operation, order_by: d.placement_id)

  defp claim_ticket!(cve, ids, versions, id, fields, identity, hash) do
    case TicketOperation.pending_for_scope(cve, ids) do
      nil -> :ok
      pending -> Repo.rollback({:operation_pending, pending.id})
    end

    current = current_targets!(cve, ids, versions)

    destination =
      case AzureDevOps.destination() do
        {:ok, destination} -> destination
        {:error, message} -> Repo.rollback({:ticket, message})
      end

    # The marker is generated here, never accepted from the browser.
    reference = Ecto.UUID.generate()
    payload = AzureDevOps.payload(cve, current, reference) |> Jason.encode!() |> Jason.decode!()

    operation =
      Repo.insert!(%TicketOperation{
        id: id,
        cve: cve,
        target_ids: ids,
        versions:
          Map.new(Map.take(versions, ids), fn {id, version} -> {to_string(id), version} end),
        fields: %{"action" => fields.action, "actor" => fields.actor},
        identity: identity,
        request_hash: hash,
        payload_hash: Workspace.hash({destination, payload}),
        payload: payload,
        destination: destination,
        marker: AzureDevOps.marker(reference)
      })

    {:create, operation}
  end

  defp finish_save({:ok, {:decisions, result, changed?}}, cve) do
    if changed?, do: broadcast(cve)
    {:ok, result}
  end

  defp finish_save({:ok, {:create, operation}}, _cve) do
    # This executes only after the durable claim transaction releases all locks.
    case AzureDevOps.create_payload(operation.destination, operation.payload) do
      {:ok, url} ->
        with {:ok, operation} <- TicketOperation.remember_remote(operation, url),
             do: finalize(operation, TicketOperation.versions(operation), operation.identity)

      {:error, _} ->
        TicketOperation.unknown(operation)
    end
  end

  defp finish_save({:ok, {:resume, %{state: "remote_created"} = operation}}, _cve),
    do: finalize(operation, TicketOperation.versions(operation), operation.identity)

  defp finish_save({:ok, {:resume, operation}}, _cve),
    do: {:error, {:reconciliation_required, operation.id}}

  defp finish_save({:error, reason}, _cve), do: {:error, reason}

  defp broadcast(cve),
    do: Phoenix.PubSub.broadcast(Triage.PubSub, "workspace:changes", {:workspace_changed, cve})

  defp valid_binding?(cve, ids, versions, operation) do
    is_binary(cve) and byte_size(cve) in 1..200 and is_list(ids) and length(ids) in 1..200 and
      Enum.all?(ids, &(is_integer(&1) and &1 > 0)) and is_map(versions) and
      is_binary(operation) and byte_size(operation) in 16..100
  end

  defp lock! do
    case Repo.query("LOCK TABLE #{@tables} IN SHARE ROW EXCLUSIVE MODE NOWAIT", [],
           mode: :savepoint
         ) do
      {:ok, _} ->
        :ok

      {:error, %Postgrex.Error{postgres: %{code: :lock_not_available}}} ->
        Repo.rollback(:conflict)

      {:error, error} ->
        raise error
    end
  end

  defp current_targets!(cve, ids, versions) do
    current =
      Workspace.targets(%{"cve" => cve, "placement_ids" => ids})
      |> Enum.filter(&(&1.id in ids))
      |> Enum.sort_by(& &1.id)

    valid =
      length(current) == length(ids) and
        Enum.all?(current, &(&1.active? and versions[&1.id] == &1.fingerprint))

    unless valid, do: Repo.rollback(:conflict)
    current
  end

  defp commit!(cve, ids, versions, operation, fields, request_hash, identity, ticket_url) do
    validate_due_date!(fields)
    current = current_targets!(cve, ids, versions)
    expires_at = expires_at(fields)

    Enum.map(current, fn target ->
      attrs = %{
        cve: cve,
        placement_id: target.id,
        decision: fields.action,
        reason: Map.get(fields, :reason) || "",
        actor: Map.get(fields, :actor) || "Local workspace",
        work_owner: Map.get(fields, :owner),
        due_on: Map.get(fields, :due_on),
        expires_at: expires_at,
        operation_id: operation,
        metadata: %{
          "source" => "workspace",
          "ticket_url" => ticket_url,
          "fixed_at" => if(fields.action == "fixed", do: DateTime.to_iso8601(DateTime.utc_now())),
          "identity" => identity["identity"],
          "user_id" => identity["user_id"],
          "reconciled_by_user_id" => identity["reconciled_by_user_id"],
          "reconciled_versions" => identity["reconciled_versions"],
          "timezone" => "Etc/UTC",
          "expiry_boundary" => "exclusive",
          "request_hash" => request_hash,
          "evidence_hash" => target.evidence_hash,
          "policy_version" => Triage.Risk.policy_version(),
          "observed_evidence" => %{
            "exposure" => target.exposure,
            "priority" => target.risk.priority,
            "findings" =>
              Enum.map(
                target.findings,
                &Map.take(&1, [
                  :id,
                  :package_name,
                  :package_version,
                  :severity,
                  :fix,
                  :description,
                  :first_seen,
                  :last_seen,
                  :resolved_at,
                  :suppressed
                ])
              )
          },
          "target" => %{
            "placement_id" => target.id,
            "team" => target.placement.owner,
            "environment" => target.placement.environment,
            "namespace" => target.placement.namespace,
            "image_id" => target.image.id,
            "digest" => target.image.digest,
            "finding_ids" => Enum.map(target.findings, & &1.id),
            "packages" =>
              Enum.map(
                target.findings,
                &%{"id" => &1.id, "name" => &1.package_name, "version" => &1.package_version}
              )
          }
        }
      }

      # Return the same JSON representation on first commit and replay.
      attrs = Map.update!(attrs, :metadata, &Jason.decode!(Jason.encode!(&1)))

      case Decisions.record(attrs) do
        {:ok, decision} -> decision
        {:error, error} -> Repo.rollback(error)
      end
    end)
  end

  defp validate_due_date!(fields) do
    if fields.action not in ["fixed", "create_ticket"] and
         Date.compare(fields.due_on, Date.utc_today()) == :lt,
       do: Repo.rollback(:past_date)
  end

  defp expires_at(%{action: action}) when action in ["fixed", "create_ticket"], do: nil

  defp expires_at(fields),
    do: fields.due_on |> Date.add(1) |> DateTime.new!(~T[00:00:00], "Etc/UTC")

  @doc """
  Operator recovery: locate the unique marker with read-only WIQL/GET, then commit
  local decisions. Missing or ambiguous results remain blocked, never authorize
  another creation. The original reviewer or an admin may reconcile.

  UI/operator workflow (no Azure credentials are returned):

      {:ok, summary} = Commit.operation(operation_id, principal)
      Commit.reconcile(summary.id, principal)

  A `{:finalization_conflict, id}` means the remote ticket is already durable.
  Review the current exact targets, capture their fingerprints on the server,
  and explicitly call `reconcile(id, versions, principal)` to accept that newer
  evidence. The original payload/actor/fingerprints remain immutable; decisions
  record the reconciling user and accepted fingerprints separately.

  A `{:reconciliation_required, id}` means keep the existing operation and its
  target claim. Search Azure by `summary.marker`, check service availability and
  restore the original server destination configuration if necessary, then
  reconcile again. Empty/ambiguous search results do not authorize a new ticket,
  deleting the claim, resetting state, or inventing a replacement operation ID.
  """
  def reconcile(id, principal), do: reconcile(id, nil, principal)

  @doc "Explicitly accept freshly reviewed server-captured fingerprints after a finalization conflict. Never POSTs a work item."
  def reconcile(id, versions, principal) do
    with false <- Repo.in_transaction?(),
         {:ok, user} <- Accounts.authorize(principal, :review),
         {:ok, operation} <- owned_operation(id, user),
         {:ok, operation} <- recover_remote(operation) do
      identity = reconciliation_identity(operation.identity, user.id, versions)

      finalize(operation, versions || TicketOperation.versions(operation), identity)
    else
      true -> {:error, :nested_transaction}
      error -> error
    end
  end

  defp reconciliation_identity(identity, user_id, versions) do
    identity = Map.put(identity, "reconciled_by_user_id", user_id)

    if is_map(versions),
      do:
        Map.put(
          identity,
          "reconciled_versions",
          Map.new(versions, fn {id, value} -> {to_string(id), value} end)
        ),
      else: identity
  end

  @doc "Non-secret operation summary for the original reviewer or an admin."
  def operation(id, principal) do
    with {:ok, user} <- Accounts.authorize(principal, :review),
         {:ok, operation} <- owned_operation(id, user) do
      {:ok, Map.take(operation, [:id, :cve, :target_ids, :state, :marker, :ticket_url])}
    end
  end

  defp owned_operation(id, user) when is_binary(id) do
    case Repo.get(TicketOperation, id) do
      nil ->
        {:error, :not_found}

      operation ->
        if operation.identity["user_id"] == user.id or user.role == "admin",
          do: {:ok, operation},
          else: {:error, :forbidden}
    end
  end

  defp owned_operation(_, _), do: {:error, :not_found}

  defp recover_remote(%{state: state} = operation) when state in ["remote_created", "completed"],
    do: {:ok, operation}

  defp recover_remote(operation) do
    case AzureDevOps.reconcile(operation.destination, operation.marker) do
      {:ok, url} -> TicketOperation.remember_remote(operation, url)
      {:error, _} -> {:error, {:reconciliation_required, operation.id}}
    end
  end

  defp finalize_locked!(id, versions, identity) do
    lock!()
    operation = Repo.get!(TicketOperation, id)

    if operation.state == "completed" do
      {:decisions, decisions(operation.id), false}
    else
      unless operation.state == "remote_created", do: Repo.rollback(:remote_not_confirmed)

      result =
        commit!(
          operation.cve,
          operation.target_ids,
          versions,
          operation.id,
          TicketOperation.fields(operation),
          operation.request_hash,
          identity,
          operation.ticket_url
        )

      operation |> Ecto.Changeset.change(state: "completed") |> Repo.update!()
      {:decisions, result, true}
    end
  end

  defp finalize(operation, versions, identity) do
    result =
      Repo.transaction(fn -> finalize_locked!(operation.id, versions, identity) end)

    case result do
      {:ok, _} -> finish_save(result, operation.cve)
      {:error, _} -> {:error, {:finalization_conflict, operation.id}}
    end
  rescue
    # The independently persisted remote result survives rollback/DB failure.
    _ -> {:error, {:finalization_conflict, operation.id}}
  end
end
