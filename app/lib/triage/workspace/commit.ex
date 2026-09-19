defmodule Triage.Workspace.Commit do
  @moduledoc "Atomic explicit-placement decisions using the existing advisory history. No inventory writes or external calls."
  import Ecto.Query
  alias Triage.{Decisions, Repo, Workspace}
  alias Triage.Decisions.Decision

  @actions ~w(request_remediation investigate accepted_risk request_verification)
  # All tables read by Workspace.targets/2. DML participates even for new scopes.
  @tables "advisory_decisions, exposure_evidences, findings, image_placements, images, intel_advisories"
  def actions, do: @actions

  def form(attrs) do
    types = %{action: :string, owner: :string, actor: :string, reason: :string, due_on: :date}

    {%{}, types}
    |> Ecto.Changeset.cast(attrs, Map.keys(types))
    |> Ecto.Changeset.update_change(:owner, &String.trim/1)
    |> Ecto.Changeset.update_change(:actor, &String.trim/1)
    |> Ecto.Changeset.update_change(:reason, &String.trim/1)
    |> Ecto.Changeset.validate_required(Map.keys(types))
    |> Ecto.Changeset.validate_inclusion(:action, @actions)
    |> Ecto.Changeset.validate_length(:owner, min: 1, max: 120)
    |> Ecto.Changeset.validate_length(:actor, min: 1, max: 120)
    |> Ecto.Changeset.validate_length(:reason, min: 3, max: 2000)
  end

  @doc "Versions are server-captured target fingerprints, never recomputed from a browser's proposed evidence."
  def save(cve, target_ids, versions, operation_id, attrs) do
    changeset = form(attrs)

    with true <- valid_binding?(cve, target_ids, versions, operation_id),
         {:ok, fields} <- Ecto.Changeset.apply_action(changeset, :insert) do
      ids = Enum.sort(Enum.uniq(target_ids))
      request_hash = Workspace.hash({cve, ids, Map.take(versions, ids), fields})

      Repo.transaction(fn ->
        lock!()

        prior =
          Repo.all(
            from d in Decision, where: d.operation_id == ^operation_id, order_by: d.placement_id
          )

        replay_or_commit(prior, cve, ids, versions, operation_id, fields, request_hash)
      end)
    else
      false -> {:error, :invalid_targets}
      error -> error
    end
  end

  defp replay_or_commit([], cve, ids, versions, operation, fields, hash),
    do: commit!(cve, ids, versions, operation, fields, hash)

  defp replay_or_commit(prior, _cve, ids, _versions, _operation, _fields, hash) do
    if Enum.map(prior, & &1.placement_id) == ids and
         Enum.all?(prior, &(&1.metadata["request_hash"] == hash)),
       do: prior,
       else: Repo.rollback(:operation_reused)
  end

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

  defp commit!(cve, ids, versions, operation, fields, request_hash) do
    if Date.compare(fields.due_on, Date.utc_today()) == :lt, do: Repo.rollback(:past_date)
    current = Workspace.targets(%{"cve" => cve}) |> Enum.filter(&(&1.id in ids))

    valid =
      length(current) == length(ids) and
        Enum.all?(current, &(&1.active? and versions[&1.id] == &1.fingerprint))

    unless valid, do: Repo.rollback(:conflict)
    expires_at = fields.due_on |> Date.add(1) |> DateTime.new!(~T[00:00:00], "Etc/UTC")

    Enum.map(current, fn target ->
      attrs = %{
        cve: cve,
        placement_id: target.id,
        decision: fields.action,
        reason: fields.reason,
        actor: fields.actor,
        work_owner: fields.owner,
        due_on: fields.due_on,
        expires_at: expires_at,
        operation_id: operation,
        metadata: %{
          "source" => "workspace",
          "identity" => "self-declared",
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
end
