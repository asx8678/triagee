defmodule Triage.Classifier.Snapshots do
  @moduledoc "Exact-target, bounded-age manual source/register attestations; no inferred live provenance."
  import Ecto.Changeset
  alias Triage.Classifier.Evidence
  alias Triage.{Exposure, Intel, Workspace}
  @max_age 86_400

  def target(cve, placement_id) do
    case Workspace.targets(%{"cve" => cve, "placement_ids" => [placement_id]}) do
      [%{active?: true} = target] -> {:ok, target}
      _ -> {:error, :target_unavailable}
    end
  end

  def prepare(cve, placement_id, attrs, actor, now) do
    types = %{
      workload_uid: :string,
      service: :string,
      source_ref: :string,
      register_ref: :string,
      applicability: :string,
      applicability_ref: :string,
      rationale: :string,
      cohort: :string,
      mode: :string,
      observed_at: :utc_datetime,
      expires_at: :utc_datetime,
      complete: :boolean,
      packet_hash: :string
    }

    changeset =
      {%{}, types}
      |> cast(attrs, Map.keys(types))
      |> validate_required(Map.keys(types))
      |> validate_inclusion(:complete, [true])
      |> validate_inclusion(:applicability, ~w(affected not_affected unknown))
      |> validate_inclusion(:mode, ~w(manual assisted))

    changeset =
      Enum.reduce(
        ~w(workload_uid service source_ref register_ref applicability_ref rationale cohort)a,
        changeset,
        fn key, acc ->
          acc |> update_change(key, &String.trim/1) |> validate_length(key, min: 3, max: 2000)
        end
      )

    with {:ok, fields} <- apply_action(changeset, :insert),
         :ok <- fresh_window(fields.observed_at, fields.expires_at, now),
         {:ok, target} <- target(cve, placement_id),
         true <- fields.packet_hash == target.packet_hash do
      snapshot = capture(target, fields, now)

      identity =
        Triage.Canonical.hash(
          {target.packet_hash, fields, actor.id, Triage.Classifier.Model.profile()}
        )

      {:ok,
       %Evidence{
         identity: identity,
         cve: cve,
         placement_id: placement_id,
         packet_hash: target.packet_hash,
         workload_uid: fields.workload_uid,
         snapshot: snapshot,
         approved_by: actor.id,
         observed_at: fields.observed_at,
         expires_at: fields.expires_at
       }}
    else
      false -> {:error, :evidence_changed}
      error -> error
    end
  end

  def current?(evidence, now \\ DateTime.utc_now()) do
    approver = Triage.Repo.get(Triage.Accounts.User, evidence.approved_by)

    with true <- approver != nil and approver.enabled and approver.role == "admin",
         :ok <- fresh_window(evidence.observed_at, evidence.expires_at, now),
         {:ok, target} <- target(evidence.cve, evidence.placement_id),
         true <- target.packet_hash == evidence.packet_hash do
      true
    else
      _ -> false
    end
  end

  def current_snapshot(evidence, now) do
    # Refresh only independently verified trust/freshness, not the frozen text.
    # A material change is rejected separately by current?/2.
    snapshot = evidence.snapshot
    exposure = Exposure.current_evidence([evidence.placement_id], now)[evidence.placement_id]

    snapshot
    |> Map.put("exposure", exposure_facts(exposure))
    |> Map.put("kev", kev_facts(evidence.cve, now))
  end

  defp fresh_window(observed, expires, now) do
    if DateTime.compare(observed, now) != :gt and DateTime.compare(expires, now) == :gt and
         DateTime.diff(now, observed) <= @max_age and
         DateTime.diff(expires, observed) in 1..@max_age, do: :ok, else: {:error, :stale_evidence}
  end

  defp capture(target, f, now) do
    exposure = Exposure.current_evidence([target.id], now)[target.id]

    %{
      "inventory" => %{
        "cve" => target.cve,
        "placement_id" => target.id,
        "image_digest" => target.image.digest,
        "packet_hash" => target.packet_hash,
        "owner" => target.placement.owner,
        "environment" => target.placement.environment,
        "namespace" => target.placement.namespace,
        "severity" =>
          target.findings
          |> Enum.max_by(&Triage.Severity.rank(&1.severity))
          |> Map.fetch!(:severity)
          |> Triage.Severity.normalize(),
        "findings" =>
          Enum.map(
            target.findings,
            &Map.take(&1, [:id, :package_name, :package_version, :severity, :description, :fix])
          )
      },
      "source" => %{
        "reference" => f.source_ref,
        "observed_at" => f.observed_at,
        "expires_at" => f.expires_at,
        "complete" => true,
        "kind" => "human_attested_snapshot"
      },
      "register" => %{
        "reference" => f.register_ref,
        "workload_uid" => f.workload_uid,
        "service" => f.service
      },
      "applicability" => %{
        "status" => f.applicability,
        "reference" => f.applicability_ref,
        "rationale" => f.rationale
      },
      "exposure" => exposure_facts(exposure),
      "kev" => kev_facts(target.cve, now),
      "cohort" => f.cohort,
      "experiment_mode" => f.mode,
      "approved_model_profile" => Triage.Classifier.Model.profile()
    }
    |> Jason.encode!()
    |> Jason.decode!()
  end

  defp exposure_facts(nil), do: %{"value" => "unknown", "state" => "none", "usable" => false}

  defp exposure_facts(e),
    do: %{
      "value" => e.exposure,
      "state" => to_string(e.state),
      "usable" => e.usable?,
      "source" => e.source,
      "observed_at" => e.observed_at,
      "expires_at" => e.expires_at
    }

  defp kev_facts(cve, now) do
    generation = Intel.current_generation("kev")

    current =
      generation != nil and generation.complete and
        DateTime.diff(now, generation.fetched_at) in 0..@max_age

    %{
      "listed" => Intel.kev_row(cve) != nil,
      "current" => current,
      "generation_id" => if(generation, do: generation.id),
      "fetched_at" => if(generation, do: generation.fetched_at)
    }
  end
end
