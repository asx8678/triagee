defmodule Triage.Seeds.TimelineSamples do
  @moduledoc "Three explicitly fictional, repeatable CVE lifecycle examples."
  import Ecto.Query
  alias Triage.{Decisions, Inventory, Repo}

  @samples [
    {"CVE-2099-9028", "demo-gateway-parser", "HIGH", ~U[2026-09-22 08:00:00Z], "accepted_risk",
     ~U[2026-09-22 10:00:00Z], nil},
    {"CVE-2099-9029", "demo-worker-transport", "MEDIUM", ~U[2026-09-21 07:00:00Z],
     "accepted_risk", ~U[2026-09-21 12:00:00Z], nil},
    {"CVE-2099-9030", "demo-file-parser", "HIGH", ~U[2026-09-21 09:00:00Z], "fixed",
     ~U[2026-09-22 10:30:00Z], ~U[2026-09-22 11:00:00Z]}
  ]

  @doc "Adds missing samples; existing findings and review history are never rewritten."
  def seed! do
    {:ok, :ok} =
      Repo.transaction(fn ->
        # Serialize repeated seed runs, including the existence check.
        Repo.query!("SELECT pg_advisory_xact_lock(2099, 9028)")

        for {cve, package, severity, detected, action, acted, cleared} <- @samples do
          unless Repo.exists?(from(f in Inventory.Finding, where: f.cve == ^cve)) do
            add_sample!(cve, package, severity, detected, action, acted, cleared)
          end
        end

        :ok
      end)

    :ok
  end

  defp add_sample!(cve, package, severity, detected, action, acted, cleared) do
    digest = :crypto.hash(:sha256, "fictional-timeline-" <> cve) |> Base.encode16(case: :lower)

    {:ok, image} =
      Inventory.upsert_image(
        %{
          digest: "sha256:" <> digest,
          repository: "demo.invalid/timeline/" <> package,
          tag: "sample",
          description: "Fictional timeline example"
        },
        detected
      )

    {:ok, finding} =
      Inventory.upsert_finding(
        image,
        %{
          cve: cve,
          package_name: package,
          package_version: "1.0.0-demo",
          severity: severity,
          description:
            "FICTIONAL TIMELINE SAMPLE: " <>
              if(action == "accepted_risk",
                do: "detected, then whitelisted after review. The finding remains present.",
                else: "detected, then marked fixed; a later scan no longer detected the finding."
              ),
          url: nil
        },
        detected,
        reopen: false
      )

    # Two deployment records deliberately share one operation: one visible step.
    for environment <- ["dev", "staging"] do
      {:ok, placement} =
        Inventory.upsert_placement(
          image,
          %{namespace: "timeline-samples", owner: "presentation", environment: environment},
          detected
        )

      {:ok, _decision} =
        Decisions.record(%{
          cve: cve,
          placement_id: placement.id,
          decision: action,
          actor: "Demo reviewer",
          reason:
            if(action == "accepted_risk",
              do: "Fictional sample: upgrade scheduled; risk accepted temporarily after review.",
              else: "Fictional sample: patched package deployed; scan verification follows."
            ),
          decided_at: acted,
          expires_at: if(action == "accepted_risk", do: ~U[2026-10-22 00:00:00Z]),
          operation_id: "timeline-sample-" <> cve,
          metadata: %{
            "source" => "fictional-timeline-sample",
            "expiry_boundary" => "exclusive",
            "target" => %{"team" => "presentation", "environment" => environment}
          }
        })
    end

    if cleared do
      Inventory.record_event(
        finding.id,
        "resolved",
        cleared,
        "Fictional sample scan: finding absent."
      )

      Inventory.set_lifecycle(finding.id, resolved_at: cleared)
    end
  end
end
