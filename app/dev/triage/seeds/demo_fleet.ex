defmodule Triage.Seeds.DemoFleet do
  @moduledoc "Additive, explicitly fictional presentation fleet. Never resets an existing case."
  import Ecto.Query
  alias Triage.{Decisions, Exposure, Inventory, Repo, Workspace}
  alias Triage.Inventory.{Finding, Image, ImagePlacement}

  @workloads [
    {"checkout-api", "demo-payments", "aks-eu/payments", "Azure AKS · West Europe",
     "internet_exposed"},
    {"payment-worker", "demo-payments", "aks-eu/payments", "Azure AKS · West Europe", "internal"},
    {"billing-scheduler", "demo-payments", "eks-us/billing", "AWS EKS · US East", "internal"},
    {"customer-portal", "demo-commerce", "aks-eu/storefront", "Azure AKS · West Europe",
     "internet_exposed"},
    {"catalog-api", "demo-commerce", "eks-us/catalog", "AWS EKS · US East", "internal"},
    {"order-events", "demo-commerce", "aks-eu/orders", "Azure AKS · West Europe", "internal"},
    {"identity-provider", "demo-identity", "aks-eu/identity", "Azure AKS · West Europe",
     "internet_exposed"},
    {"api-gateway", "demo-identity", "edge-eu/gateway", "Edge cluster · Frankfurt",
     "internet_exposed"},
    {"postgres", "demo-data", "aks-eu/data", "Azure AKS · West Europe", "internal"},
    {"redis", "demo-data", "eks-us/cache", "AWS EKS · US East", "internal"},
    {"kafka", "demo-data", "eks-us/streaming", "AWS EKS · US East", "internal"},
    {"opensearch", "demo-data", "eks-us/search", "AWS EKS · US East", "internal"},
    {"grafana", "demo-observability", "aks-eu/monitoring", "Azure AKS · West Europe", "internal"},
    {"otel-collector", "demo-observability", "eks-us/telemetry", "AWS EKS · US East", "internal"},
    {"ci-runner", "demo-platform", "vm-eu/build", "Linux VM pool · West Europe", "internal"},
    {"artifact-registry", "demo-platform", "aks-eu/registry", "Azure AKS · West Europe",
     "internal"},
    {"windows-batch", "demo-platform", "vm-eu/batch", "Windows VM pool · West Europe", "unknown"},
    {"edge-agent", "demo-edge", "edge-eu/retail", "Edge devices · EU retail", "unknown"}
  ]

  # The package names provide realistic context; these IDs and vulnerability
  # narratives are invented and must never be presented as vendor advisories.
  @scenarios [
    {9101, "checkout-api", "jackson-databind", "CRITICAL", :needs,
     "An untrusted checkout payload reaches a vulnerable deserialization path on the public API. Prioritize production before the next payment peak."},
    {9102, "payment-worker", "netty", "HIGH", :progress,
     "A malformed queue message can exhaust payment workers. A simulated remediation ticket is assigned to the payments team."},
    {9103, "billing-scheduler", "commons-compress", "MEDIUM", :accepted,
     "The affected archive helper is installed but unused by the scheduled billing job. A temporary exception has an owner and a planned upgrade window."},
    {9104, "customer-portal", "next", "CRITICAL", :needs,
     "A crafted request can bypass the public storefront route guard. The same image is deployed to production, staging and development."},
    {9105, "catalog-api", "spring-web", "HIGH", :fixed,
     "The team reports deploying a patched catalogue service. The scanner still reports the original package, so the fix is not yet scan-verified."},
    {9106, "order-events", "protobuf-java", "MEDIUM", :expiring,
     "A temporary exception for internal order events expires in two days. Demonstrate an upcoming renewal rather than a permanent suppression."},
    {9107, "identity-provider", "keycloak-core", "CRITICAL", :needs,
     "A token validation edge case affects the externally reachable sign-in service. The identity team must verify the affected authentication flow."},
    {9108, "api-gateway", "envoy", "HIGH", :mixed,
     "One CVE has different outcomes per environment: production needs review, staging has a work item, and development has a temporary exception."},
    {9109, "postgres", "libssl", "HIGH", :progress,
     "A shared TLS library affects the private database image. A rolling database restart is planned after replica health checks."},
    {9110, "redis", "redis-server", "HIGH", :accepted,
     "The affected command is restricted to administrators on a private cache network. Risk was accepted temporarily pending the maintenance window."},
    {9111, "kafka", "snappy-java", "MEDIUM", :needs,
     "A malformed compressed batch may interrupt event ingestion. Confirm whether untrusted producers can submit the affected payload format."},
    {9112, "opensearch", "log4j-core", "HIGH", :verified,
     "The search image was patched and a later simulated scan no longer detected the package. Compare the scan lifecycle with a reported-only fix."},
    {9113, "grafana", "golang.org/x/net", "MEDIUM", :expired,
     "A monitoring exception expired yesterday. The finding is still present and has returned to the review queue."},
    {9114, "otel-collector", "grpc", "MEDIUM", :progress,
     "A malformed telemetry request may stop ingestion. The observability team is preparing a staged collector rollout."},
    {9115, "ci-runner", "git", "HIGH", :needs,
     "Untrusted pull-request content reaches a shared Linux build runner. Distinguish ephemeral build jobs from production application containers."},
    {9116, "artifact-registry", "distribution", "HIGH", :fixed,
     "The registry rollout is reported complete. Deployment verification is pending, so the original scanner observation remains visible."},
    {9117, "windows-batch", "System.Text.Json", "MEDIUM", :needs,
     "A Windows batch image parses partner-supplied files. Network exposure is unknown and the asset owner must validate reachability."},
    {9118, "edge-agent", "busybox", "LOW", :accepted,
     "The affected diagnostic utility is not invoked by normal retail device operation. A time-limited exception covers the next edge-fleet update."},
    {9119, "checkout-api payment-worker customer-portal", "openssl", "CRITICAL", :needs,
     "A shared base-layer TLS issue spans three services and two teams. Demonstrate narrowing the decision to a single team and environment."},
    {9120, "ci-runner artifact-registry", "curl", "MEDIUM", :accepted,
     "Only a disabled optional transfer protocol is affected. The scoped temporary exception does not cover unrelated application images."},
    {9121, "postgres redis kafka", "glibc", "HIGH", :progress,
     "A common operating-system library spans the data platform. Coordinate the upgrade sequence across databases, cache and streaming."},
    {9122, "grafana otel-collector", "go-jose", "HIGH", :needs,
     "An optional authentication integration needs validation across monitoring and telemetry workloads before any exception is considered."},
    {9123, "catalog-api order-events", "zlib", "MEDIUM", :verified,
     "A compression-library update was rolled out and a subsequent simulated scan cleared both service images."},
    {9124, "api-gateway edge-agent", "libxml2", "HIGH", :reopened,
     "The package disappeared after a rollout, then returned when an older edge image was redeployed. The earlier fix no longer covers the evidence."},
    {9125, "identity-provider customer-portal", "nimbus-jose-jwt", "CRITICAL", :mixed,
     "A token parsing issue crosses the public sign-in and storefront boundary. Compare production urgency with already reviewed non-production scopes."},
    {9126, "billing-scheduler windows-batch", "sqlite", "LOW", :accepted,
     "The affected embedded database is used only for local job bookkeeping with no untrusted SQL input. The exception expires after the next patch cycle."},
    {9127, "checkout-api catalog-api", "libpng", "MEDIUM", :expired,
     "A previously disabled thumbnail path was enabled during a feature rollout. The old exception expired and a fresh review is required."},
    {9128, "ci-runner", "setuptools", "LOW", :fixed,
     "The build team reports rebuilding the toolchain image. Keep the reported fix distinct from evidence that every runner has pulled the new image."},
    {9129, "grafana", "jquery", "LOW", :needs,
     "A bundled administrative dashboard component has a low-severity issue. Confirm the UI path and authorized-user prerequisites."},
    {9130, "payment-worker order-events edge-agent", "libarchive", "MEDIUM", :needs,
     "A shared extraction helper is present in workers and edge agents. Establish which services process externally supplied archives before deciding."}
  ]

  def cves, do: Enum.map(@scenarios, &cve/1)

  @doc "Add missing cases once, anchored to today; reruns preserve all presenter changes."
  def seed!(now \\ DateTime.utc_now()) do
    now = DateTime.truncate(now, :second)

    {:ok, result} =
      Repo.transaction(fn ->
        Repo.query!("SELECT pg_advisory_xact_lock(2099, 9101)")

        existing =
          Repo.all(from f in Finding, where: f.cve in ^cves(), select: f.cve, distinct: true)

        pending = Enum.reject(@scenarios, &(cve(&1) in existing))

        services =
          pending
          |> Enum.flat_map(fn {_, services, _, _, _, _} -> String.split(services) end)
          |> Enum.uniq()

        images =
          @workloads
          |> Enum.filter(&(elem(&1, 0) in services))
          |> Map.new(&seed_workload!(&1, now))

        Enum.each(pending, &seed_case!(&1, images, now))

        %{
          added_cves: length(pending),
          total_demo_cves: length(@scenarios),
          workloads: length(@workloads),
          placements: length(@workloads) * 3
        }
      end)

    result
  end

  defp cve({id, _, _, _, _, _}), do: "CVE-2099-#{id}"

  defp seed_workload!({service, owner, namespace, platform, exposure}, now) do
    digest =
      "sha256:" <>
        Base.encode16(:crypto.hash(:sha256, "triage-demo-fleet-v1:" <> service), case: :lower)

    image = Repo.get_by(Image, digest: digest) || insert_image!(digest, service, platform, now)
    Enum.each(~w(prod staging dev), &seed_placement!(image, owner, namespace, exposure, &1, now))
    {service, image}
  end

  defp insert_image!(digest, service, platform, now) do
    {:ok, image} =
      Inventory.upsert_image(
        %{
          digest: digest,
          repository: "demo.invalid/" <> service,
          tag: "2026.09-demo",
          description:
            "SIMULATED DEMO infrastructure: #{platform}; #{service}. Not a discovered asset."
        },
        now
      )

    image
  end

  defp seed_placement!(image, owner, namespace, exposure, environment, now) do
    attrs = %{image_id: image.id, owner: owner, namespace: namespace, environment: environment}

    unless Repo.get_by(ImagePlacement, attrs) do
      {:ok, placement} = Inventory.upsert_placement(image, Map.delete(attrs, :image_id), now)
      value = if environment == "prod", do: exposure, else: "internal"

      if value != "unknown" do
        {:ok, _} =
          Exposure.record(
            placement.id,
            value,
            "SIMULATED DEMO: declared network zone; not collected from cloud infrastructure",
            now,
            DateTime.add(now, 90, :day),
            now
          )
      end
    end
  end

  defp seed_case!({id, services, package, severity, state, summary} = scenario, images, now) do
    detected = DateTime.add(now, -(14 + rem(id * 7, 28)), :day)
    name = cve(scenario)

    Enum.each(String.split(services), fn service ->
      {:ok, finding} =
        Inventory.upsert_finding(
          Map.fetch!(images, service),
          %{
            cve: name,
            package_name: package,
            package_version: "1.0.0-demo",
            severity: severity,
            fix: if(rem(id, 5) == 0, do: nil, else: "1.0.1-demo"),
            url: nil,
            description:
              "SIMULATED DEMO — fictional CVE, package impact and infrastructure; not a vendor advisory. " <>
                summary
          },
          detected,
          reopen: false
        )

      seed_lifecycle!(finding, state, detected)

      unless state == :verified do
        finding
        |> Finding.changeset(%{last_seen: DateTime.add(now, -3600, :second)})
        |> Repo.update!()
      end
    end)

    targets = Workspace.targets(%{"cve" => name}, now)
    Enum.each(targets, &seed_decision!(&1, state, detected, now))
  end

  defp seed_lifecycle!(finding, :verified, detected) do
    cleared = DateTime.add(detected, 2, :day)

    Inventory.record_event(
      finding.id,
      "resolved",
      cleared,
      "SIMULATED DEMO: absent in the follow-up scan"
    )

    Inventory.set_lifecycle(finding.id, resolved_at: cleared)
  end

  defp seed_lifecycle!(finding, :reopened, detected) do
    Inventory.record_event(
      finding.id,
      "resolved",
      DateTime.add(detected, 5, :day),
      "SIMULATED DEMO: absent after initial rollout"
    )

    Inventory.record_event(
      finding.id,
      "reopened",
      DateTime.add(detected, 10, :day),
      "SIMULATED DEMO: older image redeployed"
    )

    Inventory.set_lifecycle(finding.id, resolved_at: nil, reopen_count: 1)
  end

  defp seed_lifecycle!(_finding, _state, _detected), do: :ok

  defp seed_decision!(target, :mixed, detected, now) do
    state =
      %{"prod" => :needs, "staging" => :progress, "dev" => :accepted}[
        target.placement.environment
      ]

    seed_decision!(target, state, detected, now)
  end

  defp seed_decision!(_target, :needs, _detected, _now), do: :ok

  defp seed_decision!(target, state, detected, now) do
    action = action(state)

    expiry =
      case state do
        :expired -> DateTime.add(now, -1, :day)
        :expiring -> DateTime.add(now, 2, :day)
        :accepted -> DateTime.add(now, 30, :day)
        _ -> nil
      end

    metadata = %{
      "source" => "fictional-demo-fleet",
      "demo" => true,
      "expiry_boundary" => "exclusive",
      "evidence_hash" => target.evidence_hash,
      "packet_hash" =>
        if(state == :reopened, do: "demo-evidence-before-redeployment", else: target.packet_hash),
      "policy_version" => Triage.Risk.policy_version(),
      "target" => %{
        "team" => target.placement.owner,
        "environment" => target.placement.environment,
        "namespace" => target.placement.namespace,
        "placement_id" => target.id,
        "digest" => target.image.digest
      }
    }

    {:ok, _} =
      Decisions.record(%{
        cve: target.cve,
        placement_id: target.id,
        decision: action,
        actor: "Demo reviewer · " <> target.placement.owner,
        reason: reason(state),
        decided_at: DateTime.add(detected, 12 * 3600, :second),
        expires_at: expiry,
        operation_id: "demo-fleet-#{target.cve}-#{action}",
        metadata: metadata
      })
  end

  defp action(state) when state in [:accepted, :expired, :expiring], do: "accepted_risk"
  defp action(:progress), do: "create_ticket"
  defp action(_state), do: "fixed"

  defp reason(:progress),
    do:
      "SIMULATED DEMO: illustrative remediation work item assigned to the service team. No Azure ticket was created."

  defp reason(state) when state in [:accepted, :expired, :expiring],
    do:
      "SIMULATED DEMO: scoped risk accepted temporarily for the planned patch window; this is not a real approval."

  defp reason(_state),
    do:
      "SIMULATED DEMO: service team reported a patched rollout. Consult the separate scan lifecycle for subsequent observations."
end
