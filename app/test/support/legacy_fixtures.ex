defmodule Triage.LegacyFixtures do
  @moduledoc """
  Deterministic synthetic fixtures for the PR 1 offline demo.

  These rows are fake security data. They exist so the interface can be developed
  and tested without production connections. Running `seed/1` again updates
  `last_seen` timestamps but never duplicates rows or lifecycle events, and never
  invents history that a real collection did not record.

  Fixture coverage:

    * one advisory (CVE-2025-1001) affecting several packages across two teams;
    * a vendor-critical finding with a reported fix available;
    * a scanner-suppressed finding (suppression is not mitigation evidence);
    * a reopened finding with a full appeared → resolved → reopened history;
    * a resolved (disappeared) finding that stays out of the active list;
    * an image with unknown deployment context (namespace `(unknown)`);
    * a hostile description string to prove third-party text is rendered safely.
  """

  alias Triage.Inventory
  alias Triage.Repo
  import Ecto.Query

  @appeared ~U[2026-08-01 06:00:00Z]
  @resolved ~U[2026-08-05 06:00:00Z]
  @reopened ~U[2026-08-06 06:00:00Z]
  @recent ~U[2026-09-09 06:00:00Z]
  @env "prod-cluster-1"

  def seed(now \\ @recent) do
    Repo.transaction(fn ->
      image_a =
        image!(
          "sha256:aaa1111111111111111111111111111111111111111111111111111111111111",
          "registry.internal/app-a",
          "1.0",
          "Synthetic service A image",
          now
        )

      image_b =
        image!(
          "sha256:bbbb222222222222222222222222222222222222222222222222222222222222",
          "registry.internal/app-b",
          "2.0",
          "Synthetic service B image",
          now
        )

      image_c =
        image!(
          "sha256:cccc333333333333333333333333333333333333333333333333333333333333",
          "registry.internal/shared-base",
          "9",
          "Synthetic shared base image",
          now
        )

      placement!(image_a, "web", "alpha", @env, now)
      placement!(image_a, "web", "beta", @env, now)
      placement!(image_b, "web", "beta", @env, now)
      placement!(image_c, "(unknown)", "alpha", @env, now)

      # Explicit operator-declared exposure evidence (never inferred from names).
      # Idempotency: record evidence only when the placement has none yet.
      seed_exposure!(
        image_a,
        "web",
        "alpha",
        @env,
        "internet_exposed",
        "seed:operator declared",
        now
      )

      seed_exposure!(
        image_a,
        "web",
        "beta",
        @env,
        "internet_exposed",
        "seed:operator declared",
        now
      )

      seed_exposure!(image_b, "web", "beta", @env, "internal", "seed:operator declared", now)
      # image_c placement intentionally has NO evidence → stays exposure `unknown`.

      # Operator-declared business impact for one placement. Never inferred from
      # severity, namespace or exposure.
      seed_impact!(image_a, "web", "alpha", @env, "critical", "seed:operator declared", now)

      finding!(
        image_a,
        "CVE-2025-1001",
        "busybox",
        "1.37",
        "HIGH",
        "1.38",
        "Use-after-free in a synthetic busybox applet. <script>alert('xss')</script> probe text must render as text, never as markup.",
        now: now
      )

      finding!(
        image_a,
        "CVE-2025-1001",
        "busybox-binsh",
        "1.37",
        "HIGH",
        nil,
        "Same advisory against the busybox-binsh subpackage.",
        now: now
      )

      finding!(
        image_a,
        "CVE-2024-2002",
        "openssl",
        "3.1",
        "CRITICAL",
        "3.2.1",
        "Synthetic OpenSSL vulnerability with a reported fixed version.",
        now: now
      )

      finding!(
        image_b,
        "CVE-2025-1001",
        "curl",
        "8.5",
        "HIGH",
        "8.5.1",
        "Same advisory against curl on another team's image.",
        now: now
      )

      finding!(
        image_c,
        "CVE-2024-4004",
        "zlib",
        "1.2.13",
        "MEDIUM",
        nil,
        "Occurrence on an image whose deployment context is unknown.",
        now: now
      )

      finding!(
        image_b,
        "CVE-2025-3003",
        "libc6",
        "2.36",
        "LOW",
        nil,
        "Scanner-suppressed by operator policy. Suppression is not mitigation evidence.",
        now: now,
        suppressed: true
      )

      reopened =
        finding!(
          image_a,
          "CVE-2024-4004",
          "zlib",
          "1.3",
          "HIGH",
          nil,
          "Synthetic zlib finding that was cleared once and came back.",
          now: now
        )

      resolved =
        finding!(
          image_a,
          "CVE-2023-5005",
          "gzip",
          "1.12",
          "MEDIUM",
          nil,
          "Disappeared from a complete unfiltered collection; not proof of remediation.",
          now: now
        )

      pin_history!(reopened, %{
        first_seen: @appeared,
        resolved_at: nil,
        reopen_count: 1,
        events: [{"appeared", @appeared}, {"resolved", @resolved}, {"reopened", @reopened}]
      })

      pin_history!(resolved, %{
        first_seen: @appeared,
        resolved_at: @resolved,
        reopen_count: 0,
        events: [{"appeared", @appeared}, {"resolved", @resolved}]
      })

      # Decision history: one live acceptance and one expired mitigation, so the
      # demo shows a covered advisory and an advisory that came back.
      seed_decision!(%{
        cve: "CVE-2024-2002",
        decision: "accepted_risk",
        reason: "Synthetic demo: risk accepted while service A is replaced next quarter.",
        actor: "local-operator",
        decided_at: now,
        expires_at: DateTime.add(now, 30, :day)
      })

      seed_decision!(%{
        cve: "CVE-2025-1001",
        decision: "mitigated",
        reason: "Synthetic demo: temporary ingress rule, expired with the old ingress.",
        actor: "local-operator",
        decided_at: DateTime.add(now, -60, :day),
        expires_at: DateTime.add(now, -30, :day)
      })

      seed_intel!(now)

      {:ok, suppressed_count: Inventory.summary_counts().suppressed}
    end)
    |> case do
      {:ok, _} -> :ok
      other -> other
    end
  end

  defp image!(digest, repository, tag, description, now) do
    {:ok, image} =
      Inventory.upsert_image(
        %{digest: digest, repository: repository, tag: tag, description: description},
        now
      )

    image
  end

  defp placement!(image, namespace, owner, environment, now) do
    {:ok, _} =
      Inventory.upsert_placement(
        image,
        %{namespace: namespace, owner: owner, environment: environment},
        now
      )

    :ok
  end

  defp finding!(
         image,
         cve,
         package,
         version,
         severity,
         fix,
         description,
         opts
       ) do
    now = Keyword.fetch!(opts, :now)
    suppressed = Keyword.get(opts, :suppressed, false)

    {:ok, finding} =
      Inventory.upsert_finding(
        image,
        %{
          cve: cve,
          package_name: package,
          package_version: version,
          severity: severity,
          fix: fix,
          description: description,
          suppressed: suppressed
        },
        now,
        reopen: false
      )

    finding
  end

  defp seed_exposure!(image, namespace, owner, environment, exposure, source, now) do
    placement = placement_for!(image, namespace, owner, environment)

    unless Repo.exists?(
             from(e in Triage.Exposure.Evidence, where: e.placement_id == ^placement.id)
           ) do
      {:ok, _} = Triage.Exposure.record(placement.id, exposure, source, now)
    end

    :ok
  end

  # Impact and decisions are demo history: seeded once, never rewritten.
  defp seed_impact!(image, namespace, owner, environment, impact, source, now) do
    placement = placement_for!(image, namespace, owner, environment)

    unless Repo.exists?(from(e in Triage.Impact.Evidence, where: e.placement_id == ^placement.id)) do
      {:ok, _} = Triage.Impact.record(placement.id, impact, source, now)
    end

    :ok
  end

  defp seed_decision!(attrs) do
    unless Repo.exists?(from(d in Triage.Decisions.Decision, where: d.cve == ^attrs.cve)) do
      {:ok, _} = Triage.Decisions.record(Map.put_new(attrs, :placement_id, nil))
    end

    :ok
  end

  defp placement_for!(image, namespace, owner, environment) do
    Repo.one!(
      from(p in Inventory.ImagePlacement,
        where:
          p.image_id == ^image.id and p.namespace == ^namespace and p.owner == ^owner and
            p.environment == ^environment
      )
    )
  end

  # Demo-only intel cache: a few synthetic news notices, never network-sourced.
  defp seed_intel!(now) do
    unless Repo.exists?(Triage.Intel.NewsItem) do
      {:ok, _} =
        Triage.Intel.replace_news("synthetic", [
          %{
            item_id: "demo-1",
            title: "Synthetic notice: new exploitation reporting for a public library CVE",
            summary:
              "Demonstration row. Public notices are concerning the world at large and are not statements about this estate; a match in Findings is needed before action.",
            link: "https://example.invalid/demo-1",
            published_at: now
          },
          %{
            item_id: "demo-2",
            title: "Synthetic notice: vendor advisory for a container runtime",
            summary:
              "Demonstration row. Scanner severity is unchanged by exposure; review priority may rise when evidence shows exposure.",
            link: "https://example.invalid/demo-2",
            published_at: now
          }
        ])
        |> elem_ok()

      {:ok, _} = Triage.Intel.record_receipt("synthetic", true, 2, "seeded demo rows")
    end

    :ok
  end

  defp elem_ok({:ok, value}), do: {:ok, value}
  defp elem_ok(other), do: other

  defp pin_history!(finding, %{events: events} = history) do
    existing_events =
      Repo.all(
        from e in Inventory.FindingEvent, where: e.finding_id == ^finding.id, select: e.event
      )

    if "resolved" not in existing_events do
      Inventory.set_lifecycle(
        finding.id,
        Map.take(history, [:first_seen, :resolved_at, :reopen_count])
      )

      events
      |> Enum.reject(fn {name, _at} -> name in existing_events end)
      |> Enum.each(fn {name, at} ->
        Inventory.record_event(finding.id, name, at, "synthetic fixture history")
      end)

      # Align the pre-recorded `appeared` event with the pinned history so the
      # timeline sorts by observation time, not by seed-run time.
      align_appeared!(finding.id, List.keyfind(events, "appeared", 0))
    end

    :ok
  end

  defp align_appeared!(_id, nil), do: :ok

  defp align_appeared!(id, {"appeared", appeared_at}) do
    event =
      Repo.one!(
        from e in Inventory.FindingEvent, where: e.finding_id == ^id and e.event == "appeared"
      )

    if event.occurred_at != appeared_at do
      event |> Inventory.FindingEvent.changeset(%{occurred_at: appeared_at}) |> Repo.update!()
    end
  end
end
