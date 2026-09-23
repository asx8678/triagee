defmodule Triage.WorkspaceQueryTest do
  use Triage.DataCase, async: false
  import Triage.Fixtures
  alias Triage.{Decisions, Exposure, Repo, Workspace}
  alias Triage.Workspace.EvidenceSQL

  @now ~U[2035-01-01 12:00:00Z]

  setup do
    reset_inventory!()
    image = image!("query-main")
    prod = placement!(image, "alpha", "prod")
    staging = placement!(image, "beta", "staging")
    orphan = placement!(image, "(unknown)", "prod")
    placement!(image, "retired", "prod", false)

    for {severity, index} <- Enum.with_index(["CRITICAL", "HIGH", "MEDIUM", "LOW", nil]) do
      finding!(image, "CVE-2034-#{1000 + index}", severity: severity, first_seen: at(index + 1))
    end

    finding!(image, "CVE-2034-1001", package_name: "second %_ package", severity: "LOW")
    finding!(image, "CVE-2034-2000", resolved_at: at(0))
    finding!(image, "CVE-2034-3000", suppressed: true)
    # Recorded at the fixture's own clock: the observation-time guard is judged
    # against the caller's clock, and this suite deliberately runs on @now.
    Exposure.record(prod.id, "internet_exposed", "fixture", @now, nil, @now)
    Exposure.record(staging.id, "internal", "fixture", @now, nil, @now)

    reference = image!("query-reference")
    placement!(reference, "public-reference", "prod")
    placement!(reference, "alpha", "not-a-deployment")
    finding!(reference, "CVE-2034-REFERENCE")

    # A reference-only image is excluded even if mistakenly given an operational placement.
    reference_image = image!("query-reference-image")

    reference_image
    |> Ecto.Changeset.change(
      repository: "public-reference/nvd-catalogue",
      tag: "reference",
      description: "NVD PUBLIC REFERENCE — fixture"
    )
    |> Repo.update!()

    placement!(reference_image, "alpha", "prod")
    finding!(reference_image, "CVE-2034-REFERENCE-IMAGE")

    decision!("CVE-2034-1001", prod.id, "fixed")
    decision!("CVE-2034-1002", staging.id, "accepted_risk", expires_at: DateTime.add(@now, 3600))
    decision!("CVE-2034-1003", prod.id, "investigate")
    %{image: image, prod: prod, staging: staging, orphan: orphan}
  end

  test "SQL pages and scalar metrics equal the original pure projection for every mode and scope" do
    for mode <- ~w(active all history needs urgent unknown fixed accepted progress),
        scope <- [
          %{},
          %{"team" => "alpha"},
          %{"team" => "__unassigned__"},
          %{"environment" => "staging"}
        ] do
      assert_reference(Map.put(scope, "mode", mode))
    end
  end

  test "search and severity filter complete targets rather than truncating their evidence" do
    for filters <- [
          %{"q" => "QUERY-MAIN"},
          %{"q" => "%_"},
          %{"q" => "1001 registry.test/query-main libssl second"},
          %{"q" => "does-not-exist"},
          %{"severity" => "LOW"},
          %{"severity" => "HIGH", "q" => "second %_ package"},
          %{"team" => "beta", "severity" => "LOW", "sort" => "age"}
        ] do
      assert_reference(filters)
    end

    page = Workspace.page(%{"q" => "%_"}, @now)
    assert [%{cve: "CVE-2034-1001", scopes: scopes, severity: "HIGH"}] = page.page_rows
    assert Enum.all?(scopes, &(length(&1.findings) == 2))
  end

  test "priority ordering is severity-led, normalized for risk only, and respects KEV and exposure",
       c do
    finding!(c.image, "CVE-2034-0001", severity: " high ")
    finding!(c.image, "CVE-2034-0002", severity: "MEDIUM")

    Repo.insert!(%Triage.Intel.Advisory{
      source: "kev",
      external_id: "CVE-2034-0002",
      fetched_at: @now
    })

    for filters <- [%{}, %{"team" => "beta"}, %{"team" => "__unassigned__"}, %{"sort" => "age"}] do
      assert_reference(filters)
    end

    rows = Workspace.page(%{"team" => "beta"}, @now).page_rows
    assert hd(rows).severity == "CRITICAL"
    assert Enum.find(rows, &(&1.cve == "CVE-2034-0002")).risk.priority == "high"

    # T05: attention-led ordering. Uncovered targets come first (severity-led
    # within the band); covered work/acceptance records come last.
    assert List.last(rows).severity in ["MEDIUM", nil, " high "]
  end

  test "database pagination bounds CVEs but retains every package and explicit off-page focus",
       c do
    for n <- 1..57 do
      cve = "CVE-2034-#{4000 + n}"
      finding!(c.image, cve, package_name: "package-a", severity: "HIGH")
      finding!(c.image, cve, package_name: "package-b", severity: "LOW")
    end

    for offset <- ["0", "50", "1000", "-1", "not-an-offset"] do
      assert_reference(%{"offset" => offset})
    end

    page =
      Workspace.page(
        %{
          "page" => "review",
          "offset" => "50",
          "item" => "CVE-2034-4057",
          "inspect" => "CVE-2034-1001"
        },
        @now
      )

    assert page.total > 50
    assert length(page.page_rows) <= 50
    allowed = MapSet.new(Enum.map(page.page_rows, & &1.cve) ++ [page.item, "CVE-2034-1001"])
    assert Enum.all?(page.targets, &MapSet.member?(allowed, &1.cve))
    assert Enum.all?(page.row.scopes, &(length(&1.findings) == 2))
    assert page.inspector.cve == "CVE-2034-1001"

    assert Workspace.page(%{"page" => "review", "offset" => "50"}, @now).item ==
             Workspace.page(%{"page" => "review"}, @now).item

    assert Workspace.page(%{"item" => "missing", "inspect" => "missing"}, @now).row == nil
    assert_reference(%{"batch" => "CVE-2034-4057,CVE-2034-1001", "sort" => "age"})
  end

  test "focused and inspector hydration respects scope and urgent/unknown target subsets", c do
    for mode <- ~w(urgent unknown) do
      page =
        Workspace.page(
          %{"page" => "inventory", "mode" => mode, "inspect" => "CVE-2034-1001"},
          @now
        )

      expected = Workspace.targets(%{"cve" => "CVE-2034-1001"}, @now) |> Workspace.select(mode)
      assert page.inspector_targets == expected
    end

    page =
      Workspace.page(
        %{"team" => "beta", "item" => "CVE-2034-1001", "inspect" => "CVE-2034-1001"},
        @now
      )

    assert Enum.map(page.row.scopes, & &1.id) == [c.staging.id]
    assert Enum.map(page.inspector_targets, & &1.id) == [c.staging.id]
    assert page.metrics["unknown"].value == 0
  end

  test "unknown counts targets, other metrics distinct CVEs, and teams are nonadditive" do
    page = Workspace.page(%{}, @now)
    assert page.metrics == counts(Workspace.metrics(Workspace.targets(%{}, @now)))
    assert page.metrics["active"].value == 6
    assert page.metrics["unknown"].value == 6
    assert Enum.sum(Enum.map(page.teams, & &1.metrics["active"].value)) == 18

    # Expired newest evidence does not resurrect an older internal observation.
    # The record boundary refuses this contradictory window (an expiry before
    # its own observation), so the state is written directly — a legacy or
    # direct-write row must still be displayed safely, never as a live value.
    Enum.each(Workspace.targets(%{}, @now) |> Enum.uniq_by(& &1.id), fn t ->
      Repo.insert!(%Exposure.Evidence{
        placement_id: t.id,
        exposure: "internal",
        source: "expired",
        observed_at: DateTime.add(@now, 10),
        expires_at: DateTime.add(@now, -1)
      })
    end)

    assert_reference(%{})
    assert Workspace.page(%{}, @now).metrics["unknown"].value == 18
  end

  test "newest global/scoped decision wins, future is ignored, expiry cannot resurrect coverage",
       c do
    cve = "CVE-2034-3000"

    decision!(cve, nil, "accepted_risk",
      decided_at: DateTime.add(@now, -100),
      expires_at: DateTime.add(@now, 100)
    )

    decision!(cve, c.prod.id, "investigate",
      decided_at: DateTime.add(@now, -50),
      expires_at: DateTime.add(@now, -1)
    )

    decision!(cve, c.staging.id, "fixed", decided_at: DateTime.add(@now, 1))
    decision!(cve, c.orphan.id, "fixed", decided_at: DateTime.add(@now, -100))
    assert_reference(%{})
    assert_reference(%{"mode" => "needs"})
    assert_reference(%{"mode" => "accepted"})
    # Same timestamp is broken by id; the newer global decision must also win.
    decision!(cve, nil, "fixed", decided_at: DateTime.add(@now, -50))
    assert_reference(%{"mode" => "fixed"})

    for boundary <- [nil, "exclusive"] do
      decision!(cve, c.prod.id, "accepted_risk",
        expires_at: @now,
        metadata: %{"expiry_boundary" => boundary}
      )

      assert_reference(%{"mode" => "accepted"})
      assert_reference(%{"mode" => "needs"})
    end
  end

  test "hash-bound coverage matches exact ETF evidence, not mutable JSON snapshots", c do
    cve = "CVE-2034-1001"
    target = hd(Workspace.targets(%{"cve" => cve, "placement_ids" => [c.prod.id]}, @now))
    decision!(cve, c.prod.id, "fixed", metadata: %{"evidence_hash" => target.evidence_hash})
    assert_reference(%{"mode" => "fixed"})
    assert_reference(%{"mode" => "needs"})
    assert_sql_hashes()

    finding = hd(target.findings)

    finding
    |> Ecto.Changeset.change(
      description: "Unicode café, 雪 and 'quotes'",
      reopen_count: 2,
      resolved_at: @now,
      suppressed: true
    )
    |> Repo.update!()

    assert_sql_hashes()
    assert_reference(%{"mode" => "fixed"})
    assert_reference(%{"mode" => "needs"})
    assert Workspace.page(%{"mode" => "fixed", "team" => "alpha"}, @now).total == 0

    # An arbitrary nonmatching stored hash must not become valid just because
    # observed_evidence happens to look plausible (or is absent).
    decision!(cve, c.prod.id, "fixed", metadata: %{"evidence_hash" => "wrong"})
    assert_reference(%{"mode" => "needs"})
  end

  test "SQL ETF handles bigint identifiers and nullable evidence fields" do
    image =
      Repo.insert!(%Triage.Inventory.Image{
        id: 4_294_967_297,
        digest: "sha256:big",
        repository: "big"
      })

    Repo.insert!(%Triage.Inventory.ImagePlacement{
      id: 4_294_967_298,
      image_id: image.id,
      namespace: "",
      owner: "",
      environment: "",
      active: true,
      first_seen: @now,
      last_seen: @now
    })

    Repo.insert!(%Triage.Inventory.Finding{
      id: 4_294_967_299,
      image_id: image.id,
      cve: "CVE-2034-BIG",
      package_name: "é雪",
      package_version: "",
      severity: nil,
      first_seen: ~U[2000-02-29 23:59:58Z],
      last_seen: @now,
      reopen_count: 257
    })

    assert_sql_hashes()
    assert_reference(%{})
  end

  test "empty scopes and out-of-range pages retain zero/scalar counts" do
    page = assert_reference(%{"team" => "no-such-team", "page" => "review"})
    assert page.page_rows == []
    assert page.targets == []
    assert page.item == nil
    assert page.teams == []
    assert Enum.all?(page.metrics, fn {_key, metric} -> metric.value == 0 end)
  end

  test "fixed history keeps nil risk and exposure equality is not expired", c do
    decision!("CVE-2034-2000", c.prod.id, "fixed")
    page = assert_reference(%{"mode" => "fixed"})
    historical = Enum.find(page.page_rows, &(&1.cve == "CVE-2034-2000"))
    assert historical.risk == nil
    Exposure.record(c.orphan.id, "internet_exposed", "at boundary", @now, @now)
    assert_reference(%{"mode" => "urgent"})
    assert_reference(%{"mode" => "unknown"})
  end

  test "CVE lists and selected placement IDs constrain full target reads", c do
    selected =
      Workspace.targets(%{"cves" => ["CVE-2034-1001"], "placement_ids" => [c.prod.id]}, @now)

    assert [%{cve: "CVE-2034-1001", id: id, findings: findings}] = selected
    assert id == c.prod.id
    assert length(findings) == 2
    assert Workspace.targets(%{"cves" => []}, @now) == []
    assert Workspace.targets(%{"placement_ids" => []}, @now) == []

    assert Workspace.targets(
             %{"cve" => "CVE-2034-1001", "placement_ids" => [c.prod.id], "team" => "beta"},
             @now
           ) == []
  end

  defp decision!(cve, placement_id, action, overrides \\ []) do
    Repo.insert!(
      struct!(
        Decisions.Decision,
        Keyword.merge(
          [
            cve: cve,
            placement_id: placement_id,
            decision: action,
            reason: "Query parity fixture",
            actor: "fixture",
            decided_at: @now,
            # Scoped fixture decisions bind the v2 packet so coverage is
            # exercised as a current approval; CVE-global decisions cannot bind
            # one placement's packet, so they stay legacy (readable, not a
            # current approval). Callers may override to pin behaviour.
            metadata: default_metadata(cve, placement_id)
          ],
          overrides
        )
      )
    )
  end

  defp default_metadata(_cve, nil), do: %{}

  defp default_metadata(cve, placement_id),
    do: %{"packet_hash" => packet_hash!(cve, placement_id)}

  defp packet_hash!(cve, placement_id) do
    [target] = Workspace.targets(%{"cve" => cve, "placement_ids" => [placement_id]}, @now)
    target.packet_hash
  end

  defp assert_sql_hashes do
    targets = Workspace.targets(%{}, @now)

    for t <- targets do
      [[actual, encoded]] =
        Repo.query!(
          """
          SELECT #{EvidenceSQL.hash_sql()}, #{EvidenceSQL.term_sql()}
          FROM image_placements p JOIN images i ON i.id = p.image_id
          CROSS JOIN (SELECT $1::text AS cve) t WHERE p.id = $2
          """,
          [t.cve, t.id]
        ).rows

      evidence =
        {Map.take(t.placement, [:id, :image_id, :owner, :environment, :namespace, :active]),
         t.image.digest,
         Enum.map(
           t.findings,
           &Map.take(&1, [
             :id,
             :package_name,
             :package_version,
             :severity,
             :fix,
             :description,
             :resolved_at,
             :reopen_count,
             :first_seen,
             :suppressed
           ])
         )}

      # The SQL must rebuild the canonical encoding byte for byte and then
      # hash it identically: value-shape failures (timestamp precision, nils)
      # and ordering failures both surface here.
      assert encoded == Triage.Canonical.canonical(evidence)
      assert actual == t.evidence_hash
      assert actual == Triage.Workspace.hash(evidence)
    end
  end

  defp assert_reference(params) do
    all = Workspace.targets(Map.take(params, ~w(team environment)), @now)
    mode = params["mode"] || if(params["page"] == "review", do: "needs", else: "active")
    q = String.downcase(params["q"] || "")
    batch = String.split(params["batch"] || "", ",", trim: true)

    rows =
      all
      |> Workspace.select(mode)
      |> Enum.filter(fn t ->
        text =
          Enum.join([t.cve, t.image.repository | Enum.map(t.findings, & &1.package_name)], " ")

        String.contains?(String.downcase(text), q) and
          (params["severity"] in [nil, ""] or
             Enum.any?(t.findings, &(&1.severity == params["severity"])))
      end)
      |> Workspace.rows(:attention)
      |> Enum.filter(&(batch == [] or &1.cve in batch))

    rows =
      if params["sort"] == "age",
        do: Enum.sort_by(rows, &{DateTime.to_unix(&1.first_seen), &1.cve}),
        else: rows

    page = Workspace.page(params, @now)
    assert page.total == length(rows), inspect(params)
    assert page.page_rows == Enum.slice(rows, page.offset, 50), inspect(params)
    assert page.metrics == counts(Workspace.metrics(all)), inspect(params)

    teams =
      all
      |> Enum.group_by(&Workspace.team_key(&1.placement.owner))
      # Team rows are current-work lists: a team whose every target is retired
      # keeps its history on the CVE level but shows no zero-work row.
      |> Enum.reject(fn {_name, ts} -> not Enum.any?(ts, & &1.active?) end)
      |> Enum.map(fn {name, ts} -> %{name: name, metrics: counts(Workspace.metrics(ts))} end)
      |> Enum.sort_by(& &1.name)

    assert page.teams == teams, inspect(params)
    page
  end

  defp counts(metrics),
    do: Map.new(metrics, fn {name, metric} -> {name, %{value: metric.value}} end)
end
