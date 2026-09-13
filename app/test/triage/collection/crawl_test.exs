defmodule Triage.Collection.CrawlTest do
  use ExUnit.Case, async: false

  alias Triage.Collection
  alias Triage.Collection.{Preview, Report}

  defp start_source(state) do
    base = %{
      images: [],
      requests: 0,
      current: 0,
      max_concurrent: 0,
      require_auth: false,
      fail_auth_after: nil,
      fail_status: nil,
      graphql_errors: false,
      delay_ms: 0,
      last_cluster_scan: "2026-09-03T12:00:00Z",
      owners_raw: nil,
      inventory_raw: %{},
      detail_raw: %{}
    }

    agent = start_supervised!({Agent, fn -> Map.merge(base, state) end}, id: unique(:agent))
    port = free_port!()

    start_supervised!(
      {Bandit, plug: {Triage.Collection.FakeSource, agent}, port: port, ip: {127, 0, 0, 1}},
      id: unique(:bandit)
    )

    %{agent: agent, url: "http://127.0.0.1:#{port}/graphql"}
  end

  defp unique(prefix), do: :"#{prefix}_#{System.unique_integer([:positive])}"

  defp free_port! do
    {:ok, socket} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, port} = :inet.port(socket)
    :gen_tcp.close(socket)
    port
  end

  # Real source image ids are UUIDs; the frozen query contract validates them.
  defp uid(n), do: "00000000-0000-4000-8000-" <> String.pad_leading(to_string(n), 12, "0")

  defp vuln(name, pkg, version, severity, opts \\ []) do
    %{
      vuln: name,
      severity: severity,
      baseSeverity: Keyword.get(opts, :base_severity, severity),
      packageName: pkg,
      packageVersion: version,
      source: Keyword.get(opts, :source, "nvd:cpe"),
      fix: Keyword.get(opts, :fix, nil)
    }
  end

  defp image(id, digest, owner, vulns, excluded, claimed) do
    %{
      id: id,
      digest: digest,
      description: "app:1",
      owner: owner,
      namespaces: [%{"id" => "ns-#{owner}", "owner" => owner}],
      vulnerabilities: vulns,
      excluded: excluded,
      claimed: claimed
    }
  end

  defp raw_vuln(name, pkg, version, severity, opts \\ []) do
    %{
      "vuln" => name,
      "description" => "desc #{name}",
      "fix" => Keyword.get(opts, :fix, ""),
      "severity" => severity,
      "baseSeverity" => Keyword.get(opts, :base_severity, severity),
      "url" => "https://example.test/#{name}",
      "source" => Keyword.get(opts, :source, "nvd:cpe"),
      "packageName" => pkg,
      "packageVersion" => version,
      "packageType" => "apk",
      "packagePath" => "pkg:apk/alpine/#{pkg}@#{version}",
      "packageCpe" => "cpe:2.3:a:#{pkg}",
      "attributedOn" => "2026-09-01T00:00:00Z"
    }
  end

  defp detail_json(id, digest, vulns, excluded, claimed) do
    %{
      "id" => id,
      "digest" => digest,
      "description" => "app:1",
      "tag" => "latest",
      "softwareBillOfMaterialCreatedBy" => "syft 1.43.0",
      "metrics" => %{
        "status" => "Analyzed",
        "vulnerabilities" => claimed,
        "vulnerableComponents" => 1
      },
      "vulnerabilities" => vulns,
      "excludedVulnerabilities" => excluded
    }
  end

  defp run(url, overrides \\ []) do
    {run_opts, config_overrides} = Keyword.split(overrides, [:owners, :max_images, :signal])
    base = [endpoint: url, environment: "test"]
    {:ok, config} = Triage.Collection.Config.new(Keyword.merge(base, config_overrides))
    state = Triage.Collection.Transport.Req.new(config)

    Collection.run(
      [config: config, transport: {Triage.Collection.Transport.Req, state}] ++ run_opts
    )
  end

  test "two-stage crawl reads owners, images and details with the engine" do
    v = vuln("CVE-1", "busybox", "1.0", "HIGH")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [v], [], 1)]})

    assert {:ok, %Report{} = report} = run(src.url)
    assert [%{digest: "digest-a", owners: ["team-a"], api_ids: [api_id]}] = report.images
    assert api_id == uid(1)
    assert [%{cve: "CVE-1", severity: "HIGH"}] = report.findings
    assert Report.complete?(report)
    assert report.status_marker == "2026-09-03T12:00:00Z"
  end

  test "an engine mismatch is a failure, not a silently empty result" do
    v = vuln("CVE-1", "busybox", "1.0", "HIGH")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [v], [], 1)]})

    assert {:ok, report} = run(src.url, engine: "Wrong")
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "returned none"))
  end

  test "id rotation and a shared digest collapse onto one image with both owners" do
    v = vuln("CVE-2", "openssl", "3.0", "MEDIUM")

    src =
      start_source(%{
        images: [
          image(uid(1), "digest-shared", "team-a", [v], [], 1),
          image(uid(2), "digest-shared", "team-b", [v], [], 1)
        ]
      })

    assert {:ok, report} = run(src.url)
    assert [%{digest: "digest-shared", owners: owners, api_ids: ids}] = report.images
    assert owners == ["team-a", "team-b"]
    assert ids == [uid(1), uid(2)]
    assert length(report.findings) == 1
  end

  test "suppressed findings are preserved and counted in reconciliation" do
    open = vuln("CVE-3", "curl", "8.0", "LOW")
    excl = vuln("CVE-4", "curl", "8.0", "LOW")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [open], [excl], 2)]})

    assert {:ok, report} = run(src.url)
    assert Report.complete?(report)
    assert [%{cve: "CVE-3", suppressed: false}] = report.findings
    assert [%{cve: "CVE-4", suppressed: true}] = report.suppressed
  end

  test "identical duplicates are collapsed and counted, not double-written" do
    v = vuln("CVE-5", "zlib", "1.2", "HIGH")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [v, v, v], [], 3)]})

    assert {:ok, report} = run(src.url)
    assert Report.complete?(report)
    assert length(report.findings) == 1
    assert Enum.any?(report.warnings, &String.contains?(&1, "duplicate"))
  end

  test "conflicting duplicates are a failure and never silently pick a severity" do
    a = vuln("CVE-6", "zlib", "1.2", "HIGH")
    b = vuln("CVE-6", "zlib", "1.2", "LOW")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [a, b], [], 2)]})

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "conflicting duplicates"))
  end

  test "missing identities are a failure and never imply completeness" do
    broken = %{
      vuln: "CVE-7",
      severity: "HIGH",
      baseSeverity: "HIGH",
      packageName: nil,
      packageVersion: "1.0",
      fix: nil
    }

    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [broken], [], 1)]})

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "missing identity"))
  end

  test "count drift other than zero-vs-positive is an explicit incomplete warning" do
    v = vuln("CVE-8", "gzip", "1.0", "MEDIUM")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [v], [], 5)]})

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "drift"))
  end

  test "unsupported severities are preserved, never mapped or dropped" do
    unknown = vuln("CVE-9", "bash", "5.0", "UNKNOWN")
    negligible = vuln("CVE-10", "bash", "5.0", "NEGLIGIBLE")

    src =
      start_source(%{images: [image(uid(1), "digest-a", "team-a", [unknown, negligible], [], 2)]})

    assert {:ok, report} = run(src.url)
    assert Report.complete?(report)
    assert Enum.sort(Enum.map(report.findings, & &1.severity)) == ["NEGLIGIBLE", "UNKNOWN"]
  end

  test "no first_seen or lifecycle history is synthesized" do
    v = vuln("CVE-11", "musl", "1.0", "LOW")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [v], [], 1)]})

    assert {:ok, report} = run(src.url)
    assert report.raw["digest-a"]
    refute Map.has_key?(hd(report.findings), :first_seen)
    refute Map.has_key?(hd(report.findings), :last_seen)
  end

  test "a terminal auth failure yields no successful report" do
    src = start_source(%{require_auth: true})
    assert {:error, %Triage.Collection.Errors.RedirectError{}} = run(src.url)
  end

  test "an owner-scoped read failure is an explicit failure, not completeness" do
    v = vuln("CVE-12", "nano", "1.0", "LOW")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [v], [], 1)]})

    assert {:ok, report} = run(src.url, owners: ["team-a", "team-ghost"])
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "team-ghost"))
  end

  test "concurrency stays within the configured bound" do
    images =
      for i <- 1..6 do
        image(uid(i), "digest-#{i}", "team-a", [vuln("CVE-#{i}", "p", "1", "LOW")], [], 1)
      end

    src = start_source(%{images: images, delay_ms: 20})
    assert {:ok, _report} = run(src.url, concurrency: 2)
    assert Agent.get(src.agent, & &1.max_concurrent) <= 2
  end

  test "an oversized text field is a failure, not silently truncated" do
    big = vuln("CVE-20", "p", "1", "HIGH", fix: String.duplicate("x", 5_000))
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [big], [], 1)]})

    assert {:ok, report} = run(src.url, max_text_bytes: 1_000)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "byte budget"))
  end

  test "deeply nested metadata is bounded by the depth budget" do
    nested = put_in(vuln("CVE-21", "p", "1", "HIGH")[:extra], %{"a" => %{"b" => %{"c" => 1}}})
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [nested], [], 1)]})

    assert {:ok, report} = run(src.url, max_depth: 1)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "depth budget"))
  end

  test "the record budget bounds normalization" do
    images =
      for i <- 1..4 do
        image(uid(i), "digest-#{i}", "team-a", [vuln("CVE-R#{i}", "p", "1", "LOW")], [], 1)
      end

    src = start_source(%{images: images})
    assert {:ok, report} = run(src.url, max_records: 2)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "record budget"))
  end

  test "preview refuses a misleading importable snapshot" do
    v = vuln("CVE-13", "p", "1", "UNKNOWN")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [v], [], 1)]})

    assert {:ok, report} = run(src.url)
    assert {:error, blockers} = Preview.to_snapshot(report)
    assert Enum.any?(blockers, &String.contains?(&1, "first_seen"))
    assert Enum.any?(blockers, &String.contains?(&1, "UNKNOWN"))
  end

  test "a malformed source image id is a controlled incomplete report, not a worker crash" do
    broken = %{
      id: "not-a-uuid",
      digest: "digest-a",
      description: "app:1",
      owner: "team-a",
      namespaces: [],
      vulnerabilities: [],
      excluded: [],
      claimed: 0
    }

    src = start_source(%{images: [broken]})

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "malformed image id"))
  end

  test "a null owner entry is a controlled error, never silently dropped" do
    src = start_source(%{owners_raw: [%{"id" => "team-a"}, %{"id" => nil}]})
    assert {:error, %Triage.Collection.Errors.GraphQLError{}} = run(src.url)
  end

  test "an inventory entry without a digest is incomplete evidence" do
    src =
      start_source(%{
        inventory_raw: %{"team-a" => [%{"id" => uid(1), "usedInNamespaces" => []}]}
      })

    assert {:ok, report} = run(src.url, owners: ["team-a"])
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "no digest"))
  end

  test "a namespace with a null owner is incomplete evidence" do
    entry = %{
      "id" => uid(1),
      "digest" => "digest-a",
      "usedInNamespaces" => [%{"id" => "ns-1", "owner" => nil}]
    }

    src = start_source(%{inventory_raw: %{"team-a" => [entry]}})
    assert {:ok, report} = run(src.url, owners: ["team-a"])
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "usedInNamespaces"))
  end

  test "null finding arrays are incomplete evidence, never verified empty" do
    detail = %{
      "id" => uid(1),
      "digest" => "digest-a",
      "metrics" => %{"status" => "Analyzed", "vulnerabilities" => 0},
      "vulnerabilities" => nil,
      "excludedVulnerabilities" => nil
    }

    src =
      start_source(%{
        images: [image(uid(1), "digest-a", "team-a", [], [], 0)],
        detail_raw: %{uid(1) => [detail]}
      })

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "missing or null"))
  end

  test "a detail object whose id does not match the requested id is a failure" do
    d = detail_json(uid(2), "digest-a", [raw_vuln("CVE-D", "p", "1", "HIGH")], [], 1)

    src =
      start_source(%{
        images: [image(uid(1), "digest-a", "team-a", [], [], 0)],
        detail_raw: %{uid(1) => [d]}
      })

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)

    assert Enum.any?(
             report.failures,
             &String.contains?(&1, "did not match the requested image id")
           )
  end

  test "a detail digest that disagrees with the inventory digest is a failure" do
    d = detail_json(uid(1), "digest-other", [raw_vuln("CVE-D", "p", "1", "HIGH")], [], 1)

    src =
      start_source(%{
        images: [image(uid(1), "digest-a", "team-a", [], [], 0)],
        detail_raw: %{uid(1) => [d]}
      })

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "did not match the inventory digest"))
  end

  test "a shared digest with conflicting details across rotating ids is a failure" do
    d1 = detail_json(uid(1), "digest-shared", [raw_vuln("CVE-X", "p", "1", "HIGH")], [], 1)
    d2 = detail_json(uid(2), "digest-shared", [raw_vuln("CVE-X", "p", "1", "LOW")], [], 1)

    src =
      start_source(%{
        images: [
          image(uid(1), "digest-shared", "team-a", [], [], 0),
          image(uid(2), "digest-shared", "team-a", [], [], 0)
        ],
        detail_raw: %{uid(1) => [d1], uid(2) => [d2]}
      })

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    refute length(report.findings) == 1
    assert Enum.any?(report.failures, &String.contains?(&1, "conflicting details"))
  end

  test "an empty detail list for a requested id is incomplete, not missing-but-ok" do
    src =
      start_source(%{
        images: [image(uid(1), "digest-a", "team-a", [], [], 0)],
        detail_raw: %{uid(1) => []}
      })

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "no detail object returned"))
  end

  test "two detail objects for one id are rejected, never silently first-picked" do
    d1 = detail_json(uid(1), "digest-a", [], [], 0)
    d2 = detail_json(uid(1), "digest-a", [], [], 0)

    src =
      start_source(%{
        images: [image(uid(1), "digest-a", "team-a", [], [], 0)],
        detail_raw: %{uid(1) => [d1, d2]}
      })

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "expected exactly one detail object"))
  end

  test "detail metrics that contradict the inventory claim are incomplete" do
    detail = detail_json(uid(1), "digest-a", [], [], 0)

    src =
      start_source(%{
        images: [image(uid(1), "digest-a", "team-a", [], [], 1)],
        detail_raw: %{uid(1) => [detail]}
      })

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "contradictory claimed counts"))
  end

  test "the record budget bounds findings, not just images" do
    vulns = for i <- 1..5, do: vuln("CVE-B#{i}", "p", "1", "LOW")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", vulns, [], 5)]})

    assert {:ok, report} = run(src.url, max_records: 1)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "record budget"))
  end

  test "an oversized image description is a bounded failure" do
    big = image(uid(1), "digest-a", "team-a", [vuln("CVE-30", "p", "1", "LOW")], [], 1)
    big = %{big | description: String.duplicate("x", 1_000)}
    src = start_source(%{images: [big]})

    assert {:ok, report} = run(src.url, max_text_bytes: 100)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "byte budget"))
  end

  test "max_images truncation is explicit incomplete evidence" do
    images =
      for i <- 1..3 do
        image(uid(i), "digest-#{i}", "team-a", [vuln("CVE-T#{i}", "p", "1", "LOW")], [], 1)
      end

    src = start_source(%{images: images})
    assert {:ok, report} = run(src.url, max_images: 1)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "max_images"))
  end

  test "duplicates that differ only in unrecognized metadata are a conflict, not a silent pick" do
    a = vuln("CVE-50", "zlib", "1.2", "HIGH", source: "source-a")
    b = vuln("CVE-50", "zlib", "1.2", "HIGH", source: "source-b")
    src = start_source(%{images: [image(uid(1), "digest-a", "team-a", [a, b], [], 2)]})

    assert {:ok, report} = run(src.url)
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "conflicting duplicates"))
  end

  test "out-of-scope placements are flagged and never silently attributed" do
    entry = %{
      "id" => uid(1),
      "digest" => "digest-a",
      "usedInNamespaces" => [
        %{"id" => "ns-a", "owner" => "team-a"},
        %{"id" => "ns-b", "owner" => "team-b"}
      ]
    }

    src = start_source(%{inventory_raw: %{"team-a" => [entry]}})
    assert {:ok, report} = run(src.url, owners: ["team-a"])
    refute Report.complete?(report)
    assert Enum.any?(report.failures, &String.contains?(&1, "outside requested owner scope"))

    [%{placements: placements}] = report.images
    refute Enum.all?(placements, & &1.in_scope)
  end
end
