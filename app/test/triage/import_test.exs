defmodule Triage.ImportTest do
  @moduledoc """
  Domain tests for the pure snapshot parser and the read-only reconciliation of
  `Triage.Import`.

  The parser is strict and reports every problem with a JSON path; the dry run
  must classify records as `:create`/`:update`/`:unchanged` (events also
  `:existing`) using the same identity rules as the rest of the application, so
  a reimport is idempotent by construction. Nothing in this slice writes.
  """

  # async: false so the telemetry SELECT counter cannot observe queries from
  # concurrently running async modules.
  use Triage.DataCase, async: false

  alias Triage.{Cases, Import, Repo}

  alias Triage.Cases.{CaseEvent, EvidenceSnapshot, Review, ReviewCase}
  alias Triage.Inventory.{Finding, FindingEvent, Image, ImagePlacement}

  # Local fixtures must mirror the snapshot timestamps exactly: placement and
  # event reconciliation depend on them, so fixture drift turns an "identical"
  # reimport into a spurious update.
  @first_seen ~U[2026-09-01 00:00:00Z]
  @last_seen ~U[2026-09-09 00:00:00Z]
  @digest "sha256:" <> "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

  setup do
    # Inventory-wide reconciliation: start from a known-empty baseline.
    Triage.DataCase.reset_inventory!()
    :ok
  end

  ## Snapshot builders

  defp placement(overrides \\ %{}) do
    Map.merge(
      %{
        "namespace" => "web",
        "owner" => "team-a",
        "environment" => "prod",
        "active" => true,
        "first_seen" => "2026-09-01T00:00:00Z",
        "last_seen" => "2026-09-09T00:00:00Z"
      },
      overrides
    )
  end

  defp event(overrides \\ %{}) do
    Map.merge(
      %{"event" => "appeared", "occurred_at" => "2026-09-01T00:00:00Z", "note" => nil},
      overrides
    )
  end

  defp finding(overrides \\ %{}) do
    Map.merge(
      %{
        "cve" => "CVE-2025-1001",
        "package_name" => "busybox",
        "package_version" => "1.0",
        "severity" => "HIGH",
        "fix" => "1.1",
        "url" => nil,
        "description" => nil,
        "suppressed" => false,
        "first_seen" => "2026-09-01T00:00:00Z",
        "last_seen" => "2026-09-09T00:00:00Z",
        "resolved_at" => nil,
        "events" => [event()]
      },
      overrides
    )
  end

  defp image(overrides \\ %{}) do
    Map.merge(
      %{
        "digest" => @digest,
        "repository" => "registry.internal/app",
        "tag" => "1.0",
        "description" => nil,
        "placements" => [placement()],
        "findings" => [finding()]
      },
      overrides
    )
  end

  defp snapshot(overrides \\ %{}) do
    Map.merge(
      %{
        "format" => "triage.snapshot",
        "version" => 1,
        "source" => "legacy-export",
        "generated_at" => "2026-09-09T06:00:00Z",
        "images" => [image()]
      },
      overrides
    )
  end

  defp parse!(map) do
    assert {:ok, parsed} = Import.parse(Jason.encode!(map))
    parsed
  end

  defp error_paths(map) do
    assert {:error, errors} = Import.parse(Jason.encode!(map))
    Enum.map(errors, & &1.path)
  end

  ## Local fixtures for the dry run (mirroring the documented identity rules)

  defp existing_image!(overrides \\ %{}) do
    Repo.insert!(%Image{
      digest: @digest,
      repository: Map.get(overrides, :repository, "registry.internal/app"),
      tag: Map.get(overrides, :tag, "1.0"),
      description: Map.get(overrides, :description)
    })
  end

  defp existing_placement!(image, overrides \\ %{}) do
    Repo.insert!(%ImagePlacement{
      image_id: image.id,
      namespace: Map.get(overrides, :namespace, "web"),
      owner: Map.get(overrides, :owner, "team-a"),
      environment: Map.get(overrides, :environment, "prod"),
      active: Map.get(overrides, :active, true),
      first_seen: Map.get(overrides, :first_seen, @first_seen),
      last_seen: Map.get(overrides, :last_seen, @last_seen)
    })
  end

  defp existing_finding!(image, overrides \\ %{}) do
    Repo.insert!(%Finding{
      image_id: image.id,
      cve: Map.get(overrides, :cve, "CVE-2025-1001"),
      package_name: Map.get(overrides, :package_name, "busybox"),
      package_version: Map.get(overrides, :package_version, "1.0"),
      severity: Map.get(overrides, :severity, "HIGH"),
      fix: Map.get(overrides, :fix, "1.1"),
      suppressed: Map.get(overrides, :suppressed, false),
      first_seen: Map.get(overrides, :first_seen, @first_seen),
      last_seen: Map.get(overrides, :last_seen, @last_seen)
    })
  end

  defp existing_event!(finding, overrides \\ %{}) do
    Repo.insert!(%FindingEvent{
      finding_id: finding.id,
      event: Map.get(overrides, :event, "appeared"),
      occurred_at: Map.get(overrides, :occurred_at, @first_seen),
      note: nil
    })
  end

  defp count_selects(fun) do
    counter = :counters.new(1, [])
    id = "import-test-" <> Integer.to_string(:erlang.unique_integer([:positive, :monotonic]))

    :ok =
      :telemetry.attach(
        id,
        [:triage, :repo, :query],
        fn _event, _measurements, _metadata, _config -> :counters.add(counter, 1, 1) end,
        nil
      )

    try do
      fun.()
    after
      :ok = :telemetry.detach(id)
    end

    :counters.get(counter, 1)
  end

  defp capture_queries(fun) do
    parent = self()
    id = "import-queries-" <> Integer.to_string(:erlang.unique_integer([:positive, :monotonic]))

    :ok =
      :telemetry.attach(
        id,
        [:triage, :repo, :query],
        fn _event, _measurements, metadata, _config ->
          send(parent, {:query, metadata[:query]})
        end,
        nil
      )

    try do
      fun.()
    after
      :ok = :telemetry.detach(id)
    end

    drain_queries([])
  end

  defp drain_queries(acc) do
    receive do
      {:query, query} -> drain_queries([query | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  describe "parse/1 request boundaries" do
    test "rejects non-string, invalid JSON and non-object documents" do
      assert {:error, [%{path: "$"}]} = Import.parse(nil)
      assert {:error, [%{path: "$"}]} = Import.parse(:not_a_string)
      assert {:error, [%{path: "$"}]} = Import.parse("{not json")
      assert {:error, [%{path: "$", message: message}]} = Import.parse("[1, 2]")
      assert message =~ "JSON object"
    end

    test "accepts the documented snapshot and normalizes text and timestamps" do
      parsed = parse!(snapshot(%{"source" => "  legacy-export  ", "images" => [image()]}))

      assert parsed.format == "triage.snapshot"
      assert parsed.version == 1
      assert parsed.generated_at == ~U[2026-09-09 06:00:00Z]
      assert [image] = parsed.images
      assert image.digest == @digest
      assert image.description == nil
      assert [%{namespace: "web", owner: "team-a", active: true}] = image.placements
      assert [finding] = image.findings
      assert finding.severity == "HIGH"
      assert finding.resolved_at == nil
      assert [%{event: "appeared", occurred_at: ~U[2026-09-01 00:00:00Z]}] = finding.events
    end

    test "reports format and version problems" do
      assert "$.format" in error_paths(snapshot(%{"format" => "other.snapshot"}))
      assert "$.version" in error_paths(snapshot(%{"version" => 2}))
      assert "$.version" in error_paths(snapshot(%{"version" => "1"}))
    end

    test "rejects unknown keys at every level" do
      assert "$" in error_paths(snapshot(%{"surprise" => true}))
      assert "$.images[0]" in error_paths(snapshot(%{"images" => [image(%{"extra" => 1})]}))

      assert "$.images[0].placements[0]" in error_paths(
               snapshot(%{"images" => [image(%{"placements" => [placement(%{"x" => 1})]})]})
             )

      assert "$.images[0].findings[0]" in error_paths(
               snapshot(%{"images" => [image(%{"findings" => [finding(%{"y" => 1})]})]})
             )

      assert "$.images[0].findings[0].events[0]" in error_paths(
               snapshot(%{
                 "images" => [
                   image(%{"findings" => [finding(%{"events" => [event(%{"z" => 1})]})]})
                 ]
               })
             )
    end

    test "rejects blank and unsafe text" do
      assert "$.images[0].digest" in error_paths(
               snapshot(%{"images" => [image(%{"digest" => "   "})]})
             )

      assert "$.images[0].digest" in error_paths(
               snapshot(%{"images" => [image(%{"digest" => 42})]})
             )

      assert "$.images[0].placements[0].owner" in error_paths(
               snapshot(%{
                 "images" => [
                   image(%{"placements" => [placement(%{"owner" => "bad\u0000owner"})]})
                 ]
               })
             )

      assert "$.images[0].repository" in error_paths(
               snapshot(%{
                 "images" => [image(%{"repository" => String.duplicate("a", 1025)})]
               })
             )
    end

    test "rejects malformed timestamps and non-ISO values" do
      assert "$.images[0].placements[0].first_seen" in error_paths(
               snapshot(%{
                 "images" => [
                   image(%{"placements" => [placement(%{"first_seen" => "yesterday"})]})
                 ]
               })
             )

      assert "$.images[0].findings[0].events[0].occurred_at" in error_paths(
               snapshot(%{
                 "images" => [
                   image(%{
                     "findings" => [finding(%{"events" => [event(%{"occurred_at" => 123})]})]
                   })
                 ]
               })
             )

      assert "$.images[0].findings[0].resolved_at" in error_paths(
               snapshot(%{
                 "images" => [image(%{"findings" => [finding(%{"resolved_at" => "nope"})]})]
               })
             )
    end

    test "rejects unknown severity and lifecycle names" do
      assert "$.images[0].findings[0].severity" in error_paths(
               snapshot(%{
                 "images" => [image(%{"findings" => [finding(%{"severity" => "URGENT"})]})]
               })
             )

      assert "$.images[0].findings[0].events[0].event" in error_paths(
               snapshot(%{
                 "images" => [
                   image(%{
                     "findings" => [finding(%{"events" => [event(%{"event" => "fixed"})]})]
                   })
                 ]
               })
             )
    end

    test "rejects duplicates at every identity level" do
      assert "$.images[1].digest" in error_paths(snapshot(%{"images" => [image(), image()]}))

      assert "$.images[0].placements[1]" in error_paths(
               snapshot(%{"images" => [image(%{"placements" => [placement(), placement()]})]})
             )

      assert "$.images[0].findings[1]" in error_paths(
               snapshot(%{"images" => [image(%{"findings" => [finding(), finding()]})]})
             )

      assert "$.images[0].findings[0].events[1]" in error_paths(
               snapshot(%{
                 "images" => [
                   image(%{"findings" => [finding(%{"events" => [event(), event()]})]})
                 ]
               })
             )
    end

    test "reports every problem instead of stopping at the first" do
      paths =
        error_paths(
          snapshot(%{
            "version" => 9,
            "surprise" => true,
            "images" => [image(%{"digest" => "  ", "tag" => 3})]
          })
        )

      assert "$" in paths
      assert "$.version" in paths
      assert "$.images[0].digest" in paths
      assert "$.images[0].tag" in paths
    end

    test "rejects a non-list images value" do
      assert "$.images" in error_paths(snapshot(%{"images" => %{}}))
    end

    test "rejects an owner or environment beyond the UI scope limit" do
      long_owner = String.duplicate("a", 121)

      assert "$.images[0].placements[0].owner" in error_paths(
               snapshot(%{
                 "images" => [image(%{"placements" => [placement(%{"owner" => long_owner})]})]
               })
             )

      long_environment = String.duplicate("b", 121)

      assert "$.images[0].placements[0].environment" in error_paths(
               snapshot(%{
                 "images" => [
                   image(%{"placements" => [placement(%{"environment" => long_environment})]})
                 ]
               })
             )

      accepted =
        parse!(
          snapshot(%{
            "images" => [
              image(%{"placements" => [placement(%{"owner" => String.duplicate("c", 120)})]})
            ]
          })
        )

      assert [%{placements: [%{owner: owner}]}] = accepted.images
      assert String.length(owner) == 120
    end

    test "normalizes blank optional text to nil so a reimport is unchanged" do
      json =
        Jason.encode!(snapshot(%{"images" => [image(%{"tag" => "", "repository" => "   "})]}))

      assert {:ok, parsed} = Import.parse(json)
      assert [%{tag: nil, repository: nil}] = parsed.images

      assert {:ok, _} = Import.import_snapshot(json)
      assert Repo.get_by!(Image, digest: @digest).tag == nil

      assert {:ok, second} = Import.import_snapshot(json)
      assert second.summary.images == %{create: 0, update: 0, unchanged: 1, existing: 0}
      assert second.warnings == []
    end

    test "enforces the document byte budget before decoding" do
      assert {:error, [%{path: "$", message: message}]} =
               Import.parse(String.duplicate("a", Import.max_document_bytes() + 1))

      assert message =~ "limit"
    end

    test "enforces the string byte budget (not just grapheme count)" do
      huge_grapheme = "a" <> String.duplicate("\u0301", 4096)
      assert byte_size(huge_grapheme) > 4096

      assert {:error, errors} =
               Import.parse(Jason.encode!(snapshot(%{"source" => huge_grapheme})))

      assert "$.source" in Enum.map(errors, & &1.path)
    end

    test "enforces per-collection record budgets" do
      too_many_events =
        snapshot(%{
          "images" => [
            image(%{
              "findings" => [
                finding(%{"events" => Enum.map(1..201, fn _ -> event() end)})
              ]
            })
          ]
        })

      assert "$.images[*].findings[*].events" in error_paths(too_many_events)

      too_many_images =
        snapshot(%{
          "images" =>
            Enum.map(1..1001, fn i ->
              image(%{
                "digest" => "sha256:" <> String.pad_leading(Integer.to_string(i), 64, "0"),
                "placements" => [],
                "findings" => []
              })
            end)
        })

      assert "$.images" in error_paths(too_many_images)
    end
  end

  describe "dry_run/1 read-only reconciliation" do
    test "classifies an absent snapshot as create and writes nothing" do
      parsed = parse!(snapshot())

      before = table_counts()
      assert {:ok, report} = Import.dry_run(parsed)
      assert table_counts() == before

      assert report.summary.images == %{create: 1, update: 0, unchanged: 0, existing: 0}
      assert report.summary.placements == %{create: 1, update: 0, unchanged: 0, existing: 0}
      assert report.summary.findings == %{create: 1, update: 0, unchanged: 0, existing: 0}
      assert report.summary.events == %{create: 1, update: 0, unchanged: 0, existing: 0}
      assert report.warnings == []

      assert [%{digest: @digest, image_id: nil, action: :create}] = report.images
    end

    test "a reimport of identical local rows is unchanged and events already exist" do
      image = existing_image!()
      existing_placement!(image)
      finding = existing_finding!(image)
      existing_event!(finding)

      before = table_counts()
      assert {:ok, report} = Import.dry_run(parse!(snapshot()))
      assert table_counts() == before

      assert report.summary.images == %{create: 0, update: 0, unchanged: 1, existing: 0}
      assert report.summary.placements == %{create: 0, update: 0, unchanged: 1, existing: 0}
      assert report.summary.findings == %{create: 0, update: 0, unchanged: 1, existing: 0}
      assert report.summary.events == %{create: 0, update: 0, unchanged: 0, existing: 1}

      assert [%{image_id: id, action: :unchanged}] = report.images
      assert id == image.id
      assert [%{action: :unchanged, events: [%{action: :existing}]}] = hd(report.images).findings
    end

    test "changed metadata is reported as update without writing" do
      image = existing_image!(%{tag: "0.9"})
      existing_placement!(image, %{active: false})
      finding = existing_finding!(image, %{severity: "LOW", fix: nil})
      existing_event!(finding)

      before = table_counts()
      assert {:ok, report} = Import.dry_run(parse!(snapshot()))
      assert table_counts() == before

      assert report.summary.images.update == 1
      assert report.summary.placements.update == 1
      assert report.summary.findings.update == 1
      assert report.summary.events.existing == 1
    end

    test "a new event on an existing finding is a create" do
      image = existing_image!()
      existing_placement!(image)
      existing = existing_finding!(image)
      existing_event!(existing)

      new_event = event(%{"occurred_at" => "2026-09-02T00:00:00Z"})

      assert {:ok, report} =
               Import.dry_run(
                 parse!(
                   snapshot(%{
                     "images" => [
                       image(%{"findings" => [finding(%{"events" => [event(), new_event]})]})
                     ]
                   })
                 )
               )

      assert report.summary.events == %{create: 1, update: 0, unchanged: 0, existing: 1}
    end

    test "uses a fixed number of SELECTs regardless of snapshot size" do
      small = parse!(snapshot())
      assert count_selects(fn -> assert {:ok, _} = Import.dry_run(small) end) <= 4

      images =
        Enum.map(1..10, fn i ->
          image(%{
            "digest" => "sha256:" <> String.duplicate(Integer.to_string(i), 64),
            "placements" =>
              Enum.map(1..5, fn p ->
                placement(%{"owner" => "team-#{p}", "environment" => "env-#{p}"})
              end),
            "findings" =>
              Enum.map(1..5, fn f ->
                finding(%{
                  "cve" => "CVE-2025-10#{f}",
                  "package_name" => "pkg-#{f}",
                  "events" => [event(%{"occurred_at" => "2026-09-0#{f}T00:00:00Z"})]
                })
              end)
          })
        end)

      large = parse!(snapshot(%{"images" => images}))
      assert count_selects(fn -> assert {:ok, _} = Import.dry_run(large) end) <= 4
    end
  end

  describe "write path (import_snapshot/1, apply/1, write!/1)" do
    test "creates rows on an empty inventory and a reimport is a no-op" do
      json = Jason.encode!(snapshot())
      before = table_counts()

      assert {:ok, report} = Import.import_snapshot(json)

      assert report.summary.images == %{create: 1, update: 0, unchanged: 0, existing: 0}
      assert report.summary.placements == %{create: 1, update: 0, unchanged: 0, existing: 0}
      assert report.summary.findings == %{create: 1, update: 0, unchanged: 0, existing: 0}
      assert report.summary.events == %{create: 1, update: 0, unchanged: 0, existing: 0}

      after_first = table_counts()

      assert after_first.images == before.images + 1
      assert after_first.placements == before.placements + 1
      assert after_first.findings == before.findings + 1
      assert after_first.events == before.events + 1

      assert {:ok, second} = Import.import_snapshot(json)

      # Idempotent by construction: the same snapshot rewrites nothing.
      assert second.summary.images == %{create: 0, update: 0, unchanged: 1, existing: 0}
      assert second.summary.placements == %{create: 0, update: 0, unchanged: 1, existing: 0}
      assert second.summary.findings == %{create: 0, update: 0, unchanged: 1, existing: 0}
      assert second.summary.events == %{create: 0, update: 0, unchanged: 0, existing: 1}
      assert second.warnings == []
      assert table_counts() == after_first
    end

    test "a reimport updates metadata but never touches cases, evidence or reviews" do
      assert {:ok, _} = Import.import_snapshot(Jason.encode!(snapshot()))

      local_finding = Repo.get_by!(Finding, cve: "CVE-2025-1001")

      assert {:ok, %{case: cse, snapshot: evidence}} =
               Cases.open_case(local_finding.id, owner: "team-a", environment: "prod")

      before_cases = case_counts()

      changed =
        snapshot(%{
          "images" => [
            image(%{
              "tag" => "1.1",
              "findings" => [finding(%{"severity" => "CRITICAL"})]
            })
          ]
        })

      assert {:ok, report} = Import.import_snapshot(Jason.encode!(changed))

      assert report.summary.images == %{create: 0, update: 1, unchanged: 0, existing: 0}
      assert report.summary.findings.update == 1
      assert report.summary.events.existing == 1

      assert Repo.get!(Image, local_finding.image_id).tag == "1.1"
      assert Repo.get_by!(Finding, cve: "CVE-2025-1001").severity == "CRITICAL"

      # Local human work is never rewritten, replaced or deleted by an import.
      assert case_counts() == before_cases

      assert {:ok, %{case: reloaded, snapshot: current, snapshots: snapshots}} =
               Cases.get_case(cse.id)

      assert reloaded.revision == cse.revision
      assert reloaded.id == cse.id
      assert current.id == evidence.id
      assert length(snapshots) == 1
    end

    test "an omitted resolved_at is preserved and reported, never cleared" do
      assert {:ok, _} = Import.import_snapshot(Jason.encode!(snapshot()))

      resolved = Repo.get_by!(Finding, cve: "CVE-2025-1001")

      resolved =
        resolved
        |> Finding.changeset(%{resolved_at: ~U[2026-09-05 00:00:00Z]})
        |> Repo.update!()

      assert {:ok, dry} = Import.dry_run(parse!(snapshot()))
      assert [%{path: "$.images[0].findings[0].resolved_at"}] = dry.warnings

      assert {:ok, report} = Import.import_snapshot(Jason.encode!(snapshot()))
      assert [%{path: "$.images[0].findings[0].resolved_at"}] = report.warnings

      assert Repo.get!(Finding, resolved.id).resolved_at == ~U[2026-09-05 00:00:00Z]
    end

    test "a parse failure writes nothing and reports every problem" do
      before = table_counts()

      assert {:error, errors} =
               Import.import_snapshot(
                 Jason.encode!(snapshot(%{"version" => 2, "surprise" => true}))
               )

      assert Enum.map(errors, & &1.path) |> Enum.sort() == ["$", "$.version"]
      assert table_counts() == before
    end

    test "apply/1 validates before touching the database and writes nothing" do
      before = table_counts()

      assert {:error, errors} = Import.apply(%{images: nil})
      assert Enum.any?(errors, &(&1.path == "$.images" and &1.message =~ "expected a list"))
      assert table_counts() == before
    end

    test "apply/1 re-validates a normalized snapshot and rejects tampering" do
      parsed = parse!(snapshot())
      [image] = parsed.images
      [finding] = image.findings

      tampered = %{
        parsed
        | version: 99,
          images: [
            %{
              image
              | description: "unsafe\u0001text",
                findings: [%{finding | severity: "URGENT"}]
            }
          ]
      }

      before = table_counts()
      assert {:error, errors} = Import.apply(tampered)
      paths = Enum.map(errors, & &1.path)
      assert "$.version" in paths
      assert "$.images[0].description" in paths
      assert "$.images[0].findings[0].severity" in paths
      assert table_counts() == before
    end

    test "write!/1 outside a transaction is rejected before any query or write" do
      before = table_counts()

      selects =
        count_selects(fn ->
          assert_raise ArgumentError, ~r/must be called inside Repo.transaction/, fn ->
            Import.write!(parse!(snapshot()))
          end
        end)

      assert selects == 0
      assert table_counts() == before
    end

    test "write!/1 inside a caller transaction validates and writes" do
      assert {:ok, report} = Repo.transaction(fn -> Import.write!(parse!(snapshot())) end)
      assert report.summary.images == %{create: 1, update: 0, unchanged: 0, existing: 0}
      assert Repo.get_by!(Image, digest: @digest).tag == "1.0"
    end

    test "rejects a snapshot that regresses recorded last_seen times" do
      image = existing_image!()
      existing_placement!(image, %{last_seen: ~U[2026-09-10 00:00:00Z]})
      finding = existing_finding!(image, %{last_seen: ~U[2026-09-10 00:00:00Z]})
      existing_event!(finding)

      before = table_counts()
      assert {:error, errors} = Import.apply(parse!(snapshot()))
      paths = Enum.map(errors, & &1.path)
      assert "$.images[0].placements[0].last_seen" in paths
      assert "$.images[0].findings[0].last_seen" in paths
      assert Enum.all?(errors, &(&1.message =~ "refusing to regress"))
      assert table_counts() == before
      assert Repo.get!(Finding, finding.id).last_seen == ~U[2026-09-10 00:00:00Z]
    end

    test "rejects a snapshot that regresses recorded first_seen times" do
      image = existing_image!()
      existing_placement!(image, %{first_seen: ~U[2026-08-01 00:00:00Z]})
      finding = existing_finding!(image, %{first_seen: ~U[2026-08-01 00:00:00Z]})
      existing_event!(finding)

      before = table_counts()
      assert {:error, errors} = Import.apply(parse!(snapshot()))
      paths = Enum.map(errors, & &1.path)
      assert "$.images[0].placements[0].first_seen" in paths
      assert "$.images[0].findings[0].first_seen" in paths
      assert table_counts() == before
    end

    test "apply/1 takes the advisory lock before rereading the inventory" do
      queries =
        capture_queries(fn ->
          assert {:ok, _} = Import.import_snapshot(Jason.encode!(snapshot()))
        end)

      lock_index = Enum.find_index(queries, &(&1 =~ "pg_advisory_xact_lock"))
      images_index = Enum.find_index(queries, &(&1 =~ ~s(FROM "images")))

      assert is_integer(lock_index)
      assert is_integer(images_index)
      assert lock_index < images_index
    end

    test "write!/1 inside a caller transaction leaves no partial rows when the caller fails" do
      before = table_counts()

      assert_raise RuntimeError, "caller failure", fn ->
        Repo.transaction(fn ->
          Import.write!(parse!(snapshot()))
          raise "caller failure"
        end)
      end

      assert table_counts() == before
    end
  end

  describe "independent public-boundary regressions" do
    test "non-map public inputs return path errors without queries" do
      assert count_selects(fn ->
               for input <- [nil, [], 42, "snapshot", ~U[2026-09-01 00:00:00Z]] do
                 assert {:error, [%{path: "$"} | _]} = Import.validate(input)
                 assert {:error, _} = Import.dry_run(input)
                 assert {:error, _} = Import.apply(input)
                 assert {:error, _} = Import.import_snapshot(input)
               end
             end) == 0
    end

    test "normalized maps reject unknown atom and string keys at every level" do
      parsed = parse!(snapshot())

      paths = [
        [],
        [:images, Access.at(0)],
        [:images, Access.at(0), :placements, Access.at(0)],
        [:images, Access.at(0), :findings, Access.at(0)],
        [:images, Access.at(0), :findings, Access.at(0), :events, Access.at(0)]
      ]

      assert count_selects(fn ->
               for path <- paths, key <- [:unexpected, "unexpected", "version"] do
                 bad =
                   if path == [],
                     do: Map.put(parsed, key, true),
                     else: update_in(parsed, path, &Map.put(&1, key, true))

                 assert {:error, errors} = Import.validate(bad)
                 assert Enum.any?(errors, &(&1.message =~ "key"))
                 assert {:error, _} = Import.dry_run(bad)
                 assert {:error, _} = Import.apply(bad)
               end
             end) == 0
    end

    test "optional whitespace cannot bypass text byte or control limits" do
      for value <- [String.duplicate(" ", 4097), "\t", "\n"] do
        assert "$.source" in error_paths(snapshot(%{"source" => value}))
        assert {:error, _} = Import.validate(%{parse!(snapshot()) | source: value})
      end
    end

    test "public map record budgets reject before converting malformed nested timestamps" do
      parsed = parse!(snapshot())

      malformed = %{
        hd(parsed.images)
        | findings: [
            %{
              hd(hd(parsed.images).findings)
              | first_seen: %{~U[2026-09-01 00:00:00Z] | calendar: :invalid_calendar}
            }
          ]
      }

      assert {:error, errors} =
               Import.validate(%{parsed | images: List.duplicate(malformed, 1001)})

      assert Enum.any?(errors, &(&1.message =~ "limit"))
    end

    test "all collection, total-record and aggregate-byte budgets also cover public maps" do
      parsed = parse!(snapshot())
      image = hd(parsed.images)
      finding = hd(image.findings)

      cases = [
        %{parsed | images: [%{image | placements: List.duplicate(hd(image.placements), 501)}]},
        %{parsed | images: [%{image | findings: List.duplicate(finding, 501)}]},
        %{
          parsed
          | images: [
              %{image | findings: [%{finding | events: List.duplicate(hd(finding.events), 201)}]}
            ]
        },
        %{
          parsed
          | images: [
              %{
                image
                | findings:
                    List.duplicate(
                      %{finding | events: List.duplicate(hd(finding.events), 20)},
                      500
                    )
              }
            ]
        },
        %{
          parsed
          | images:
              List.duplicate(
                %{
                  image
                  | repository: String.duplicate("a", 4096),
                    description: String.duplicate("b", 4096),
                    findings: [],
                    placements: []
                },
                1000
              )
        }
      ]

      assert count_selects(fn ->
               for bad <- cases do
                 assert {:error, errors} = Import.validate(bad)
                 assert Enum.any?(errors, &(&1.message =~ "limit"))
                 assert {:error, _} = Import.apply(bad)
                 assert {:error, _} = Import.dry_run(bad)
               end
             end) == 0

      # JSON uses the same total-record policy, before duplicate validation.
      total =
        snapshot(%{
          "images" => [
            image(%{
              "findings" =>
                List.duplicate(finding(%{"events" => List.duplicate(event(), 20)}), 500)
            })
          ]
        })

      assert "$" in error_paths(total)
    end

    test "nested non-maps, structs and malformed DateTimes are controlled errors" do
      parsed = parse!(snapshot())

      for path <- [
            [:images, Access.at(0)],
            [:images, Access.at(0), :placements, Access.at(0)],
            [:images, Access.at(0), :findings, Access.at(0)],
            [:images, Access.at(0), :findings, Access.at(0), :events, Access.at(0)]
          ],
          value <- [nil, [], 42, ~U[2026-09-01 00:00:00Z]] do
        bad = put_in(parsed, path, value)
        assert {:error, _} = Import.validate(bad)
        assert {:error, _} = Import.dry_run(bad)
      end

      for time <- [
            %{~U[2026-09-01 00:00:00Z] | calendar: :invalid_calendar},
            %{~U[2026-09-01 00:00:00Z] | year: nil}
          ] do
        bad = %{parsed | generated_at: time}
        assert {:error, [%{path: "$.generated_at"}]} = Import.validate(bad)
      end
    end

    test "invalid composable writes reject unknown keys before queries" do
      bad = Map.put(parse!(snapshot()), "version", 99)

      assert {:ok, :checked} =
               Repo.transaction(fn ->
                 assert count_selects(fn ->
                          assert_raise ArgumentError, ~r/invalid snapshot/, fn ->
                            Import.write!(bad)
                          end
                        end) == 0

                 :checked
               end)
    end

    test "dry run rejects stale observations with the same errors and no writes" do
      existing = existing_image!()
      existing_placement!(existing, %{last_seen: ~U[2026-09-10 00:00:00Z]})
      parsed = parse!(snapshot())
      assert {:error, errors} = Import.apply(parsed)
      assert {:error, ^errors} = Import.dry_run(parsed)
    end

    test "CLI stale dry run raises a controlled Mix error with a JSON path" do
      existing = existing_image!()
      existing_placement!(existing, %{last_seen: ~U[2026-09-10 00:00:00Z]})

      path =
        Path.join(System.tmp_dir!(), "triage-stale-#{System.unique_integer([:positive])}.json")

      File.write!(path, Jason.encode!(snapshot()))
      on_exit(fn -> File.rm!(path) end)

      assert_raise Mix.Error, ~r/\$\.images\[0\]\.placements\[0\]\.last_seen/, fn ->
        Mix.Tasks.Triage.Import.run(["--file", path])
      end
    end
  end

  defp case_counts do
    %{
      cases: Repo.aggregate(ReviewCase, :count),
      snapshots: Repo.aggregate(EvidenceSnapshot, :count),
      reviews: Repo.aggregate(Review, :count),
      case_events: Repo.aggregate(CaseEvent, :count)
    }
  end

  defp table_counts do
    %{
      images: Repo.aggregate(Image, :count),
      placements: Repo.aggregate(ImagePlacement, :count),
      findings: Repo.aggregate(Finding, :count),
      events: Repo.aggregate(FindingEvent, :count)
    }
  end
end
