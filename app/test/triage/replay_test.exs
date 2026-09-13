defmodule Triage.ReplayTest do
  use ExUnit.Case, async: false
  alias Triage.Replay
  defp fixture(name), do: File.read!(Path.join([__DIR__, "../fixtures/replay", name <> ".json"]))
  defp document, do: Jason.decode!(fixture("complete"))
  defp run(d), do: Replay.run(Jason.encode!(d))

  test "empty root is complete and never actionable" do
    assert {:ok, s} = Replay.run(fixture("empty"))
    assert s["complete"]
    assert s["counts"]["findings"] == 0
    refute s["actionable"]
    refute s["historical_provenance"]
    refute s["inventory_changed"]
  end

  test "nonempty evidence is normalized without source leakage" do
    assert {:ok, s} = Replay.run(fixture("complete"))
    assert s["complete"]
    assert s["counts"]["findings"] == 1
    assert s["counts"]["actionable"] == 0
    encoded = Jason.encode!(s)

    for secret <- [
          "do-not-emit",
          "synthetic-owner",
          "synthetic-package",
          "CVE-2099",
          "sha256:synthetic"
        ] do
      refute encoded =~ secret
    end

    assert byte_size(encoded) <= 65_536
  end

  test "omissions and contradictions cannot imply completeness" do
    assert {:ok, %{"complete" => false}} = Replay.run(fixture("incomplete"))
    d = document()

    for changed <- [
          Map.put(d, "inventories", []),
          Map.put(d, "owners", []),
          Map.put(d, "details", d["details"] ++ d["details"])
        ] do
      assert {:ok, %{"complete" => false}} = run(changed)
    end

    [detail] = d["details"]

    for image <- [
          Map.put(detail["image"], "vulnerabilities", nil),
          Map.put(detail["image"], "metrics", %{"vulnerabilities" => 2})
        ] do
      assert {:ok, %{"complete" => false}} =
               run(%{d | "details" => [%{detail | "image" => image}]})
    end
  end

  test "stage-specific Query counts are required and malformed claims rejected" do
    d = document()
    [inventory] = d["inventories"]
    [image] = inventory["images"]
    [detail] = d["details"]

    for {stage, fields} <- [
          inventory: ~w(vulnerabilities vulnerabilitiesSuppressed),
          detail: ~w(vulnerabilities vulnerableComponents)
        ],
        field <- fields,
        value <- [:missing, nil, false, -1, "1", %{}, []] do
      raw = if stage == :inventory, do: image, else: detail["image"]

      raw =
        update_in(raw, ["metrics"], fn metrics ->
          if value == :missing,
            do: Map.delete(metrics, field),
            else: Map.put(metrics, field, value)
        end)

      changed =
        if stage == :inventory,
          do: %{d | "inventories" => [%{inventory | "images" => [raw]}]},
          else: %{d | "details" => [%{detail | "image" => raw}]}

      assert {:ok, %{"complete" => false}} = run(changed)
    end

    for value <- [nil, 0, "0"] do
      changed = put_in(detail, ["image", "metrics", "vulnerabilitiesSuppressed"], value)
      assert {:ok, %{"complete" => false}} = run(%{d | "details" => [changed]})
    end
  end

  test "repeated API identity cannot change its placement claim" do
    d = document()
    [inventory] = d["inventories"]
    [image] = inventory["images"]

    changed =
      Map.put(image, "usedInNamespaces", [%{"id" => "namespace", "owner" => "synthetic-owner"}])

    d = %{d | "inventories" => [%{inventory | "images" => [image, changed]}]}
    assert {:ok, %{"complete" => false}} = run(d)
  end

  test "detail placement claims cannot contradict inventory" do
    d = document()
    [detail] = d["details"]

    for placements <- [nil, [%{"id" => "other", "owner" => "outside"}]] do
      detail = update_in(detail, ["image"], &Map.put(&1, "usedInNamespaces", placements))
      assert {:ok, %{"complete" => false}} = run(%{d | "details" => [detail]})
    end
  end

  test "invalid envelopes and budgets are closed errors" do
    for input <- [
          nil,
          "{",
          String.duplicate(" ", 1_048_577),
          String.duplicate("[", 33) <> String.duplicate("]", 33)
        ] do
      assert {:error, reason} = Replay.run(input)
      assert is_atom(reason)
    end

    for d <- [
          Map.put(document(), "provenance", true),
          Map.put(document(), "owners", nil),
          Map.put(document(), "engine", "secret"),
          Map.put(document(), "environment", "secret"),
          Map.put(document(), "details", List.duplicate(%{}, 5001))
        ] do
      assert {:error, :invalid_document} = run(d)
    end

    d = document()
    [detail] = d["details"]
    image = Map.put(detail["image"], "secret", String.duplicate("x", 4097))
    assert {:error, :invalid_document} = run(%{d | "details" => [%{detail | "image" => image}]})
  end

  test "digest is document canonical, not lexical" do
    d = document()
    assert {:ok, a} = run(d)
    assert {:ok, b} = Replay.run(Jason.encode!(d, pretty: true))
    assert a["input_sha256"] == b["input_sha256"]
    assert a["input_sha256"] =~ ~r/^[a-f0-9]{64}$/
    assert {:ok, c} = run(Map.put(d, "engine", "grype"))
    refute a["input_sha256"] == c["input_sha256"]
  end

  test "genuine Query-shaped open and suppressed evidence matches unchanged Normalize" do
    alias Triage.Collection.{Normalize, Query, Report}

    for name <- ["complete", "suppressed"] do
      d = Jason.decode!(fixture(name))
      [inv] = d["inventories"]
      [image] = inv["images"]
      [row] = d["details"]
      refute Query.image_detail_query(row["id"], d["engine"]) =~ "vulnerabilitiesSuppressed"
      refute Map.has_key?(row["image"]["metrics"], "vulnerabilitiesSuppressed")

      report =
        Normalize.build(%{
          config: %{
            environment: d["environment"],
            engine: d["engine"],
            max_records: 5000,
            max_text_bytes: 4096,
            max_depth: 32,
            max_total_bytes: 8_388_608
          },
          scope: "owners",
          status_marker: nil,
          owners: d["owners"],
          requested_owners: d["owners"],
          inventory: %{
            image["digest"] => %{
              digest: image["digest"],
              image: image,
              owners: MapSet.new(d["owners"]),
              api_ids: MapSet.new([image["id"]]),
              placements: MapSet.new()
            }
          },
          details: %{image["digest"] => Map.drop(row["image"], ["id", "usedInNamespaces"])},
          warnings: [],
          failures: [],
          requests: 0,
          duration_ms: 0
        })

      assert Report.complete?(report)
      assert length(report.findings) + length(report.suppressed) == 1
      assert {:ok, summary} = run(d)
      assert summary["complete"] == Report.complete?(report)
      assert summary["counts"]["images"] == length(report.images)
      assert summary["counts"]["findings"] == length(report.findings)
      assert summary["counts"]["suppressed"] == length(report.suppressed)
    end
  end

  test "unknown stage evidence cannot silently confer completeness or leak claims" do
    d = document()
    [inv] = d["inventories"]
    [image] = inv["images"]
    [detail] = d["details"]

    for field <-
          ~w(vulnerabilities excludedVulnerabilities secret actionable historical_provenance inventory_changed),
        value <- [[%{"vuln" => "private-canary"}], "private-canary", true] do
      changed = %{d | "inventories" => [%{inv | "images" => [Map.put(image, field, value)]}]}
      assert {:ok, %{"complete" => false} = summary} = run(changed)
      refute inspect(summary) =~ "private-canary"
    end

    for field <-
          ~w(secret actionable historical_provenance inventory_changed repository usedInNamespaces) do
      changed = %{
        d
        | "details" => [%{detail | "image" => Map.put(detail["image"], field, "private-canary")}]
      }

      assert {:ok, %{"complete" => false} = summary} = run(changed)
      refute summary["actionable"]
      refute summary["historical_provenance"]
      refute summary["inventory_changed"]
      refute inspect(summary) =~ "private-canary"
    end

    # Finding metadata is intentionally retained/bounded by unchanged Normalize;
    # unlike unknown image evidence it participates in conflict detection.
    changed =
      update_in(d, ["details"], fn [row] ->
        [
          update_in(row, ["image", "vulnerabilities"], fn [v] ->
            [Map.put(v, "metadata", %{"secret" => "private-canary", "actionable" => true})]
          end)
        ]
      end)

    assert {:ok, %{"complete" => true, "actionable" => false} = summary} = run(changed)
    refute inspect(summary) =~ "private-canary"
  end

  test "lexical budgets precede Jason with exact array boundaries and escaped strings" do
    Code.ensure_loaded!(Jason)
    parent = self()
    tracer = spawn_link(fn -> trace_loop(parent) end)
    :erlang.trace_pattern({Jason, :decode, 1}, true, [:local])
    :erlang.trace(self(), true, [:call, {:tracer, tracer}])

    try do
      for value <- [
            "null",
            "true",
            "17",
            "{}",
            "[]",
            Jason.encode!("escaped \\\" [,{}] \\\\ end")
          ] do
        for {count, decoded?} <- [{5000, true}, {5001, false}] do
          input = "[" <> Enum.join(List.duplicate(value, count), ",") <> "]"
          assert {:error, :invalid_document} = Replay.run(input)
          trace_barrier(tracer)
          if decoded?, do: assert_received(:decoded), else: refute_received(:decoded)
        end
      end

      # Container values count in addition to their children, across arrays.
      for {count, decoded?} <- [{2499, true}, {2500, false}] do
        input = "[null," <> Enum.join(List.duplicate("[null]", count), ",") <> "]"
        assert {:error, :invalid_document} = Replay.run(input)
        trace_barrier(tracer)
        if decoded?, do: assert_received(:decoded), else: refute_received(:decoded)
      end

      for {count, decoded?} <- [{64, true}, {65, false}] do
        input = "{" <> Enum.join(List.duplicate("\"same\":null", count), ",") <> "}"
        assert {:error, :invalid_document} = Replay.run(input)
        trace_barrier(tracer)
        if decoded?, do: assert_received(:decoded), else: refute_received(:decoded)
      end

      for input <- ["[null,]", "{", "[}", "[\"unterminated", "[tru]", "[1 2]"] do
        assert {:error, :invalid_json} = Replay.run(input)
        trace_barrier(tracer)
        assert_received :decoded
      end

      for input <- [String.duplicate(" ", 1_048_577), String.duplicate("[", 33)] do
        assert {:error, _} = Replay.run(input)
        trace_barrier(tracer)
        refute_received :decoded
      end
    after
      :erlang.trace(self(), false, [:call])
      :erlang.trace_pattern({Jason, :decode, 1}, false, [:local])
      send(tracer, :stop)
    end
  end

  defp trace_loop(parent) do
    receive do
      {:trace, _, :call, {Jason, :decode, _}} ->
        send(parent, :decoded)
        trace_loop(parent)

      {:barrier, p} ->
        send(p, :drained)
        trace_loop(parent)

      :stop ->
        :ok
    end
  end

  defp trace_barrier(tracer) do
    ref = :erlang.trace_delivered(self())
    assert_receive {:trace_delivered, _, ^ref}
    send(tracer, {:barrier, self()})
    assert_receive :drained
  end
end
