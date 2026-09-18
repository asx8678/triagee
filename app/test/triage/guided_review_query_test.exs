defmodule Triage.GuidedReviewQueryTest do
  use Triage.DataCase, async: true
  import Triage.Fixtures
  alias Triage.{Decisions, GuidedReview}

  setup do
    reset_inventory!()
    image = image!("query")
    placement = placement!(image, "alpha", "prod")
    %{image: image, placement: placement}
  end

  test "keyset traversal has no omissions or duplicates, and get is independent", %{image: image} do
    cves = for n <- 1..27, do: "CVE-2090-#{1000 + n}"
    Enum.each(cves, &finding!(image, &1))
    assert {:ok, first} = GuidedReview.page()
    assert length(first.rows) == 25
    assert first.has_more?
    assert is_binary(first.next_after_cve)
    assert GuidedReview.get(List.last(cves)).cve == List.last(cves)
    assert {:ok, last} = GuidedReview.page(after_cve: first.next_after_cve)
    assert Enum.map(first.rows ++ last.rows, & &1.cve) == cves
    refute last.has_more?
    assert last.next_after_cve == nil
    assert {:error, :invalid_page} = GuidedReview.page(after_cve: List.last(cves))
  end

  test "covered candidates do not erase the continuation cursor", %{image: image} do
    for n <- 1..3, do: finding!(image, "CVE-2090-#{1000 + n}")

    for n <- 1..2 do
      assert {:ok, _} =
               Decisions.record(%{
                 cve: "CVE-2090-#{1000 + n}",
                 decision: "not_affected",
                 reason: "Scoped test",
                 actor: "test",
                 decided_at: DateTime.add(DateTime.utc_now(), -60)
               })
    end

    assert {:ok, %{rows: [], has_more?: true, next_after_cve: cursor}} =
             GuidedReview.page(limit: 2)

    assert {:ok, %{rows: [row], has_more?: false}} =
             GuidedReview.page(limit: 2, after_cve: cursor)

    assert row.cve == "CVE-2090-1003"
    assert GuidedReview.get("CVE-2090-1001") == nil

    assert Enum.map(GuidedReview.actionable_for([row.cve, row.cve, "missing"]), & &1.cve) == [
             row.cve
           ]
  end

  test "a page bound never truncates one advisory's scopes", %{image: image} do
    finding!(image, "CVE-2090-1001")
    for n <- 1..101, do: placement!(image, "owner-#{n}", "prod")
    assert {:ok, %{rows: [row]}} = GuidedReview.page(limit: 1)
    assert length(row.scopes) == 102
    assert length(row.pending) == 102
  end

  test "queue, get and timeline selection share the detail KEV classification inputs", %{
    image: image
  } do
    finding = finding!(image, "CVE-2090-7654", severity: "HIGH")

    Repo.insert!(%Triage.Intel.Advisory{
      source: "kev",
      external_id: finding.cve,
      fetched_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })

    expected =
      Triage.Risk.classify(%{
        severity: finding.severity,
        exposure: "unknown",
        known_exploited: Triage.Intel.cached_kev(finding.cve) != [],
        fix_available: false
      })

    assert expected.priority == "critical"
    assert {:ok, %{rows: [row]}} = GuidedReview.page()
    assert row.risk == expected
    assert hd(row.scopes).risk == expected
    assert GuidedReview.get(finding.cve).risk == expected
    assert [selected] = GuidedReview.actionable_for([finding.cve])
    assert selected.risk == expected
  end

  test "an unrelated intelligence source does not become KEV evidence", %{image: image} do
    finding = finding!(image, "CVE-2090-7655", severity: "HIGH")

    Repo.insert!(%Triage.Intel.Advisory{
      source: "nvd:" <> finding.cve,
      external_id: finding.cve,
      fetched_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })

    risk = GuidedReview.get(finding.cve).risk
    assert risk.priority == "high"
    assert "Not listed as known exploited — absence is not evidence" in risk.reasons
  end

  test "risk ordering precedes CVE and keysets continue after the anchor disappears", %{
    image: image
  } do
    finding!(image, "CVE-2090-1000", severity: "LOW")
    urgent = finding!(image, "CVE-2090-9999", severity: "CRITICAL")
    finding!(image, "CVE-2090-9998", severity: "HIGH")
    assert {:ok, first} = GuidedReview.page(limit: 1)
    assert [row] = first.rows
    assert row.cve == urgent.cve
    Repo.delete!(urgent)
    assert {:ok, second} = GuidedReview.page(limit: 1, after_cve: first.next_after_cve)
    assert Enum.map(second.rows, & &1.cve) == ["CVE-2090-9998"]
    assert {:ok, third} = GuidedReview.page(limit: 1, after_cve: second.next_after_cve)
    assert Enum.map(third.rows, & &1.cve) == ["CVE-2090-1000"]
    refute third.has_more?
  end

  test "SQL ordering matches classifier for all severities, KEV and exposure states" do
    cases =
      for severity <- ["CRITICAL", "HIGH", "MEDIUM", "LOW", nil, " high "],
          exposure <- ["internet_exposed", "internal", "unknown"],
          kev <- [false, true],
          do: {severity, exposure, kev}

    expected =
      cases
      |> Enum.with_index()
      |> Enum.map(fn {{severity, exposure, kev}, n} ->
        image = image!("parity-#{n}")
        placement = placement!(image, "parity", "prod")
        cve = "CVE-2091-#{1000 + n}"
        finding!(image, cve, severity: severity)

        {:ok, _} =
          Triage.Exposure.record(
            placement.id,
            exposure,
            "test",
            DateTime.add(DateTime.utc_now(), -60)
          )

        if kev,
          do:
            Repo.insert!(%Triage.Intel.Advisory{
              source: "kev",
              external_id: cve,
              fetched_at: DateTime.utc_now() |> DateTime.truncate(:second)
            })

        risk =
          Triage.Risk.classify(%{severity: severity, exposure: exposure, known_exploited: kev})

        {Enum.find_index(Triage.Risk.priorities(), &(&1 == risk.priority)), cve}
      end)
      |> Enum.sort()
      |> Enum.map(&elem(&1, 1))

    assert {:ok, page} = GuidedReview.page(limit: 100)
    assert Enum.map(page.rows, & &1.cve) == expected
  end

  test "filters select complete CVEs, search is literal, and cursors bind filters", %{
    image: image,
    placement: placement
  } do
    finding!(image, "CVE-2090-1001", severity: "LOW", package_name: "lib_100%")
    finding!(image, "CVE-2090-1002", severity: "LOW", package_name: "lib_100%")
    placement!(image, "beta", "dev")

    {:ok, _} =
      Triage.Exposure.record(
        placement.id,
        "internet_exposed",
        "test",
        DateTime.add(DateTime.utc_now(), -60)
      )

    opts = [
      q: "100%",
      team: "alpha",
      severity: "LOW",
      kev: "no",
      exposure: "internet_exposed",
      limit: 1
    ]

    assert {:ok, first} = GuidedReview.page(opts)
    assert [row] = first.rows
    assert length(row.scopes) == 2
    assert row.risk.priority == "high"
    assert {:ok, last} = GuidedReview.page(opts ++ [after_cve: first.next_after_cve])
    assert Enum.map(last.rows, & &1.cve) == ["CVE-2090-1002"]
    assert {:error, :invalid_page} = GuidedReview.page(after_cve: first.next_after_cve)
    assert {:ok, %{rows: []}} = GuidedReview.page(q: "100X")
    assert {:ok, %{rows: []}} = GuidedReview.page(kev: "yes")

    for opts <- [[q: []], [severity: "urgent"], [kev: true], [team: <<0>>], [exposure: "public"]] do
      assert {:error, :invalid_page} = GuidedReview.page(opts)
    end
  end

  test "malformed and unbounded options are rejected before querying" do
    for opts <- [
          %{},
          nil,
          [1],
          [limit: 0],
          [limit: 101],
          [limit: "2"],
          [limit: 2, limit: 3],
          [unknown: true],
          [after_cve: []],
          [after_cve: <<255>>],
          [after_cve: "x\0"],
          [after_cve: String.duplicate("x", 201)]
        ] do
      assert {:error, :invalid_page} = GuidedReview.page(opts)
    end

    for cve <- [nil, [], "", <<255>>, "x\0"], do: assert(GuidedReview.get(cve) == nil)
  end
end
