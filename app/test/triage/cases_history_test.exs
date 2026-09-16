defmodule Triage.CasesHistoryTest do
  use Triage.DataCase, async: false
  import Triage.Fixtures
  alias Triage.Cases
  alias Triage.Cases.History
  alias TriageWeb.CaseLive.Format

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  test "previews bound each stream, omit sensitive fields and preserve full-history formatting" do
    %{case: cse, snapshot: snapshot} = open!("bounded-history")

    current =
      Enum.reduce(1..27, cse, fn _index, current ->
        assert {:ok, %{case: updated}} =
                 Cases.submit_review(
                   current.id,
                   current.revision,
                   snapshot.id,
                   Ecto.UUID.generate(),
                   review_attrs()
                 )

        updated
      end)

    preview = History.previews([current])[current.id]
    assert length(preview.reviews) == History.stream_limit()
    assert length(preview.events) == History.stream_limit()
    assert preview.history_truncated?

    for review <- preview.reviews do
      refute Map.has_key?(review, :idempotency_token)
      refute Map.has_key?(review, :request_hash)
    end

    for snapshot <- preview.snapshots, do: refute(Map.has_key?(snapshot, :payload))

    assert {:ok, full} = Cases.get_case(current.id)
    assert length(full.reviews) == 27
    entries = Format.timeline_entries(preview)
    keys = MapSet.new(entries, & &1.key)
    expected = full |> Format.timeline_entries() |> Enum.filter(&MapSet.member?(keys, &1.key))
    assert entries == expected
  end

  test "query families are fixed and cases never receive another case history" do
    %{case: one} = open!("history-one")
    %{case: two} = open!("history-two")
    assert count_queries(fn -> History.previews([one]) end) == 3
    assert count_queries(fn -> History.previews([one, two]) end) == 3
    previews = History.previews([one, two])

    for cse <- [one, two] do
      preview = previews[cse.id]
      refute preview.history_truncated?
      assert Enum.all?(preview.events, &(&1.case_id == cse.id))
      assert Enum.all?(preview.reviews, &(&1.case_id == cse.id))
    end

    assert History.previews([]) == %{}
  end

  defp open!(name) do
    image = image!(name)
    placement!(image, "alpha", "prod")
    finding = finding!(image, "CVE-2026-7200")
    event!(finding, "appeared", at(1))
    assert {:ok, opened} = Cases.open_case(finding.id, owner: "alpha", environment: "prod")
    opened
  end

  defp count_queries(fun) do
    counter = :counters.new(1, [])
    id = "history-budget-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        id,
        [:triage, :repo, :query],
        fn _event, _measurements, _metadata, _config -> :counters.add(counter, 1, 1) end,
        nil
      )

    try do
      fun.()
      :counters.get(counter, 1)
    after
      :telemetry.detach(id)
    end
  end
end
