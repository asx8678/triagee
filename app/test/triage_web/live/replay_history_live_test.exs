defmodule TriageWeb.ReplayHistoryLiveTest do
  use TriageWeb.ConnCase, async: false

  alias Triage.Replay.{Run, Runs}
  alias Triage.Repo

  @fixture Path.expand("../../fixtures/replay/complete.json", __DIR__)
  @ttl 30 * 24 * 60 * 60

  setup do
    Triage.DataCase.reset_inventory!()
    Repo.delete_all(Run)
    :ok
  end

  test "empty history is honest and browsing never writes", %{conn: conn} do
    before = inventory()
    {:ok, view, _} = live(conn, "/replay/history")
    assert has_element?(view, "#replay-history-empty")
    refute has_element?(view, "#replay-history-stream #replay-history-empty")
    refute has_element?(view, "#replay-history-next")
    refute has_element?(view, "#replay-history-error")
    assert has_element?(view, "#replay-history-safety", "not live evidence")
    refute has_element?(view, "#replay-history-stream button")
    assert Repo.aggregate(Run, :count) == 0
    assert inventory() == before
  end

  test "ascending bounded pages with Next and First page and separate details cards", %{
    conn: conn
  } do
    rows = for n <- 1..27, do: receipt!("pagination-#{n}")
    first = hd(rows)
    twenty_fifth = Enum.at(rows, 24)
    twenty_sixth = Enum.at(rows, 25)
    before = inventory()

    {:ok, view, _} = live(conn, "/replay/history")
    assert row_count(view) == 25

    ids =
      view
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.query("#replay-history-stream > details")
      |> LazyHTML.attribute("id")

    assert ids == Enum.map(Enum.take(rows, 25), &"replay-receipt-#{&1.id}")

    assert has_element?(
             view,
             "details#replay-receipt-#{first.id} > summary",
             "Complete synthetic replay"
           )

    assert has_element?(
             view,
             "#replay-history-next[href='/replay/history?after=#{twenty_fifth.id}']"
           )

    refute has_element?(view, "#replay-receipt-#{twenty_sixth.id}")
    view |> element("#replay-history-next") |> render_click()
    assert_patch(view, "/replay/history?after=#{twenty_fifth.id}")
    assert row_count(view) == 2
    assert has_element?(view, "#replay-receipt-#{twenty_sixth.id}")
    refute has_element?(view, "#replay-receipt-#{first.id}")
    refute has_element?(view, "#replay-history-next")
    view |> element("#replay-history-first") |> render_click()
    assert_patch(view, "/replay/history")
    assert row_count(view) == 25
    assert inventory() == before
    assert Repo.aggregate(Run, :count) == 27
  end

  test "refreshing an expired page clears previously rendered rows", %{conn: conn} do
    row = receipt!("expires-after-mount")
    {:ok, view, _} = live(conn, "/replay/history")
    assert has_element?(view, "#replay-receipt-#{row.id}")
    # Production receipts are immutable: simulate elapsed time with a separate
    # expired fixture after deleting this test fixture inside the sandbox.
    Repo.delete!(row)

    Repo.insert_all(Run, [
      attrs(row, "already-expired", DateTime.add(DateTime.utc_now(), -@ttl - 60, :second))
    ])

    render_patch(view, "/replay/history?after=0")
    assert row_count(view) == 0
    assert has_element?(view, "#replay-history-empty")
    refute has_element?(view, "#replay-history-next")
  end

  test "strict invalid cursors clear rows and controls and can recover", %{conn: conn} do
    row = receipt!("cursor-private-key")
    {:ok, view, _} = live(conn, "/replay/history")

    for query <- [
          "after=-1",
          "after=no",
          "after=9223372036854775808",
          "after[]=1",
          "after=1&unknown=true",
          "after="
        ] do
      render_patch(view, "/replay/history?#{query}")
      assert has_element?(view, "#replay-history-error")
      refute has_element?(view, "#replay-history-empty")
      assert row_count(view) == 0
      refute has_element?(view, "#replay-history-next")
      render_patch(view, "/replay/history")
      assert has_element?(view, "#replay-receipt-#{row.id}")
      refute has_element?(view, "#replay-history-error")
    end

    render_click(view, "purge", %{"id" => row.id})
    assert has_element?(view, "#replay-history-error")
    assert row_count(view) == 0
    assert Repo.aggregate(Run, :count) == 1
  end

  test "expired receipts are hidden and source secrets or unknown summary fields never render", %{
    conn: conn
  } do
    sample = receipt!("caller-private-key")
    past = DateTime.add(DateTime.utc_now(), -@ttl - 60, :second)
    expired = attrs(sample, "expired-private-key", past)
    {1, [expired_row]} = Repo.insert_all(Run, [expired], returning: [:id])
    noisy = attrs(sample, "another-private-key", DateTime.utc_now())

    noisy = %{
      noisy
      | summary:
          Map.merge(sample.summary, %{
            "private" => "<script>private-summary-secret</script>",
            "diagnostics" => ["unknown-private-diagnostic", "incomplete_evidence"],
            "counts" =>
              Map.put(sample.summary["counts"], "private-counter", "private-count-secret")
          })
    }

    {1, [noisy_row]} = Repo.insert_all(Run, [noisy], returning: [:id])

    {:ok, view, _} = live(conn, "/replay/history")
    assert row_count(view) == 2
    refute has_element?(view, "#replay-receipt-#{expired_row.id}")
    assert has_element?(view, "#replay-receipt-#{noisy_row.id}", "Incomplete evidence:")
    assert has_element?(view, "#replay-receipt-#{sample.id}", sample.input_sha256)
    text = view |> render() |> LazyHTML.from_fragment() |> LazyHTML.text()

    for secret <- [
          "caller-private-key",
          sample.key_hash,
          "do-not-emit",
          "synthetic-owner",
          "synthetic-package",
          "private-summary-secret",
          "unknown-private-diagnostic",
          "private-count-secret",
          "private-counter"
        ] do
      refute text =~ secret
    end

    refute has_element?(view, "#replay-history-stream script")
    assert Repo.aggregate(Run, :count) == 3
  end

  defp receipt!(key) do
    {:ok, row} = Runs.record_result(key, File.read!(@fixture))
    row
  end

  defp attrs(sample, key, received) do
    %{
      key_hash: Base.encode16(:crypto.hash(:sha256, key), case: :lower),
      input_sha256: sample.input_sha256,
      summary: sample.summary,
      outcome: sample.outcome,
      received_at: received,
      expires_at: DateTime.add(received, @ttl, :second)
    }
  end

  defp row_count(view) do
    view
    |> render()
    |> LazyHTML.from_fragment()
    |> LazyHTML.query("#replay-history-stream > details")
    |> Enum.count()
  end

  defp inventory do
    for table <- ~w(images image_placements findings finding_events), into: %{} do
      {table, Repo.query!("SELECT to_jsonb(t) FROM #{table} t ORDER BY id", [], log: false).rows}
    end
  end
end
