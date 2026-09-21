defmodule TriageWeb.ToolsReadabilityTest do
  use TriageWeb.LegacyUICase, async: false

  alias Triage.Inventory.Image
  alias Triage.Replay.{Run, Runs}
  alias Triage.Repo
  alias TriageWeb.ReplayLive

  @fixture Path.expand("../fixtures/replay/complete.json", __DIR__)

  setup do
    Triage.DataCase.reset_inventory!()
    Repo.delete_all(Run)
    :ok
  end

  test "import steps separate selection, preview, confirmation and applied result", %{conn: conn} do
    {:ok, view, _} = live(conn, "/imports")
    assert_step(view, "import", 1)
    assert has_element?(view, "#import-preview[phx-disable-with]")
    refute has_element?(view, "#import-apply")
    before = inventory()

    upload(view, "#import-upload-form", :snapshot, snapshot())
    refute has_element?(view, "#import-preview-result")
    assert inventory() == before
    view |> form("#import-upload-form") |> render_submit()
    assert_step(view, "import", 2)
    assert has_element?(view, "#import-preview-result .status-badge", "Not applied")
    assert has_element?(view, "#import-preview-result [role='region'][tabindex='0'][aria-label]")
    assert has_element?(view, "#import-preview-table caption", "Proposed")
    assert has_element?(view, "#import-preview-table th[scope='col']", "Record type")
    assert has_element?(view, "#import-preview-table-images th[scope='row']", "Images")

    assert has_element?(
             view,
             "#import-preview-provenance time[datetime='2026-09-09T06:00:00Z']",
             "UTC"
           )

    refute has_element?(view, "#import-apply")
    assert inventory() == before

    view |> element("#import-review") |> render_click(%{"value" => ""})
    assert_step(view, "import", 3)

    assert has_element?(
             view,
             "#import-confirm-form[aria-describedby='import-confirm-effects'][phx-mounted]"
           )

    assert has_element?(view, "#import-confirm-effects", "may make saved evidence stale")
    refute has_element?(view, "#import-confirm-form input[type='checkbox'][checked]")
    assert inventory() == before

    view |> form("#import-confirm-form", confirmation: %{ack: "true"}) |> render_submit()
    assert_step(view, "import", 4)
    assert has_element?(view, "#import-receipt [role='status']", "Import completed")
    assert has_element?(view, "#import-receipt-heading[tabindex='-1'][phx-mounted]")
    assert has_element?(view, "#import-receipt-table caption", "Applied")
    assert has_element?(view, "#import-receipt-provenance time[datetime='2026-09-09T06:00:00Z']")
    assert Repo.aggregate(Image, :count) == 1
    after_apply = inventory()

    {:ok, reloaded, _} = live(conn, "/imports")
    assert_step(reloaded, "import", 1)
    refute has_element?(reloaded, "#import-receipt")
    refute has_element?(reloaded, "#import-confirm-form")
    assert inventory() == after_apply
  end

  test "import provenance is escaped text, missing metadata is honest and cancel never writes", %{
    conn: conn
  } do
    {:ok, view, _} = live(conn, "/imports")
    source = "<script>untrusted-source()</script>"

    json =
      snapshot()
      |> Jason.decode!()
      |> Map.put("source", source)
      |> Map.delete("generated_at")
      |> Jason.encode!()

    upload(view, "#import-upload-form", :snapshot, json)
    view |> form("#import-upload-form") |> render_submit()
    assert has_element?(view, "#import-preview-provenance dd", source)
    assert has_element?(view, "#import-preview-provenance dd", "Not reported")
    refute has_element?(view, "#import-preview-provenance script")
    refute has_element?(view, "#import-preview-provenance time")
    assert {:ok, prepared} = Triage.ImportFlow.prepare(json)

    assert has_element?(
             view,
             "#import-preview-provenance-digest button[data-copy-value='#{prepared.digest}'][phx-hook='CopyValue']"
           )

    view |> element("#import-review") |> render_click()
    view |> element("#import-cancel") |> render_click()
    assert_step(view, "import", 1)
    refute has_element?(view, "#import-confirm-form")
    refute has_element?(view, "#import-preview-provenance")
    assert Repo.aggregate(Image, :count) == 0

    upload(view, "#import-upload-form", :snapshot, "{invalid-json")
    view |> form("#import-upload-form") |> render_submit()
    assert has_element?(view, "#import-error[role='alert']", "preview again")
    refute has_element?(view, "#import-receipt")
    assert Repo.aggregate(Image, :count) == 0
  end

  test "replay steps keep selecting, running and saving separate with exact receipt times", %{
    conn: conn
  } do
    before = inventory()
    {:ok, view, _} = live(conn, "/replay")
    assert_step(view, "replay", 1)
    assert has_element?(view, "#replay-run[phx-disable-with]")
    json = File.read!(@fixture)
    upload(view, "#replay-form", :replay, json)
    assert_step(view, "replay", 2)
    refute has_element?(view, "#replay-result")
    refute has_element?(view, "#replay-save")
    assert Repo.aggregate(Run, :count) == 0

    view |> form("#replay-form") |> render_submit()
    assert_step(view, "replay", 3)
    assert has_element?(view, "#replay-result [role='status']", "Summary not saved")
    assert has_element?(view, "#replay-result-heading[tabindex='-1'][phx-mounted]")

    assert has_element?(
             view,
             "#replay-save[phx-disable-with][aria-describedby='replay-save-help']"
           )

    assert has_element?(view, "#replay-summary dt", "Would be actionable in replay")
    assert {:ok, summary} = Triage.Replay.run(json)

    assert has_element?(
             view,
             "#replay-summary-digest button[data-copy-value='#{summary["input_sha256"]}'][phx-hook='CopyValue']"
           )

    assert Repo.aggregate(Run, :count) == 0
    assert inventory() == before

    view |> element("#replay-save") |> render_click(%{"value" => ""})
    assert_step(view, "replay", 4)
    receipt = Repo.one!(Run)

    assert has_element?(
             view,
             "#replay-saved[role='status'] time[datetime='#{DateTime.to_iso8601(receipt.received_at)}']",
             "UTC"
           )

    assert has_element?(
             view,
             "#replay-saved time[datetime='#{DateTime.to_iso8601(receipt.expires_at)}']"
           )

    refute has_element?(view, "#replay-save")
    render_click(view, "save", %{"value" => ""})
    assert Repo.one!(Run) == receipt
    assert inventory() == before

    {:ok, reloaded, _} = live(conn, "/replay")
    assert_step(reloaded, "replay", 1)
    refute has_element?(reloaded, "#replay-result")
    assert Repo.one!(Run) == receipt
  end

  test "history disclosures have distinct exact-copy IDs and browsing is passive", %{conn: conn} do
    json = File.read!(@fixture)
    {:ok, first} = Runs.record_result("readability-first", json)
    {:ok, second} = Runs.record_result("readability-second", json)
    before = inventory()
    receipts = Repo.all(Run)
    {:ok, view, _} = live(conn, "/replay/history")
    assert has_element?(view, "#replay-history-count", "2 receipts on this page")
    assert has_element?(view, "#replay-history-order", "by receipt ID")

    for row <- [first, second] do
      selector = "#replay-receipt-#{row.id}"

      assert has_element?(
               view,
               "details#{selector} > summary .status-badge",
               "Complete synthetic replay"
             )

      assert has_element?(
               view,
               "#{selector} > summary time[datetime='#{DateTime.to_iso8601(row.received_at)}']",
               "UTC"
             )

      assert has_element?(
               view,
               "#{selector} > summary [data-receipt-count='Findings']",
               "Findings"
             )

      assert has_element?(
               view,
               "#{selector} > summary [data-receipt-count='Suppressed findings']",
               "Suppressed findings"
             )

      assert has_element?(
               view,
               "#{selector}-summary-digest button[data-copy-value='#{row.input_sha256}']"
             )
    end

    ids =
      view
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.query("[id]")
      |> LazyHTML.attribute("id")

    assert length(ids) == length(Enum.uniq(ids))
    refute has_element?(view, "#replay-history-stream [phx-click]")
    refute has_element?(view, "#replay-history-stream form")
    render_patch(view, "/replay/history?after=#{first.id}")
    assert has_element?(view, "#replay-history-count", "1 receipts on this page")
    refute has_element?(view, "#replay-receipt-#{first.id}")
    view |> element("#replay-history-first") |> render_click()
    assert has_element?(view, "#replay-receipt-#{first.id}")
    assert Repo.all(Run) == receipts
    assert inventory() == before
  end

  test "history errors do not masquerade as empty results and offer read-only recovery", %{
    conn: conn
  } do
    {:ok, view, _} = live(conn, "/replay/history?after=invalid")
    assert has_element?(view, "#replay-history-error[role='alert']", "First page")
    refute has_element?(view, "#replay-history-empty")
    refute has_element?(view, "#replay-history-count")
    view |> element("#replay-history-first") |> render_click()
    refute has_element?(view, "#replay-history-error")
    assert has_element?(view, "#replay-history-empty h2", "No retained replay receipts")
    assert Repo.aggregate(Run, :count) == 0
  end

  test "missing replay telemetry is unavailable rather than zero or a favorable state" do
    result =
      ReplayLive.safe_summary(%{
        "counts" => %{"findings" => -1, "images" => "0"},
        "input_sha256" => "<script>bad()</script>"
      })

    html = render_component(&ReplayLive.summary_panel/1, id: "missing-summary", result: result)
    document = LazyHTML.from_fragment(html)

    assert document |> LazyHTML.query("#missing-summary .status-badge") |> LazyHTML.text() ==
             "Completeness unavailable"

    values = document |> LazyHTML.query("#missing-summary dd") |> Enum.map(&LazyHTML.text/1)
    assert values == List.duplicate("Unavailable", 5)
    assert Enum.empty?(LazyHTML.query(document, "button[data-copy-value]"))
    assert Enum.empty?(LazyHTML.query(document, "script"))
  end

  test "import and replay file inputs stay labelled and keyboard operable", %{conn: conn} do
    assert_file_input(conn, "/imports", "#import-upload-form", "Historical snapshot JSON")
    assert_file_input(conn, "/replay", "#replay-form", "Replay JSON")
  end

  test "first page control is disabled on the first page and enabled after paging", %{conn: conn} do
    json = File.read!(@fixture)
    {:ok, first} = Runs.record_result("first-page-disabled", json)
    {:ok, view, _} = live(conn, "/replay/history")
    assert has_element?(view, "button#replay-history-first[disabled][aria-disabled='true']")
    refute has_element?(view, "a#replay-history-first")

    render_patch(view, "/replay/history?after=#{first.id}")
    assert has_element?(view, "a#replay-history-first")
    refute has_element?(view, "button#replay-history-first[disabled]")

    view |> element("#replay-history-first") |> render_click()
    assert has_element?(view, "button#replay-history-first[disabled]")
  end

  defp assert_file_input(conn, path, form, label) do
    {:ok, view, _} = live(conn, path)
    document = view |> render() |> LazyHTML.from_fragment()
    input = LazyHTML.query(document, "#{form} input[type='file']")
    assert Enum.count(input) == 1
    [input_id] = LazyHTML.attribute(input, "id")
    [input_class] = LazyHTML.attribute(input, "class")
    assert input_class =~ "file-input"
    assert has_element?(view, "#{form} .triage-upload")
    assert has_element?(view, "#{form} label[for='#{input_id}']", label)
    refute has_element?(view, "#{form} input[type='file'][disabled]")
    refute has_element?(view, "#{form} input[type='file'][tabindex='-1']")
    refute has_element?(view, "#{form} input[type='file'][hidden]")
  end

  defp assert_step(view, tool, step) do
    assert has_element?(view, "##{tool}-steps > li:nth-child(#{step})[aria-current='step']")
    assert has_element?(view, "##{tool}-steps > li:nth-child(#{step})[data-step-state='current']")

    document = view |> render() |> LazyHTML.from_fragment()

    steps = LazyHTML.query(document, "##{tool}-steps > li[aria-current='step']")
    assert Enum.count(steps) == 1

    complete = LazyHTML.query(document, "##{tool}-steps > li[data-step-state='complete']")
    assert Enum.count(complete) == step - 1

    upcoming = LazyHTML.query(document, "##{tool}-steps > li[data-step-state='upcoming']")
    assert Enum.count(upcoming) == 4 - step
  end

  defp upload(view, selector, field, content) do
    file_input(view, selector, field, [
      %{name: "local.json", content: content, type: "application/json"}
    ])
    |> render_upload("local.json")
  end

  defp snapshot do
    Jason.encode!(%{
      format: "triage.snapshot",
      version: 1,
      source: "synthetic readability fixture",
      generated_at: "2026-09-09T06:00:00Z",
      images: [
        %{
          digest: "sha256:" <> String.duplicate("d", 64),
          repository: "synthetic/readability",
          tag: "historical",
          placements: [],
          findings: []
        }
      ]
    })
  end

  defp inventory do
    for table <- ~w(images image_placements findings finding_events), into: %{} do
      {table, Repo.query!("SELECT to_jsonb(t) FROM #{table} t ORDER BY id", [], log: false).rows}
    end
  end
end
