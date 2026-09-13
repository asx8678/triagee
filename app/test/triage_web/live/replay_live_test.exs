defmodule TriageWeb.ReplayLiveTest do
  use TriageWeb.ConnCase, async: false

  alias Triage.Replay.Run
  alias Triage.Repo

  @fixture Path.expand("../../fixtures/replay/complete.json", __DIR__)

  setup do
    Triage.DataCase.reset_inventory!()
    Repo.delete_all(Run)
    :ok
  end

  test "real upload replays without writes; explicit save and duplicate reuse one receipt", %{
    conn: conn
  } do
    before = inventory()
    {:ok, view, _} = live(conn, "/replay")
    assert has_element?(view, "#replay-form")
    assert has_element?(view, "#replay-example[href='/assets/examples/replay.json']")
    assert has_element?(view, "#replay-safety", "Synthetic, not live")
    refute has_element?(view, "#replay-save")
    assert Repo.aggregate(Run, :count) == 0

    upload(view, File.read!(@fixture))
    assert Repo.aggregate(Run, :count) == 0
    view |> form("#replay-form") |> render_submit()
    assert has_element?(view, "#replay-result", "Complete synthetic evidence")
    assert has_element?(view, "#replay-save")
    refute has_element?(view, "[id^='replay-upload-']")
    assert Repo.aggregate(Run, :count) == 0
    assert inventory() == before
    assert_safe(view)

    view |> element("#replay-save") |> render_click()
    assert has_element?(view, "#replay-saved")
    assert has_element?(view, "#replay-history-link[href='/replay/history']")
    receipt = Repo.one!(Run)
    render_click(view, "save", %{})
    assert Repo.one!(Run) == receipt
    assert inventory() == before
    assert_safe(view)

    {:ok, reloaded, _} = live(conn, "/replay")
    refute has_element?(reloaded, "#replay-result")
    refute has_element?(reloaded, "#replay-save")
    assert Repo.aggregate(Run, :count) == 1
  end

  test "shipped browser button value permits save and clear, but not arbitrary values", %{
    conn: conn
  } do
    {:ok, view, _} = live(conn, "/replay")
    replay(view)
    render_click(view, "save", %{"value" => ""})
    assert has_element?(view, "#replay-saved")
    receipt = Repo.one!(Run)
    render_click(view, "save", %{"value" => ""})
    assert Repo.one!(Run) == receipt
    replay(view)
    render_click(view, "cancel", %{"value" => ""})
    assert has_element?(view, "#replay-error", "cancelled")
    refute has_element?(view, "#replay-save")
    replay(view)
    render_click(view, "save", %{"value" => "forged"})
    refute has_element?(view, "#replay-save")
    assert Repo.one!(Run) == receipt
  end

  test "new validation, failed JSON and forged events clear old save bindings", %{conn: conn} do
    {:ok, view, _} = live(conn, "/replay")
    replay(view)
    render_change(view, "validate", %{})
    refute has_element?(view, "#replay-result")
    render_click(view, "save", %{})
    assert has_element?(view, "#replay-error")
    assert Repo.aggregate(Run, :count) == 0

    replay(view)
    upload(view, "{malformed")
    refute has_element?(view, "#replay-save")
    view |> form("#replay-form") |> render_submit()
    assert has_element?(view, "#replay-error")
    refute has_element?(view, "#replay-result")
    render_click(view, "save", %{})
    assert Repo.aggregate(Run, :count) == 0

    for {event, payload} <- [
          {"save", %{"json" => File.read!(@fixture), "key" => "forged-secret"}},
          {"replay", %{"path" => "/etc/passwd"}},
          {"validate", %{"_target" => %{"nested" => "bad"}}},
          {"save", %{"key" => ["nested"]}}
        ] do
      replay(view)
      render_click(view, event, payload)
      assert has_element?(view, "#replay-error")
      refute has_element?(view, "#replay-result")
      refute has_element?(view, "#replay-save")
      render_click(view, "save", %{})
      assert Repo.aggregate(Run, :count) == 0
    end
  end

  test "new replay without upload and cancellation cannot save an old result", %{conn: conn} do
    {:ok, view, _} = live(conn, "/replay")
    replay(view)
    view |> form("#replay-form") |> render_submit()
    assert has_element?(view, "#replay-error")
    refute has_element?(view, "#replay-save")
    replay(view)
    view |> element("#replay-cancel") |> render_click()
    assert has_element?(view, "#replay-error", "cancelled")
    refute has_element?(view, "#replay-result")
    render_click(view, "save", %{})
    assert Repo.aggregate(Run, :count) == 0
  end

  test "oversized upload invalidates a previous successful result", %{conn: conn} do
    {:ok, view, _} = live(conn, "/replay")
    replay(view)

    input =
      file_input(view, "#replay-form", :replay, [
        %{
          name: "large.json",
          content: String.duplicate("x", 1_000_001),
          type: "application/json"
        }
      ])

    assert {:error, _} = render_upload(input, "large.json")
    render_change(view, "validate", %{})
    refute has_element?(view, "#replay-save")
    render_click(view, "save", %{})
    assert has_element?(view, "#replay-error")
    assert Repo.aggregate(Run, :count) == 0
  end

  test "incomplete evidence is clearly labelled rather than actionable", %{conn: conn} do
    {:ok, view, _} = live(conn, "/replay")

    json =
      @fixture |> File.read!() |> Jason.decode!() |> Map.put("details", []) |> Jason.encode!()

    upload(view, json)
    view |> form("#replay-form") |> render_submit()
    assert has_element?(view, "#replay-result", "Incomplete synthetic evidence")
    assert has_element?(view, "#replay-result", "Incomplete evidence:")
    assert has_element?(view, "#replay-safety", "non-actionable")
    assert Repo.aggregate(Run, :count) == 0
  end

  test "download is the genuine complete fixture", %{conn: conn} do
    response = get(conn, "/assets/examples/replay.json")
    assert response.status == 200
    assert response.resp_body == File.read!(@fixture)
    assert {:ok, %{"complete" => true}} = Triage.Replay.run(response.resp_body)
  end

  test "quota failure is static and clears the accepted save binding", %{conn: conn} do
    {:ok, sample} = Triage.Replay.Runs.record_result("quota-template", File.read!(@fixture))

    rows =
      for n <- 1..999 do
        %{
          key_hash: Base.encode16(:crypto.hash(:sha256, "quota-#{n}"), case: :lower),
          input_sha256: sample.input_sha256,
          summary: sample.summary,
          outcome: sample.outcome,
          received_at: sample.received_at,
          expires_at: sample.expires_at
        }
      end

    Repo.insert_all(Run, rows)
    {:ok, view, _} = live(conn, "/replay")
    replay(view)
    view |> element("#replay-save") |> render_click()
    assert has_element?(view, "#replay-error", "quota")
    refute has_element?(view, "#replay-save")
    refute has_element?(view, "#replay-result")
    render_click(view, "save", %{})
    assert Repo.aggregate(Run, :count) == 1000
  end

  defp replay(view) do
    upload(view, File.read!(@fixture))
    view |> form("#replay-form") |> render_submit()
    assert has_element?(view, "#replay-save")
  end

  defp upload(view, json) do
    input =
      file_input(view, "#replay-form", :replay, [
        %{
          name: "private-upload-name.json",
          content: json,
          type: "application/json"
        }
      ])

    render_upload(input, "private-upload-name.json")
  end

  defp assert_safe(view) do
    text = view |> render() |> LazyHTML.from_fragment() |> LazyHTML.text()

    for secret <- [
          "do-not-emit",
          "synthetic-owner",
          "synthetic-repository",
          "synthetic-package",
          "00000000-0000-0000-0000-000000000001",
          "private-upload-name.json",
          "forged-secret"
        ] do
      refute text =~ secret
    end
  end

  defp inventory do
    for table <- ~w(images image_placements findings finding_events), into: %{} do
      {table, Repo.query!("SELECT to_jsonb(t) FROM #{table} t ORDER BY id", [], log: false).rows}
    end
  end
end
