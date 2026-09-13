defmodule TriageWeb.ImportLiveTest do
  use TriageWeb.ConnCase, async: false
  import Phoenix.LiveViewTest
  alias Triage.Repo
  alias Triage.Inventory.Image

  setup do
    Triage.DataCase.reset_inventory!()
    :ok
  end

  defp upload(view, content) do
    file_input(view, "#import-upload-form", :snapshot, [
      %{name: "historical.json", content: content, type: "application/json"}
    ])
    |> render_upload("historical.json")
  end

  defp json do
    Jason.encode!(%{
      format: "triage.snapshot",
      version: 1,
      source: "synthetic historical fixture",
      generated_at: "2026-09-09T06:00:00Z",
      images: [
        %{
          digest: "sha256:" <> String.duplicate("d", 64),
          repository: "synthetic/example",
          tag: "historical",
          placements: [],
          findings: []
        }
      ]
    })
  end

  defp preview(view) do
    upload(view, json())
    view |> form("#import-upload-form") |> render_submit()
    assert has_element?(view, "#import-preview-result")
  end

  test "preview is read-only and apply requires review plus acknowledgement", %{conn: conn} do
    {:ok, view, _} = live(conn, "/imports")
    assert has_element?(view, "#import-local-notice")
    preview(view)
    assert Repo.aggregate(Image, :count) == 0
    refute has_element?(view, "#import-apply")
    view |> element("#import-review") |> render_click()
    view |> form("#import-confirm-form", confirmation: %{ack: "true"}) |> render_submit()
    assert has_element?(view, "#import-receipt")
    assert Repo.aggregate(Image, :count) == 1
    render_click(view, "apply", %{"confirmation" => %{"nonce" => "forged", "ack" => "true"}})
    assert Repo.aggregate(Image, :count) == 1
    refute has_element?(view, "#import-receipt")
  end

  test "shipped browser review button value preserves exact nonce binding", %{conn: conn} do
    {:ok, view, _} = live(conn, "/imports")
    preview(view)
    view |> element("#import-review") |> render_click(%{"value" => ""})
    assert has_element?(view, "#import-confirm-form")
    view |> form("#import-confirm-form", confirmation: %{ack: "true"}) |> render_submit()
    assert has_element?(view, "#import-receipt")
    assert Repo.aggregate(Image, :count) == 1
    preview(view)
    view |> element("#import-review") |> render_click(%{"value" => "forged"})
    refute has_element?(view, "#import-confirm-form")
    assert has_element?(view, "#import-error")
  end

  test "exact nonce duplicate event cannot write twice", %{conn: conn} do
    {:ok, view, _} = live(conn, "/imports")
    preview(view)
    view |> element("#import-review") |> render_click()

    nonce =
      view
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.query("#import-confirm-form input[name='confirmation[nonce]']")
      |> LazyHTML.attribute("value")
      |> hd()

    payload = %{"confirmation" => %{"nonce" => nonce, "ack" => "true"}}
    render_submit(view, "apply", payload)
    first = Repo.one!(Image)
    render_submit(view, "apply", payload)
    assert Repo.one!(Image) == first
    assert has_element?(view, "#import-error")
  end

  test "wrong shape, cancellation and replacement invalidate a valid confirmation", %{conn: conn} do
    {:ok, view, _} = live(conn, "/imports")

    for event <- ["review", "apply", "preview", "cancel", "unknown"] do
      preview(view)
      view |> element("#import-review") |> render_click()
      render_click(view, event, %{"confirmation" => [], "path" => "/private/secret"})
      refute has_element?(view, "#import-confirm-form")
      refute has_element?(view, "#import-preview-result")
      assert Repo.aggregate(Image, :count) == 0
    end

    preview(view)
    view |> element("#import-review") |> render_click()
    upload(view, "{private-source-secret")
    refute has_element?(view, "#import-confirm-form")
    view |> form("#import-upload-form") |> render_submit()
    assert has_element?(view, "#import-error")
    refute render(view) =~ "private-source-secret"
    refute render(view) =~ "/private/secret"
  end

  test "missing acknowledgement cancels the prepared binding", %{conn: conn} do
    {:ok, view, _} = live(conn, "/imports")
    preview(view)
    view |> element("#import-review") |> render_click()
    view |> form("#import-confirm-form") |> render_submit()
    assert has_element?(view, "#import-error")
    refute has_element?(view, "#import-confirm-form")
    assert Repo.aggregate(Image, :count) == 0
  end

  test "new invalid input and forged events cannot reuse an earlier preview", %{conn: conn} do
    {:ok, view, _} = live(conn, "/imports")
    preview(view)
    view |> form("#import-upload-form") |> render_change()
    refute has_element?(view, "#import-preview-result")
    upload(view, "{invalid secret source text")
    view |> form("#import-upload-form") |> render_submit()
    assert has_element?(view, "#import-error")
    refute has_element?(view, "#import-review")
    render_click(view, "preview", %{"path" => "/etc/passwd"})
    render_click(view, "review", %{"nonce" => "forged"})
    assert Repo.aggregate(Image, :count) == 0
  end
end
