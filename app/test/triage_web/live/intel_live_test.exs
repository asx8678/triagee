defmodule TriageWeb.IntelLiveTest do
  @moduledoc """
  The Intel page is a read-only cache view: it must state the fetch policy and
  show a broken read as broken rather than as an empty cache.
  """
  use TriageWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Triage.Intel

  defp text(document, selector), do: document |> LazyHTML.query(selector) |> LazyHTML.text()

  test "states the fetch policy and reports the disabled default", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/intel")

    assert has_element?(view, "#nav-intel[aria-current='page']")
    assert has_element?(view, "#intel-banner")
    assert has_element?(view, "#intel-source-policy")
    assert render(view) =~ "never downloads anything"
    assert render(view) =~ "Disabled (default)"
    assert has_element?(view, "#intel-news")
    assert has_element?(view, "#intel-receipts")
  end

  test "renders cached news, withholding a link that is not https", %{conn: conn} do
    now = DateTime.utc_now()

    {:ok, _} =
      Intel.replace_news("test", [
        %{
          item_id: "secure",
          title: "Cached secure notice",
          link: "https://example.invalid/secure",
          published_at: now
        },
        %{
          item_id: "insecure",
          title: "Cached insecure notice",
          link: "http://insecure.invalid/item",
          published_at: now
        }
      ])

    {:ok, view, html} = live(conn, ~p"/intel")
    document = LazyHTML.from_document(html)

    assert document
           |> LazyHTML.query("a[href='https://example.invalid/secure']")
           |> Enum.count() == 1

    refute has_element?(view, "#intel-news-test-insecure a")
    assert text(document, "#intel-news-test-insecure") =~ "Link withheld"
    assert has_element?(view, "#intel-news-list")
  end
end
