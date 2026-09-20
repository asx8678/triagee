defmodule TriageWeb.SecurityNewsTest do
  use TriageWeb.ConnCase, async: false
  import Phoenix.LiveViewTest
  alias Triage.SecurityNews

  defp nvd do
    %{
      "totalResults" => 1,
      "vulnerabilities" => [
        %{
          "cve" => %{
            "id" => "CVE-2026-12345",
            "published" => "2026-09-10T12:00:00.000",
            "descriptions" => [%{"lang" => "en", "value" => "A library vulnerability."}],
            "metrics" => %{"cvssMetricV31" => [%{"cvssData" => %{"baseScore" => 9.8}}]},
            "configurations" => [
              %{
                "nodes" => [
                  %{
                    "cpeMatch" => [
                      %{
                        "vulnerable" => true,
                        "criteria" => "cpe:2.3:a:vendor:library:1:*:*:*:*:*:*:*"
                      }
                    ]
                  }
                ]
              }
            ],
            "references" => [%{"url" => "https://pypi.org/project/library/"}]
          }
        }
      ]
    }
  end

  defp rss,
    do:
      "<rss><channel><item><title>Critical CVE-2026-12345 patched</title><link>https://www.bleepingcomputer.com/news/security/example/</link><pubDate>Sun, 20 Sep 2026</pubDate></item></channel></rss>"

  setup do
    previous = Application.get_env(:triage, :security_news_transport)

    Application.put_env(:triage, :security_news_transport, fn url, _opts ->
      body =
        if String.starts_with?(url, "https://services.nvd.nist.gov/"),
          do: Jason.encode!(nvd()),
          else: rss()

      {:ok, %{status: 200, body: body}}
    end)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:triage, :security_news_transport, previous),
        else: Application.delete_env(:triage, :security_news_transport)
    end)

    :ok
  end

  test "news fetches on entry, deduplicates scores, and leaves inventory unchanged", %{conn: conn} do
    before = Triage.Workspace.targets()
    {:ok, view, _} = live(conn, "/?page=news")
    render_async(view)
    assert has_element?(view, "#news-CVE-2026-12345", "A library vulnerability.")
    refute has_element?(view, "#news-cve-table th", "Products / libraries")
    refute has_element?(view, "#news-cve-table th", "Ecosystem")
    assert has_element?(view, ".news-article a", "Critical CVE-2026-12345 patched")

    assert Enum.count(
             LazyHTML.from_document(render(view))
             |> LazyHTML.query("#news-cve-table tbody tr")
           ) == 1

    refute has_element?(view, "#workspace-scope")
    assert Triage.Workspace.targets() == before

    Application.put_env(:triage, :security_news_transport, fn _, _ -> {:error, :timeout} end)
    view |> element("#refresh-news") |> render_click()
    render_async(view)
    assert has_element?(view, "#news-CVE-2026-12345")
    assert has_element?(view, "[role=alert]", "Previously fetched")
  end

  test "unknown products remain unknown and noncritical or rejected CVEs are excluded" do
    payload = nvd()
    [entry] = payload["vulnerabilities"]
    bare = put_in(entry, ["cve", "configurations"], []) |> put_in(["cve", "references"], [])

    assert {:ok, %{rows: [row]}} =
             SecurityNews.parse_cves(%{payload | "vulnerabilities" => [bare]})

    assert row.products == "" and row.ecosystems == ""

    low =
      put_in(entry, ["cve", "metrics"], %{
        "cvssMetricV31" => [%{"cvssData" => %{"baseScore" => 7.5}}]
      })

    rejected = put_in(entry, ["cve", "vulnStatus"], "Rejected")

    assert {:ok, %{rows: []}} =
             SecurityNews.parse_cves(%{payload | "vulnerabilities" => [low, rejected]})
  end

  test "RSS refuses entities and unsafe article links" do
    assert {:error, _} =
             SecurityNews.parse_headlines(
               "<!DOCTYPE rss [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><rss>&x;</rss>"
             )

    unsafe =
      String.replace(
        rss(),
        "https://www.bleepingcomputer.com/news/security/example/",
        "javascript:alert(1)"
      )

    assert {:ok, %{items: []}} = SecurityNews.parse_headlines(unsafe)
  end
end
