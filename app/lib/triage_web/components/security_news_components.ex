defmodule TriageWeb.SecurityNewsComponents do
  @moduledoc "Public CVE and vulnerability-news dashboard."
  use TriageWeb, :html

  def panel(assigns) do
    ~H"""
    <div id="security-news">
      <div class="news-heading">
        <div>
          <h1>CVE news</h1><p class="muted">
            Critical CVEs published in {Calendar.strftime(Date.utc_today(), "%B %Y")} · Global advisories, not confirmed local exposure.
          </p>
        </div>
        <button
          id="refresh-news"
          phx-click="refresh-news"
          disabled={@news_cves_loading or @news_headlines_loading}
        >Refresh</button>
      </div>
      <section class="panel">
        <div class="panel-head">
          <h2>This month’s critical CVEs</h2><a
            href="https://nvd.nist.gov/"
            target="_blank"
            rel="noopener noreferrer"
          >Source: NVD</a>
        </div>
        <div class="news-status" aria-live="polite">
          <p :if={@news_cves_loading}>Fetching critical CVEs from NVD…</p>
          <p :if={@news_cves_error} class="form-error" role="alert">
            {@news_cves_error} <span :if={@news_cves}>Previously fetched results remain below.</span>
          </p>
          <p :if={@news_cves} class="muted">
            {length(@news_cves.rows)} advisories · CVSS v3/v4 critical · Fetched {Calendar.strftime(
              @news_cves.fetched_at,
              "%d %b %H:%M UTC"
            )}
          </p>
          <p :if={@news_cves && @news_cves.limited} class="muted">
            NVD’s result limit was reached. This list is incomplete.
          </p>
        </div>
        <div :if={@news_cves} class="table-wrap">
          <table id="news-cve-table" class="data-table news-cve-table">
            <thead>
              <tr>
                <th>CVE / published</th><th>CVSS</th><th>
                  Description
                </th>
              </tr>
            </thead>
            <tbody>
              <tr :for={row <- @news_cves.rows} id={"news-#{row.id}"}>
                <td>
                  <a
                    href={"https://nvd.nist.gov/vuln/detail/" <> row.id}
                    target="_blank"
                    rel="noopener noreferrer"
                  >{row.id}</a><span class="subline">{row.published}</span>
                </td>
                <td><span class="red">{row.score}</span></td>
                <td>
                  <details>
                    <summary>
                      {String.slice(row.description, 0, 150)}{if String.length(row.description) > 150,
                        do: "…"}
                    </summary><p>{row.description}</p>
                  </details>
                </td>
              </tr>
            </tbody>
          </table>
          <p :if={@news_cves.rows == []} class="empty">
            No published CVEs with a critical CVSS v3/v4 score were returned for this month. Unscored CVEs are not included.
          </p>
        </div>
      </section>
      <section class="panel news-headlines">
        <div class="panel-head">
          <h2>Latest vulnerability news</h2><a
            href="https://www.bleepingcomputer.com/"
            target="_blank"
            rel="noopener noreferrer"
          >BleepingComputer</a>
        </div>
        <div class="news-status" aria-live="polite">
          <p :if={@news_headlines_loading}>Fetching recent headlines…</p>
          <p :if={@news_headlines_error} class="form-error" role="alert">
            {@news_headlines_error}
            <span :if={@news_headlines}>Previously fetched headlines remain below.</span>
          </p>
          <p :if={@news_headlines} class="muted">
            Recent publisher headlines · Fetched {Calendar.strftime(
              @news_headlines.fetched_at,
              "%d %b %H:%M UTC"
            )}
          </p>
        </div>
        <div :if={@news_headlines} class="panel-body">
          <article :for={item <- @news_headlines.items} class="news-article">
            <a href={item.url} target="_blank" rel="noopener noreferrer">{item.title}</a><p class="muted">
              {item.date}
            </p>
          </article>
          <p :if={@news_headlines.items == []}>
            No vulnerability headlines were found in the publisher’s latest feed.
          </p>
        </div>
      </section>
    </div>
    """
  end
end
