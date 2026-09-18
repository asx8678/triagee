defmodule TriageWeb.IntelLive do
  @moduledoc """
  Data tools · Intel: the cached public-intelligence surface, and the honest
  state of that cache.

  Read-only. Nothing here contacts a network: adapters run only through the
  explicit manual CLI (`mix triage.intel`) with sources enabled by configuration,
  so an empty cache is reported as empty rather than silently looking current.

  Public intelligence is never a statement about the local estate: absence from
  a cache is not absence of exposure, and a cached advisory is not a verdict on
  any team, image or finding in this inventory.
  """

  use TriageWeb, :live_view

  alias Triage.Intel
  alias Triage.Intel.Config

  @news_limit 25
  @receipt_limit 10

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Intel")
     |> assign(:enabled?, Config.enabled?())
     |> assign(:sources, Config.enabled_sources())
     |> assign(:news, read(&news/0))
     |> assign(:receipts, read(&receipts/0))
     |> assign(:news_error?, false)
     |> assign(:receipts_error?, false)}
  end

  @impl true
  def handle_event("reload", _params, socket) do
    news = read(&news/0)
    receipts = read(&receipts/0)

    {:noreply,
     socket
     |> assign(:news, news)
     |> assign(:receipts, receipts)
     |> assign(:news_error?, news == :unavailable)
     |> assign(:receipts_error?, receipts == :unavailable)}
  end

  # A broken cache read must look broken, never like an empty cache.
  defp read(fun) do
    fun.()
  rescue
    _e -> :unavailable
  catch
    :exit, _ -> :unavailable
  end

  defp news, do: Intel.list_cached_news(@news_limit) |> Enum.take(@news_limit)
  defp receipts, do: Intel.latest_receipts() |> Enum.take(@receipt_limit)

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="intel">
      <.page_header
        title="Intel"
        subtitle="Cached public advisories and news, with their provenance and freshness."
      />

      <details id="intel-policy-help">
        <summary>Refresh policy and limitations</summary>
        <p id="intel-banner" class="supporting">
          Local inventory is never written from here, and this page never downloads anything.
          Adapters run only through <code>mix triage.intel --kev</code> (and an explicitly
          enabled source) with operator approval; a failed refresh keeps the last good cache
          and records a receipt. Public intelligence is not a statement about this estate.
        </p>
      </details>

      <dl class="metric-strip metric-strip-compact" aria-label="Intel cache state">
        <div>
          <dt>Cached news items</dt>
          <dd id="intel-news-count">{length(@news)}</dd>
        </div>
        <div>
          <dt>Network sources</dt>
          <dd id="intel-enabled-state">
            {if @enabled?, do: "Enabled by configuration", else: "Disabled (default)"}
          </dd>
        </div>
        <div>
          <dt>Named sources</dt>
          <dd id="intel-named-sources">
            {if @sources == [], do: "None named", else: Enum.map_join(@sources, ", ", &to_string/1)}
          </dd>
        </div>
        <div>
          <dt>Refresh receipts</dt>
          <dd id="intel-receipt-count">
            {if @receipts == :unavailable, do: "—", else: length(@receipts)}
          </dd>
        </div>
      </dl>

      <details id="intel-source-help">
        <summary>Source configuration</summary>
        <p id="intel-source-policy" class="supporting">
          Each source must be both enabled and named before it may be refreshed; an unnamed
          source is refused, so the configuration is a restriction rather than a statement of
          intent. This build is a local, synthetic-data demo: an empty cache is expected and
          means nothing has been fetched, not that nothing is published.
        </p>
      </details>

      <.notice :if={@news_error?} id="intel-news-error" kind="warning" role="alert">
        The cached news read failed. This is a read failure, not an empty cache.
      </.notice>

      <section id="intel-news" class="stack" aria-labelledby="intel-news-title">
        <h2 id="intel-news-title">Cached news and advisories</h2>
        <.empty_state
          :if={@news == []}
          id="intel-news-empty"
          title="No cached news yet"
          description="Nothing has been fetched into the intel cache. An empty cache is not an absence of published advisories."
        >
          <:actions>
            <button id="intel-reload" type="button" phx-click="reload" class="button button-secondary">
              Re-read cache
            </button>
          </:actions>
        </.empty_state>

        <ul :if={is_list(@news) and @news != []} id="intel-news-list" class="ov-list">
          <li :for={item <- @news} id={"intel-news-#{item.source}-#{item.item_id}"}>
            <strong>{item.title}</strong>
            <div class="supporting">
              {item.source} ·
              <%= if Intel.safe_link?(item.link) do %>
                <a href={item.link} rel="noreferrer noopener" target="_blank">source</a>
              <% else %>
                Link withheld (not an https URL)
              <% end %>
              <span :if={item.published_at}> · published <.timestamp value={item.published_at} /></span>
              <span :if={item.fetched_at}> · fetched <.timestamp value={item.fetched_at} /></span>
            </div>
            <p :if={item.summary}>{item.summary}</p>
          </li>
        </ul>
      </section>

      <.notice :if={@receipts_error?} id="intel-receipts-error" kind="warning" role="alert">
        The refresh-receipt read failed. This is a read failure, not a missing history.
      </.notice>

      <section id="intel-receipts" class="stack" aria-labelledby="intel-receipts-title">
        <h2 id="intel-receipts-title">Refresh receipts</h2>
        <p class="supporting">
          Every attempt is recorded, including failures, so a stale cache is visible as stale.
        </p>
        <.empty_state
          :if={@receipts == []}
          id="intel-receipts-empty"
          title="No refresh has been attempted"
          description="Receipts appear here after an operator runs the intel task, whether it succeeded or failed."
        />
        <dl :if={is_list(@receipts) and @receipts != []} id="intel-receipt-list" class="ov-receipts">
          <div :for={receipt <- @receipts} id={"intel-receipt-#{receipt.id}"}>
            <dt>{receipt.source}</dt>
            <dd>
              {if receipt.succeeded, do: "OK", else: "FAILED"}
              <span :if={receipt.item_count}>· {receipt.item_count} items</span>
              · <.timestamp value={receipt.attempted_at} />
            </dd>
            <dd :if={receipt.message} class="supporting">{receipt.message}</dd>
          </div>
        </dl>
      </section>

      <details id="intel-legend" class="disclosure">
        <summary>What a cache can and cannot tell you</summary>
        <p>
          Absence from this cache is not absence of a published advisory, and presence is not
          a verdict on any finding here. Suppression, applicability and exposure are recorded
          per scope elsewhere in the app; intel never overrides them.
        </p>
      </details>
    </Layouts.app>
    """
  end
end
