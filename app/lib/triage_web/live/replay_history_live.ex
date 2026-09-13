defmodule TriageWeb.ReplayHistoryLive do
  use TriageWeb, :live_view

  alias Triage.Replay.Runs
  alias TriageWeb.ReplayLive

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(
       page_title: "Replay history",
       error: nil,
       empty?: false,
       next: nil,
       page_count: 0,
       cursor: 0
     )
     |> stream_configure(:runs, dom_id: &"replay-receipt-#{&1.id}")
     |> stream(:runs, [])}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    with {:ok, cursor} <- cursor(params),
         {:ok, rows} <- Runs.list(limit: 26, after_id: cursor) do
      page = Enum.take(rows, 25)
      next = if length(rows) > 25, do: List.last(page).id, else: nil

      {:noreply,
       socket
       |> assign(
         error: nil,
         empty?: page == [],
         next: next,
         page_count: length(page),
         cursor: cursor
       )
       |> stream(:runs, Enum.map(page, &safe_row/1), reset: true)}
    else
      {:error, :invalid_cursor} ->
        {:noreply, clear(socket, "Invalid history cursor. Choose First page to recover.")}

      _ ->
        {:noreply,
         clear(
           socket,
           "Replay history is unavailable. No history was changed. Choose First page to retry."
         )}
    end
  end

  @impl true
  def handle_event(_event, _params, socket),
    do: {:noreply, clear(socket, "Unsupported history request. Choose First page to recover.")}

  defp cursor(params) when params == %{}, do: {:ok, 0}

  defp cursor(%{"after" => value} = params)
       when map_size(params) == 1 and is_binary(value) and byte_size(value) in 1..19 do
    if Regex.match?(~r/\A[0-9]+\z/, value) do
      case Integer.parse(value) do
        {n, ""} when n <= 9_223_372_036_854_775_807 -> {:ok, n}
        _ -> {:error, :invalid_cursor}
      end
    else
      {:error, :invalid_cursor}
    end
  end

  defp cursor(_), do: {:error, :invalid_cursor}

  defp clear(socket, message) do
    socket
    |> assign(error: message, empty?: false, next: nil, page_count: 0)
    |> stream(:runs, [], reset: true)
  end

  defp safe_row(row) do
    %{
      id: row.id,
      outcome:
        case row.outcome do
          "complete" -> "Complete synthetic replay"
          "incomplete" -> "Incomplete synthetic replay"
          _ -> "Outcome unavailable"
        end,
      received: safe_time(row.received_at),
      expires: safe_time(row.expires_at),
      result: ReplayLive.safe_summary(row.summary)
    }
  end

  defp safe_time(%DateTime{} = time), do: time
  defp safe_time(_), do: nil

  # Inline receipt counts are projected from the persisted summary only.
  # The stored summary exposes owners/images/findings/suppressed/actionable;
  # there is no "advisories" or "changes" count in the receipt data.
  @inline_counts ["Owners", "Images", "Findings", "Suppressed findings"]

  defp key_counts(%{counts: counts}) when is_list(counts) do
    Enum.filter(counts, fn {label, _value} -> label in @inline_counts end)
  end

  defp key_counts(_), do: []

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active_page="replay-history">
      <section id="replay-history-workspace" class="tool-layout stack">
        <.page_header
          title="Replay history"
          eyebrow="Data tools"
          subtitle="Browse summaries that were explicitly saved from synthetic replays."
        >
          <:actions>
            <.link id="replay-history-new" navigate="/replay" class="button button-secondary">Open replay tool</.link>
          </:actions>
        </.page_header>
        <p id="replay-history-safety" class="supporting">
          Saved synthetic summaries, not live evidence. Non-actionable; inventory unchanged. Receipt times are local storage times, not source history. Browsing never reruns or saves a replay.
        </p>
        <p id="replay-history-order" class="supporting">
          Oldest retained first, by receipt ID. Up to 25 unexpired receipts per page. Receipts expire after 30 days; expired receipts are hidden. No automatic refresh.
        </p>
        <nav class="filter-toolbar" aria-label="Replay history pages">
          <%= if @cursor == 0 and is_nil(@error) do %>
            <button
              id="replay-history-first"
              type="button"
              class="button button-secondary"
              disabled
              aria-disabled="true"
            >First page</button>
          <% else %>
            <.link
              id="replay-history-first"
              patch="/replay/history"
              class="button button-secondary"
            >First page</.link>
          <% end %>
          <p :if={is_nil(@error)} id="replay-history-count" class="filter-summary">
            {@page_count} receipts on this page<span :if={@cursor > 0}> · After receipt {@cursor}</span>
          </p>
          <.link
            :if={@next}
            id="replay-history-next"
            patch={"/replay/history?after=#{@next}"}
            class="button button-secondary"
          >Next page</.link>
        </nav>
        <.notice :if={@error} id="replay-history-error" role="alert" kind="error">{@error}</.notice>
        <div :if={@empty?} id="replay-history-empty">
          <.empty_state
            title="No retained replay receipts on this page"
            description="Replays are saved only by explicit request. Expired receipts are not shown."
          >
            <:actions>
              <.link navigate="/replay" class="button button-secondary">Open replay tool</.link>
            </:actions>
          </.empty_state>
        </div>
        <section aria-labelledby="replay-history-receipts-heading" class="stack">
          <h2 id="replay-history-receipts-heading" class="section-header">Saved receipts</h2>
          <p :if={@page_count > 0} class="supporting">
            Open a receipt to inspect its counts, diagnostics and input fingerprint.
          </p>
          <div id="replay-history-stream" phx-update="stream" class="event-list">
            <details :for={{id, row} <- @streams.runs} id={id} class="disclosure event-item">
              <summary>
                <span class="cluster">
                  <strong>Receipt {row.id}</strong>
                  <.status_badge
                    label={row.outcome}
                    kind={
                      if row.outcome == "Incomplete synthetic replay", do: "warning", else: "neutral"
                    }
                  />
                  <span class="filter-summary">
                    <span :for={{label, value} <- key_counts(row.result)} data-receipt-count={label}>
                      {label}: <strong>{value}</strong>
                    </span>
                  </span>
                  <span class="supporting">Saved locally:
                  <.timestamp :if={row.received} value={row.received} /><span :if={
                    is_nil(row.received)
                  }>Unavailable</span></span>
                </span>
              </summary>
              <div class="stack">
                <dl class="evidence-grid">
                  <div class="key-value">
                    <dt>Receipt expires</dt><dd>
                      <.timestamp :if={row.expires} value={row.expires} /><span :if={
                        is_nil(row.expires)
                      }>Unavailable</span>
                    </dd>
                  </div>
                </dl>
                <ReplayLive.summary_panel id={"#{id}-summary"} result={row.result} />
                <p class="supporting">
                  Synthetic only. No historical provenance asserted. Input documents are not stored in history.
                </p>
              </div>
            </details>
          </div>
        </section>
      </section>
    </Layouts.app>
    """
  end
end
