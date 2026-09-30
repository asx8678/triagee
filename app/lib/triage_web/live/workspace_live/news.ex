defmodule TriageWeb.WorkspaceLive.News do
  @moduledoc """
  News page and the CVE research list for `TriageWeb.WorkspaceLive`. Both
  fetch public sources only when a person opens or refreshes them.
  """
  use TriageWeb, :html
  import Phoenix.LiveView, only: [connected?: 1, start_async: 3]
  import TriageWeb.WorkspaceComponents, only: [time: 1]

  @events ~w(refresh-news manual-open manual-close manual-fetch manual-save)
  def events, do: @events

  def handle_event("refresh-news", _, socket) do
    if socket.assigns.news_cves_loading or socket.assigns.news_headlines_loading,
      do: {:noreply, socket},
      else: {:noreply, start_news(socket)}
  end

  def handle_event("manual-close", _, socket), do: {:noreply, assign(socket, manual_open: false)}

  # The research list is read only when its dialog opens, not on every page load.
  def handle_event("manual-open", _, %{assigns: %{manual_open: false}} = socket),
    do: {:noreply, assign(socket, manual_open: true, manual_cves: Triage.ManualCves.list())}

  def handle_event("manual-open", _, socket), do: {:noreply, assign(socket, manual_open: false)}

  def handle_event("manual-fetch", %{"manual" => %{"cve" => cve}}, socket) do
    if socket.assigns.manual_loading do
      {:noreply, socket}
    else
      {:noreply,
       socket
       |> assign(
         manual_loading: true,
         manual_preview: nil,
         manual_error: nil,
         manual_form: to_form(%{"cve" => cve}, as: :manual)
       )
       |> start_async(:manual_fetch, fn -> Triage.ManualCves.fetch(cve) end)}
    end
  end

  def handle_event("manual-save", _, %{assigns: %{manual_preview: nil}} = socket),
    do: {:noreply, socket}

  def handle_event("manual-save", _, socket) do
    case Triage.ManualCves.save(socket.assigns.manual_preview) do
      {:ok, _} ->
        {:noreply,
         assign(socket,
           manual_preview: nil,
           manual_cves: Triage.ManualCves.list(),
           message: "CVE saved to your research list."
         )}

      {:error, _} ->
        {:noreply, assign(socket, manual_error: "Could not save this CVE. Please try again.")}
    end
  end

  def maybe_load_news(socket) do
    if socket.assigns.can_review and socket.assigns.page == "news" and connected?(socket) and
         not socket.assigns.news_started,
       do: start_news(socket),
       else: socket
  end

  defp start_news(socket) do
    socket
    |> assign(
      news_started: true,
      news_cves_loading: true,
      news_headlines_loading: true,
      news_cves_error: nil,
      news_headlines_error: nil
    )
    |> start_async(:news_cves, fn -> Triage.SecurityNews.critical() end)
    |> start_async(:news_headlines, fn -> Triage.SecurityNews.headlines() end)
  end

  def handle_async(:news_cves, {:ok, {:ok, result}}, socket),
    do: {:noreply, assign(socket, news_cves: result, news_cves_loading: false)}

  def handle_async(:news_headlines, {:ok, {:ok, result}}, socket),
    do: {:noreply, assign(socket, news_headlines: result, news_headlines_loading: false)}

  def handle_async(:news_cves, result, socket),
    do: {:noreply, assign(socket, news_cves_loading: false, news_cves_error: news_error(result))}

  def handle_async(:news_headlines, result, socket),
    do:
      {:noreply,
       assign(socket, news_headlines_loading: false, news_headlines_error: news_error(result))}

  def handle_async(:manual_fetch, {:ok, {:ok, row}}, socket),
    do: {:noreply, assign(socket, manual_loading: false, manual_preview: row)}

  def handle_async(:manual_fetch, {:ok, {:error, error}}, socket),
    do: {:noreply, assign(socket, manual_loading: false, manual_error: error)}

  def handle_async(:manual_fetch, {:exit, _}, socket),
    do:
      {:noreply,
       assign(socket,
         manual_loading: false,
         manual_error: "NVD request failed. Please try again."
       )}

  defp news_error({:ok, {:error, message}}) when is_binary(message), do: message
  defp news_error(_), do: "Source could not be refreshed. Please try again."

  attr :form, :map, required: true
  attr :loading, :boolean, required: true
  attr :error, :string, default: nil
  attr :preview, :map, default: nil
  attr :cves, :list, required: true
  attr :can_review, :boolean, required: true

  def research_dialog(assigns) do
    ~H"""
    <dialog
      id="manual-cves"
      class="confirm manual-cves"
      phx-hook="WorkspaceDialog"
      data-close-event="manual-close"
      aria-labelledby="manual-title"
    >
      <div class="confirmation-layout">
        <header class="modal-head">
          <h2 id="manual-title">Add CVE · Research list</h2>
        </header>
        <div class="modal-body">
          <div class="panel-body">
            <p class="muted">
              Paste a CVE ID to fetch its description from NVD. Saved research CVEs do not count as affected inventory.
            </p>
            <.form
              for={@form}
              id="manual-cve-form"
              phx-submit="manual-fetch"
              class="manual-cve-form"
            >
              <.input
                field={@form[:cve]}
                label="CVE number"
                placeholder="CVE-2024-3094"
                required
                maxlength="40"
                disabled={@loading}
              />
              <button type="submit" disabled={@loading}>{if @loading,
                do: "Fetching…",
                else: "Fetch from NVD"}</button>
            </.form>
            <p :if={@error} id="manual-cve-error" class="form-error" role="alert">
              {@error}
            </p>
            <div :if={@preview} id="manual-cve-preview">
              <h3>{@preview.external_id}</h3>
              <p>{@preview.summary}</p>
              <p>
                <a
                  href={"https://nvd.nist.gov/vuln/detail/" <> @preview.external_id}
                  target="_blank"
                  rel="noopener noreferrer"
                >Source: NVD</a>
              </p>
              <button :if={@can_review} id="manual-cve-save" phx-click="manual-save">Save to research list</button>
            </div>
          </div>
          <div :if={@cves != []} class="panel-body" id="manual-cve-list">
            <details :for={cve <- @cves} id={"research-#{cve.external_id}"}>
              <summary>{cve.external_id}</summary>
              <p>{cve.summary}</p>
              <a
                href={"https://nvd.nist.gov/vuln/detail/" <> cve.external_id}
                target="_blank"
                rel="noopener noreferrer"
              >Source: NVD</a>
              <span class="muted"> · Fetched {time(cve.fetched_at)}</span>
            </details>
          </div>
        </div>
        <footer class="modal-foot"><button phx-click="manual-close">Close</button></footer>
      </div>
    </dialog>
    """
  end
end
