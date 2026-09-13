defmodule TriageWeb.ImportLive do
  use TriageWeb, :live_view
  alias Triage.ImportFlow

  @impl true
  def mount(_, _, socket) do
    {:ok,
     socket
     |> assign(
       page_title: "Imports",
       prepared: nil,
       stage: :empty,
       receipt: nil,
       receipt_context: nil,
       error: nil,
       upload_form: to_form(%{}, as: :snapshot),
       confirm_form: to_form(%{}, as: :confirmation)
     )
     |> allow_upload(:snapshot,
       accept: ~w(.json),
       max_entries: 1,
       max_file_size: ImportFlow.max_bytes(),
       progress: &handle_progress/3
     )}
  end

  @impl true
  def handle_event("validate", _, socket), do: {:noreply, clear(socket)}

  def handle_event("preview", params, socket)
      when params == %{} or params == %{"snapshot" => ""} do
    socket = clear(socket)
    {done, pending} = uploaded_entries(socket, :snapshot)

    if length(done) == 1 and pending == [] and
         upload_errors(socket.assigns.uploads.snapshot) == [] and
         Enum.all?(done, &(upload_errors(socket.assigns.uploads.snapshot, &1) == [])) do
      results =
        consume_uploaded_entries(socket, :snapshot, fn %{path: path}, _entry ->
          result = with {:ok, json} <- ImportFlow.read_upload(path), do: ImportFlow.prepare(json)
          {:ok, result}
        end)

      case results do
        [{:ok, prepared}] ->
          {:noreply, assign(socket, prepared: prepared, stage: :preview)}

        _ ->
          {:noreply, fail(socket, :invalid_snapshot)}
      end
    else
      {:noreply, fail(socket, :invalid_snapshot)}
    end
  end

  # The shipped LiveSocket includes value="" alongside phx-value-nonce.
  # Normalize only that exact native button shape; retain strict nonce checks.
  def handle_event("review", %{"nonce" => nonce, "value" => ""} = params, socket)
      when map_size(params) == 2,
      do: handle_event("review", %{"nonce" => nonce}, socket)

  def handle_event("review", %{"nonce" => nonce} = params, socket) when map_size(params) == 1 do
    if socket.assigns.stage == :preview and bound?(socket, nonce) do
      {:noreply,
       assign(socket,
         stage: :confirm,
         confirm_form: to_form(%{"nonce" => nonce, "ack" => false}, as: :confirmation)
       )}
    else
      {:noreply, fail(socket, :invalid_confirmation)}
    end
  end

  def handle_event(
        "apply",
        %{"confirmation" => %{"nonce" => nonce, "ack" => "true"} = confirmation} = params,
        socket
      )
      when map_size(params) == 1 and map_size(confirmation) == 2 do
    prepared = socket.assigns.prepared
    allowed = socket.assigns.stage == :confirm and bound?(socket, nonce)
    socket = clear(socket)

    if allowed do
      case ImportFlow.apply(prepared, nonce, "true") do
        {:ok, report} ->
          {:noreply,
           assign(socket,
             receipt: report.summary,
             receipt_context: %{
               source: prepared.snapshot.source,
               generated_at: prepared.snapshot.generated_at,
               digest: prepared.digest
             }
           )}

        {:error, reason} ->
          {:noreply, fail(socket, reason)}
      end
    else
      {:noreply, fail(socket, :invalid_confirmation)}
    end
  end

  def handle_event("cancel-upload", %{"ref" => ref}, socket) do
    socket = clear(socket)

    if Enum.any?(socket.assigns.uploads.snapshot.entries, &(&1.ref == ref)) do
      {:noreply, cancel_upload(socket, :snapshot, ref)}
    else
      {:noreply, fail(socket, :invalid_snapshot)}
    end
  end

  def handle_event("cancel", _, socket), do: {:noreply, clear(socket)}
  def handle_event(_, _, socket), do: {:noreply, fail(socket, :invalid_confirmation)}

  defp handle_progress(:snapshot, _entry, socket), do: {:noreply, clear(socket)}

  defp bound?(socket, nonce) do
    case socket.assigns.prepared do
      %{nonce: ^nonce} ->
        uploaded_entries(socket, :snapshot) == {[], []} and
          upload_errors(socket.assigns.uploads.snapshot) == []

      _ ->
        false
    end
  end

  defp clear(socket),
    do:
      assign(socket,
        prepared: nil,
        stage: :empty,
        receipt: nil,
        receipt_context: nil,
        error: nil,
        confirm_form: to_form(%{}, as: :confirmation)
      )

  defp fail(socket, reason), do: socket |> clear() |> assign(error: reason)

  defp message(:stale_preview),
    do: "Local inventory changed. Nothing was applied. Upload again for a fresh preview."

  defp message(:invalid_snapshot),
    do:
      "Snapshot unavailable or invalid. Choose one valid historical JSON file and preview again."

  defp message(:invalid_confirmation),
    do: "Confirmation expired or incomplete. Preview again before applying."

  defp message(_), do: "Import could not complete and was rolled back. Preview again."

  defp current_step(assigns) do
    cond do
      assigns.receipt -> 4
      assigns.stage == :confirm -> 3
      assigns.stage == :preview -> 2
      assigns.uploads.snapshot.entries != [] -> 2
      true -> 1
    end
  end

  defp step_state(current, step) do
    cond do
      step < current -> "complete"
      step == current -> "current"
      true -> "upcoming"
    end
  end

  @impl true
  def render(assigns) do
    assigns = assign(assigns, :current_step, current_step(assigns))

    ~H"""
    <Layouts.app flash={@flash} active_page="imports">
      <section id="import-workspace" class="tool-layout stack">
        <.page_header
          title="Imports"
          eyebrow="Data tools"
          subtitle="Preview a historical snapshot before changing local inventory."
        />
        <p id="import-local-notice" class="supporting">
          Uploads go to this app only. No external sources are contacted. This is historical inventory, not live collection.
        </p>
        <ol id="import-steps" class="step-list" aria-label="Import steps">
          <li
            :for={
              {step, label} <- [
                {1, "Select file"},
                {2, "Preview"},
                {3, "Confirm & apply"},
                {4, "Result"}
              ]
            }
            id={"import-step-#{step}"}
            class={["step-item", "step-#{step_state(@current_step, step)}"]}
            data-step-state={step_state(@current_step, step)}
            aria-current={if @current_step == step, do: "step"}
          >
            <span :if={step < @current_step} class="step-marker" aria-hidden="true">✓&nbsp;</span>
            <span>{label}</span>
          </li>
        </ol>
        <.form
          for={@upload_form}
          id="import-upload-form"
          phx-change="validate"
          phx-submit="preview"
          class="stack"
        >
          <h2 class="section-header">1. Select a historical snapshot</h2>
          <div class="triage-upload">
            <label for={@uploads.snapshot.ref}>Historical snapshot JSON</label>
            <.live_file_input
              upload={@uploads.snapshot}
              class="file-input"
              aria-describedby="import-file-help"
            />
            <p id="import-file-help" class="supporting">
              One JSON file, at most 1 MB (1,000,000 bytes). Maximum JSON nesting: 32.
            </p>
          </div>
          <p :for={_error <- upload_errors(@uploads.snapshot)} role="alert" class="notice">
            Upload rejected. Select one JSON file within the size limit.
          </p>
          <div
            :for={entry <- @uploads.snapshot.entries}
            id={"import-upload-#{entry.ref}"}
            class="cluster"
          >
            <label for={"import-progress-#{entry.ref}"}>Upload progress: {entry.progress}%</label>
            <progress id={"import-progress-#{entry.ref}"} value={entry.progress} max="100">{entry.progress}%</progress>
            <button
              id={"import-remove-#{entry.ref}"}
              type="button"
              phx-click="cancel-upload"
              phx-value-ref={entry.ref}
              class="button button-secondary"
            >Remove upload</button>
            <p :for={_error <- upload_errors(@uploads.snapshot, entry)} role="alert" class="notice">
              File rejected. Select a JSON file within the size limit.
            </p>
          </div>
          <div class="cluster">
            <button
              id="import-preview"
              type="submit"
              class="button"
              phx-disable-with="Preparing preview…"
            >Preview without writing</button>
            <span class="supporting">Selecting or previewing a file does not import it.</span>
          </div>
        </.form>
        <.notice
          :if={@error}
          id="import-error"
          role="alert"
          kind="error"
          tabindex="-1"
          phx-mounted={JS.focus()}
        >
          {message(@error)}
        </.notice>
        <section
          :if={@prepared}
          id="import-preview-result"
          class="stack"
          aria-labelledby="import-preview-heading"
        >
          <div class="section-header cluster">
            <h2 id="import-preview-heading" tabindex="-1" phx-mounted={JS.focus()}>
              2. Review the preview
            </h2>
            <.status_badge label="Not applied" />
          </div>
          <p class="supporting">
            No inventory has changed. These are proposed record changes, not advisory totals.
          </p>
          <.summary
            summary={@prepared.report.summary}
            id="import-preview-table"
            caption="Proposed local inventory changes"
          />
          <.provenance
            id="import-preview-provenance"
            source={@prepared.snapshot.source}
            generated_at={@prepared.snapshot.generated_at}
            digest={@prepared.digest}
          />
          <p id="import-warning-summary" class="notice">
            Preserved local resolution warnings: {length(@prepared.report.warnings)}. Omitted resolution does not clear a recorded resolution. Raw source warnings are not displayed.
          </p>
          <div class="cluster">
            <button
              :if={@stage == :preview}
              id="import-review"
              type="button"
              phx-click="review"
              phx-value-nonce={@prepared.nonce}
              class="button"
              phx-disable-with="Opening confirmation…"
            >Review &amp; confirm</button>
            <button
              id="import-cancel"
              type="button"
              phx-click={JS.push("cancel") |> JS.focus(to: "#import-preview")}
              class="button button-secondary"
            >Cancel preview</button>
          </div>
          <.form
            :if={@stage == :confirm}
            for={@confirm_form}
            id="import-confirm-form"
            phx-submit="apply"
            phx-mounted={JS.focus(to: "#import-confirm-form input[type='checkbox']")}
            class="stack"
            aria-describedby="import-confirm-effects"
          >
            <h2 class="section-header">3. Confirm &amp; apply</h2>
            <.notice kind="warning" title="This changes local inventory">
              <p id="import-confirm-effects">
                Human case records remain unchanged; imported inventory may make saved evidence stale. Exceptions are not activated.
              </p>
              <p>
                This preview reserves nothing. Apply revalidates under the importer lock and rejects a changed preview.
              </p>
            </.notice>
            <.input field={@confirm_form[:nonce]} type="hidden" />
            <.input
              field={@confirm_form[:ack]}
              type="checkbox"
              label="I acknowledge that Apply changes this local inventory."
            />
            <div>
              <button
                id="import-apply"
                type="submit"
                class="button"
                phx-disable-with="Applying snapshot…"
              >Apply historical snapshot</button>
            </div>
          </.form>
        </section>
        <section
          :if={@receipt}
          id="import-receipt"
          class="stack"
          aria-labelledby="import-receipt-heading"
        >
          <div role="status">
            <h2
              id="import-receipt-heading"
              class="section-header"
              tabindex="-1"
              phx-mounted={JS.focus()}
            >
              4. Import completed
            </h2>
            <p>
              Local inventory reconciled. Human records were not changed. This does not verify a fix or activate exceptions.
            </p>
          </div>
          <.summary
            summary={@receipt}
            id="import-receipt-table"
            caption="Applied local inventory changes"
          />
          <.provenance
            id="import-receipt-provenance"
            source={@receipt_context.source}
            generated_at={@receipt_context.generated_at}
            digest={@receipt_context.digest}
          />
          <p class="supporting">
            This result is shown for this session. Reloading does not apply the snapshot again.
          </p>
          <div>
            <.link navigate="/findings" class="button button-secondary">Browse local findings</.link>
          </div>
        </section>
      </section>
    </Layouts.app>
    """
  end

  attr :id, :string, required: true
  attr :source, :any, default: nil
  attr :generated_at, :any, default: nil
  attr :digest, :string, required: true

  defp provenance(assigns) do
    ~H"""
    <details id={@id} class="disclosure">
      <summary>Snapshot provenance</summary>
      <dl class="evidence-grid">
        <div class="key-value">
          <dt>File-provided source</dt><dd>{@source || "Not reported"}</dd>
        </div>
        <div class="key-value">
          <dt>File-provided generation time</dt>
          <dd>
            <.timestamp :if={@generated_at} value={@generated_at} /><span :if={is_nil(@generated_at)}>Not reported</span>
          </dd>
        </div>
      </dl>
      <p class="supporting">
        File metadata is not verified historical provenance or authoritative source ordering.
      </p>
      <.technical_value id={"#{@id}-digest"} label="Normalized snapshot fingerprint" value={@digest} />
    </details>
    """
  end

  attr :summary, :map, required: true
  attr :id, :string, required: true
  attr :caption, :string, required: true

  defp summary(assigns) do
    ~H"""
    <div class="table-region" role="region" tabindex="0" aria-label={@caption}>
      <table id={@id} class="data-table">
        <caption>{@caption}</caption>
        <thead>
          <tr>
            <th scope="col">Record type</th><th scope="col">Create</th><th scope="col">Update</th><th scope="col">
              Unchanged
            </th><th scope="col">Existing</th>
          </tr>
        </thead>
        <tbody>
          <tr
            :for={
              {key, label} <- [
                images: "Images",
                placements: "Placements",
                findings: "Findings",
                events: "Events"
              ]
            }
            id={"#{@id}-#{key}"}
          >
            <th scope="row">{label}</th><td>{@summary[key].create}</td><td>{@summary[key].update}</td><td>
              {@summary[key].unchanged}
            </td><td>{@summary[key].existing}</td>
          </tr>
        </tbody>
      </table>
    </div>
    """
  end
end
