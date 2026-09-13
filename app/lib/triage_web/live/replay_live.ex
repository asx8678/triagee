defmodule TriageWeb.ReplayLive do
  use TriageWeb, :live_view

  alias Triage.Replay
  alias Triage.Replay.Runs

  @max_bytes 1_000_000
  @counts [
    {"owners", "Owners"},
    {"images", "Images"},
    {"findings", "Findings"},
    {"suppressed", "Suppressed findings"},
    {"actionable", "Would be actionable in replay"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(page_title: "Replay", form: to_form(%{}, as: :replay))
     |> clear_result()
     |> allow_upload(:replay,
       accept: ~w(.json),
       max_entries: 1,
       max_file_size: @max_bytes,
       auto_upload: false,
       progress: &handle_progress/3
     )}
  end

  @impl true
  def handle_event("validate", params, socket) do
    socket = clear_result(socket)

    cond do
      not validation_params?(params) ->
        {:noreply, reject(socket, :invalid_input)}

      upload_errors(socket.assigns.uploads.replay) != [] ->
        {:noreply, reject(socket, :upload_invalid)}

      Enum.any?(socket.assigns.uploads.replay.entries, fn entry ->
        upload_errors(socket.assigns.uploads.replay, entry) != []
      end) ->
        {:noreply, reject(socket, :upload_invalid)}

      true ->
        {:noreply, socket}
    end
  end

  def handle_event("replay", params, socket) when params == %{} or params == %{"replay" => ""} do
    socket = clear_result(socket)
    {done, pending} = uploaded_entries(socket, :replay)

    if length(done) == 1 and pending == [] and
         upload_errors(socket.assigns.uploads.replay) == [] do
      results =
        consume_uploaded_entries(socket, :replay, fn %{path: path}, _entry ->
          {:ok, bounded_read(path)}
        end)

      case results do
        [{:ok, json}] ->
          case Replay.run(json) do
            {:ok, summary} ->
              {:noreply,
               assign(socket,
                 accepted: {Ecto.UUID.generate(), json},
                 result: safe_summary(summary),
                 error: nil
               )}

            {:error, reason} ->
              # Consumed upload processes have already stopped. Do not cancel
              # their entries again using this callback's pre-consumption socket.
              {:noreply, assign(clear_result(socket), :error, error_label(reason))}
          end

        _ ->
          {:noreply, assign(clear_result(socket), :error, error_label(:read_failed))}
      end
    else
      {:noreply, reject(socket, :upload_required)}
    end
  end

  # Native button clicks include their empty DOM value in the shipped client.
  def handle_event("save", params, socket) when params == %{} or params == %{"value" => ""} do
    case {socket.assigns.accepted, socket.assigns.receipt, socket.assigns.uploads.replay.entries} do
      {{_key, _json}, receipt, []} when not is_nil(receipt) ->
        {:noreply, socket}

      {{key, json}, nil, []} ->
        case Runs.record_result(key, json) do
          {:ok, row} ->
            {:noreply,
             assign(socket,
               receipt: row.id,
               receipt_received_at: row.received_at,
               receipt_expires_at: row.expires_at,
               error: nil
             )}

          {:error, reason} ->
            {:noreply, reject(socket, reason)}
        end

      _ ->
        {:noreply, reject(socket, :invalid_input)}
    end
  end

  def handle_event("cancel", params, socket) when params == %{} or params == %{"value" => ""},
    do: {:noreply, reject(socket, :cancelled)}

  def handle_event(_event, _params, socket),
    do: {:noreply, reject(socket, :invalid_input)}

  defp handle_progress(:replay, entry, socket) do
    socket = clear_result(socket)

    if upload_errors(socket.assigns.uploads.replay, entry) == [] do
      {:noreply, socket}
    else
      {:noreply, reject(socket, :upload_invalid)}
    end
  end

  defp validation_params?(params) when is_map(params) do
    Enum.all?(params, fn
      {"replay", ""} ->
        true

      {"_target", target} when is_list(target) ->
        length(target) <= 2 and Enum.all?(target, &(is_binary(&1) and byte_size(&1) <= 100))

      _ ->
        false
    end)
  end

  defp validation_params?(_), do: false

  defp bounded_read(path) do
    case File.open(path, [:read, :binary], fn file -> IO.binread(file, @max_bytes + 1) end) do
      {:ok, json} when is_binary(json) and byte_size(json) <= @max_bytes -> {:ok, json}
      _ -> {:error, :read_failed}
    end
  rescue
    _ -> {:error, :read_failed}
  end

  defp clear_result(socket),
    do:
      assign(socket,
        accepted: nil,
        result: nil,
        receipt: nil,
        receipt_received_at: nil,
        receipt_expires_at: nil,
        error: nil
      )

  defp reject(socket, reason) do
    socket =
      Enum.reduce(socket.assigns.uploads.replay.entries, socket, fn entry, acc ->
        cancel_upload(acc, :replay, entry.ref)
      end)

    socket |> clear_result() |> assign(:error, error_label(reason))
  end

  defp error_label(:quota_exceeded), do: "History storage quota reached. Nothing was saved."
  defp error_label(:expired), do: "This save receipt has expired. Run a new replay to save again."
  defp error_label(:idempotency_conflict), do: "The history receipt conflicts. Run a new replay."

  defp error_label(reason) when reason in [:database_unavailable, :database_error],
    do: "History storage is unavailable. Nothing was saved. Run a new replay to retry."

  defp error_label(:cancelled),
    do: "Upload cancelled. Previous results and save permission were cleared."

  defp error_label(:upload_invalid), do: "Choose one JSON file no larger than 1,000,000 bytes."
  defp error_label(:upload_required), do: "Upload one complete JSON file before replaying."

  defp error_label(:read_failed),
    do: "The uploaded file could not be read within the size limit. Choose it again."

  defp error_label(:invalid_json), do: "The file is not valid replay JSON."

  defp error_label(:invalid_document),
    do: "The document is not a supported version-1 synthetic replay."

  defp error_label(_), do: "Replay input was rejected. Choose a new supported JSON file."

  # Deliberately project values, never iterate arbitrary summary keys or source text.
  def safe_summary(summary) when is_map(summary) do
    counts = if is_map(summary["counts"]), do: summary["counts"], else: %{}
    diagnostics = if is_list(summary["diagnostics"]), do: summary["diagnostics"], else: []

    %{
      complete:
        case summary["complete"] do
          true -> "Complete synthetic evidence"
          false -> "Incomplete synthetic evidence"
          _ -> "Completeness unavailable"
        end,
      digest: safe_digest(summary["input_sha256"]),
      counts:
        Enum.map(@counts, fn {key, label} ->
          value =
            case counts[key] do
              n when is_integer(n) and n >= 0 and n <= 5000 -> Integer.to_string(n)
              _ -> "Unavailable"
            end

          {label, value}
        end),
      diagnostics:
        Enum.flat_map(
          [
            {"incomplete_evidence",
             "Incomplete evidence: one or more required records are missing or inconsistent."},
            {"normalization_warning",
             "Normalization warning: some synthetic evidence could not be normalized cleanly."}
          ],
          fn {code, label} -> if code in diagnostics, do: [label], else: [] end
        )
    }
  end

  def safe_summary(_), do: safe_summary(%{})

  def safe_digest(value) when is_binary(value) and byte_size(value) == 64 do
    if Regex.match?(~r/\A[0-9a-f]{64}\z/, value), do: value, else: "Unavailable"
  end

  def safe_digest(_), do: "Unavailable"

  attr :result, :map, required: true
  attr :id, :string, default: "replay-summary"

  def summary_panel(assigns) do
    ~H"""
    <div id={@id} class="stack">
      <div>
        <.status_badge
          label={@result.complete}
          kind={
            if @result.complete == "Incomplete synthetic evidence", do: "warning", else: "neutral"
          }
        />
      </div>
      <dl class="metric-strip">
        <div :for={{label, value} <- @result.counts} class="key-value">
          <dt>{label}</dt><dd>{value}</dd>
        </div>
      </dl>
      <p class="supporting">
        Counts describe this synthetic replay only. Suppression does not establish mitigation; no result authorizes an action.
      </p>
      <p :for={label <- @result.diagnostics} class="notice">{label}</p>
      <.technical_value
        :if={@result.digest != "Unavailable"}
        id={"#{@id}-digest"}
        label="Canonical input SHA-256"
        value={@result.digest}
      />
      <p :if={@result.digest == "Unavailable"} class="supporting">
        Canonical input SHA-256: Unavailable
      </p>
    </div>
    """
  end

  defp current_step(assigns) do
    cond do
      assigns.receipt -> 4
      assigns.result -> 3
      assigns.uploads.replay.entries != [] -> 2
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
    <Layouts.app flash={@flash} active_page="replay">
      <section id="replay-workspace" class="tool-layout stack">
        <.page_header
          title="Replay"
          eyebrow="Data tools"
          subtitle="Run a synthetic file in memory, then choose whether to save its summary."
        >
          <:actions>
            <.link navigate="/replay/history" class="button button-secondary">Replay history</.link>
          </:actions>
        </.page_header>
        <p id="replay-safety" class="supporting">
          Synthetic, not live data; non-actionable. Inventory is unchanged. No external source calls are made. Uploads send your selected file only to this application.
        </p>
        <ol id="replay-steps" class="step-list" aria-label="Replay steps">
          <li
            :for={
              {step, label} <- [
                {1, "Select file"},
                {2, "Run replay"},
                {3, "Review result"},
                {4, "Save summary (optional)"}
              ]
            }
            id={"replay-step-#{step}"}
            class={["step-item", "step-#{step_state(@current_step, step)}"]}
            data-step-state={step_state(@current_step, step)}
            aria-current={if @current_step == step, do: "step"}
          >
            <span :if={step < @current_step} class="step-marker" aria-hidden="true">✓&nbsp;</span>
            <span>{label}</span>
          </li>
        </ol>
        <.form for={@form} id="replay-form" phx-change="validate" phx-submit="replay" class="stack">
          <h2 class="section-header">1. Select a replay file</h2>
          <div class="triage-upload">
            <label for={@uploads.replay.ref}>Replay JSON</label>
            <.live_file_input
              upload={@uploads.replay}
              class="file-input"
              aria-describedby="replay-file-help"
            />
            <p id="replay-file-help" class="supporting">
              One version-1 synthetic replay JSON file, maximum 1,000,000 bytes.
            </p>
            <a id="replay-example" href="/assets/examples/replay.json" download>Download complete synthetic example</a>
          </div>
          <div
            :for={entry <- @uploads.replay.entries}
            id={"replay-upload-#{entry.ref}"}
            class="cluster"
          >
            <label for={"replay-progress-#{entry.ref}"}>Selected JSON upload: {entry.progress}% transferred</label>
            <progress id={"replay-progress-#{entry.ref}"} value={entry.progress} max="100">{entry.progress}%</progress>
            <p :for={_error <- upload_errors(@uploads.replay, entry)} role="alert" class="notice">
              Upload rejected. Choose one JSON file within the size limit.
            </p>
          </div>
          <p :for={_error <- upload_errors(@uploads.replay)} role="alert" class="notice">
            Upload rejected. Choose one JSON file within the size limit.
          </p>
          <section class="stack" aria-labelledby="replay-run-heading">
            <h2 id="replay-run-heading" class="section-header">2. Run in memory</h2>
            <p class="supporting">
              Selecting a file does not run it. Running does not save to history or change inventory.
            </p>
            <div class="cluster">
              <button id="replay-run" type="submit" class="button" phx-disable-with="Replaying…">Run synthetic replay</button>
              <button
                id="replay-cancel"
                type="button"
                phx-click="cancel"
                class="button button-secondary"
              >Clear upload and result</button>
            </div>
          </section>
        </.form>
        <.notice
          :if={@error}
          id="replay-error"
          role="alert"
          kind="error"
          tabindex="-1"
          phx-mounted={JS.focus()}
        >
          {@error}
        </.notice>
        <section
          :if={@result}
          id="replay-result"
          class="stack"
          aria-labelledby="replay-result-heading"
        >
          <div role="status">
            <h2
              id="replay-result-heading"
              class="section-header"
              tabindex="-1"
              phx-mounted={JS.focus()}
            >
              3. Review the synthetic result
            </h2>
            <p :if={is_nil(@receipt)}>Replay finished in memory. Summary not saved.</p>
          </div>
          <.summary_panel result={@result} />
          <p class="supporting">
            No historical provenance is asserted. This result cannot authorize inventory changes.
          </p>
          <section id="replay-save-step" class="stack" aria-labelledby="replay-save-heading">
            <h2 id="replay-save-heading" class="section-header">4. Save a summary (optional)</h2>
            <p :if={is_nil(@receipt)} id="replay-save-help" class="supporting">
              Only the summary is saved locally, not the input document. Reloading or choosing another file discards this unsaved result.
            </p>
            <div :if={is_nil(@receipt)}>
              <button
                id="replay-save"
                type="button"
                phx-click="save"
                class="button"
                aria-describedby="replay-save-help"
                phx-disable-with="Saving…"
              >Save summary to local history</button>
            </div>
            <div
              :if={@receipt}
              id="replay-saved"
              role="status"
              class="stack"
              tabindex="-1"
              phx-mounted={JS.focus()}
            >
              <p>Summary saved as receipt {@receipt}. Repeated saves reuse this receipt.</p>
              <dl class="evidence-grid">
                <div class="key-value">
                  <dt>Saved locally</dt><dd><.timestamp value={@receipt_received_at} /></dd>
                </div>
                <div class="key-value">
                  <dt>Receipt expires</dt><dd><.timestamp value={@receipt_expires_at} /></dd>
                </div>
              </dl>
              <p class="supporting">These are local storage times, not source history.</p>
            </div>
            <div :if={@receipt}>
              <.link
                id="replay-history-link"
                navigate="/replay/history"
                class="button button-secondary"
              >Browse replay history</.link>
            </div>
          </section>
        </section>
      </section>
    </Layouts.app>
    """
  end
end
