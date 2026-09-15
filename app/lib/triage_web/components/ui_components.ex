defmodule TriageWeb.UIComponents do
  @moduledoc "Shared, semantic presentation primitives. No evidence or workflow state is inferred here."
  use Phoenix.Component

  @doc "Keep a validated URL scope selected even when it is absent from available inventory options."
  def display_scope_options(values, selected, all_label) do
    options = [{all_label, ""} | Enum.map(values, &{&1, &1})]

    if is_binary(selected) and selected != "" and selected not in values do
      options ++ [{selected <> " (not in available scopes)", selected}]
    else
      options
    end
  end

  attr :title, :string, required: true
  attr :subtitle, :string, default: nil
  attr :eyebrow, :string, default: nil
  attr :id, :string, default: nil
  slot :actions

  def page_header(assigns) do
    ~H"""
    <header class="page-header">
      <div>
        <p :if={@eyebrow} class="eyebrow">{@eyebrow}</p>
        <h1 id={@id}>{@title}</h1>
        <p :if={@subtitle} class="supporting">{@subtitle}</p>
      </div>
      <div :if={@actions != []} class="page-actions">{render_slot(@actions)}</div>
    </header>
    """
  end

  attr :label, :string, required: true
  attr :kind, :any, default: :neutral

  def status_badge(assigns) do
    kind = to_string(assigns.kind)
    kind = if kind == "severity", do: String.downcase(assigns.label), else: kind
    kind = if kind in ~w(critical high medium low warning), do: kind, else: "neutral"
    assigns = assign(assigns, :badge_kind, kind)

    ~H"""
    <span class={["status-badge", "status-badge-#{@badge_kind}"]}>{@label}</span>
    """
  end

  @doc """
  The marker for an advisory the cached KEV feed lists as exploited.

  Rendered only when the cache holds a row: a missing row and an empty cache both render
  nothing, so this can never be read as "not exploited". The label names the cache because
  a cached feed is the only thing the product knows — an operator refresh populates it, and
  callers disclose freshness separately.
  """
  attr :id, :string, required: true
  attr :kev, :any, default: nil

  def kev_marker(assigns) do
    ~H"""
    <span :if={@kev} id={@id} class="kev-flag">Known exploited (KEV cache)</span>
    """
  end

  @doc """
  The one-line source note for a view that renders KEV markers.

  Shown only while at least one marker is present, so its absence is not a statement
  either: no marker means nothing was claimed, never that nothing is exploited.
  """
  attr :id, :string, required: true
  attr :present?, :boolean, required: true

  def kev_note(assigns) do
    ~H"""
    <p :if={@present?} id={@id} class="supporting">
      Known exploited is read from the cached KEV feed an operator refresh populates; an
      advisory missing from it may still be exploited.
    </p>
    """
  end

  @doc """
  Copy control for one exact short value that is also displayed as a heading or a link.

  The shared `CopyValue` hook copies the value verbatim; the accessible name states what is
  copied and the feedback region is announced politely. Nothing renders when the value is
  missing, so an absent id never produces a control that copies nothing.
  """
  attr :id, :string, required: true
  attr :label, :string, required: true
  attr :value, :any, default: nil

  def copy_value(assigns) do
    assigns = assign(assigns, :text, if(is_binary(assigns.value), do: assigns.value, else: nil))

    ~H"""
    <%= if @text do %>
      <button
        id={@id}
        type="button"
        class="button button-secondary"
        phx-hook="CopyValue"
        data-copy-value={@text}
        data-copy-feedback={"#{@id}-feedback"}
        aria-label={"Copy exact #{@label}"}
      >
        Copy {@label}
      </button>
      <span
        id={"#{@id}-feedback"}
        class="supporting"
        role="status"
        aria-live="polite"
        phx-update="ignore"
      ></span>
    <% end %>
    """
  end

  attr :id, :string, required: true
  attr :label, :string, required: true
  attr :value, :any, required: true
  attr :variant, :string, default: "default", values: ~w(default compact)

  def technical_value(assigns) do
    value = if is_nil(assigns.value), do: nil, else: to_string(assigns.value)
    assigns = assign(assigns, value: value, available?: value not in [nil, ""])

    ~H"""
    <div id={@id} class={["technical-value", @variant == "compact" && "technical-value-compact"]}>
      <span class={["technical-label", @variant == "compact" && "sr-only"]}>{@label}</span>
      <%= if @available? do %>
        <details class={["disclosure", @variant == "compact" && "technical-compact"]}>
          <summary aria-label={"Show full #{@label}"}>
            <span class="technical-preview">{technical_preview(@value)}</span>
            <span class="supporting">Full value</span>
          </summary>
          <code id={"#{@id}-full"} class="technical-full">{@value}</code>
          <div class="cluster">
            <button
              id={"#{@id}-copy"}
              type="button"
              class="button button-secondary"
              phx-hook="CopyValue"
              data-copy-value={@value}
              data-copy-feedback={"#{@id}-feedback"}
              aria-label={"Copy exact #{@label}"}
            >
              Copy value
            </button>
            <span
              id={"#{@id}-feedback"}
              class="supporting"
              role="status"
              aria-live="polite"
              phx-update="ignore"
            ></span>
          </div>
        </details>
      <% else %>
        <span class="muted">Not captured</span>
      <% end %>
    </div>
    """
  end

  attr :value, :any, required: true

  def timestamp(assigns) do
    {formatted, exact} = timestamp_parts(assigns.value)
    assigns = assign(assigns, formatted: formatted, exact: exact)

    ~H"""
    <time :if={@exact} datetime={@exact} title={@exact}>{@formatted}</time>
    <span :if={is_nil(@exact)} class="muted">{@formatted}</span>
    """
  end

  attr :kind, :any, default: :info
  attr :title, :string, default: nil
  attr :id, :string, default: nil
  attr :rest, :global
  slot :inner_block, required: true

  def notice(assigns) do
    kind = to_string(assigns.kind)
    assigns = assign(assigns, :notice_kind, if(kind in ~w(error warning), do: kind, else: "info"))

    ~H"""
    <div
      id={@id}
      class={["notice", "notice-#{@notice_kind}"]}
      role={if @notice_kind == "error", do: "alert", else: "status"}
      {@rest}
    >
      <strong :if={@title}>{@title}</strong>
      <div>{render_slot(@inner_block)}</div>
    </div>
    """
  end

  attr :title, :string, required: true
  attr :description, :string, default: nil
  attr :id, :string, default: nil
  slot :actions

  def empty_state(assigns) do
    ~H"""
    <section id={@id} class="empty-state">
      <h2>{@title}</h2>
      <p :if={@description} class="supporting">{@description}</p>
      <div :if={@actions != []} class="page-actions">{render_slot(@actions)}</div>
    </section>
    """
  end

  @doc "A missing display value is not a security conclusion."
  def display_value(value, missing \\ "Not reported")
  def display_value(nil, missing), do: missing
  def display_value("", missing), do: missing
  def display_value(value, _missing), do: to_string(value)

  @doc "Maps a queue row's existing review data to a plain assessment-state label."
  def assessment_state(%{latest_review: nil}), do: "No assessment recorded"
  def assessment_state(%{latest_review: _review}), do: "Assessment recorded"
  def assessment_state(_row), do: "No assessment recorded"

  @doc """
  Server-computed relative time for an exact timestamp, for example "5 weeks ago".

  Returns `nil` when the value is missing or unparseable so callers omit the
  relative phrase rather than inventing freshness. `now` is injectable for
  deterministic tests; production callers use the default UTC clock.
  """
  def relative_time(value, now \\ DateTime.utc_now()) do
    case normalize_datetime(value) do
      {:ok, datetime} -> relative_label(DateTime.diff(now, datetime, :second))
      :error -> nil
    end
  end

  defp normalize_datetime(%DateTime{} = value), do: {:ok, value}

  defp normalize_datetime(%NaiveDateTime{} = value),
    do: {:ok, DateTime.from_naive!(value, "Etc/UTC")}

  defp normalize_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, parsed, _offset} -> {:ok, parsed}
      _ -> :error
    end
  end

  defp normalize_datetime(_value), do: :error

  defp relative_label(seconds) when seconds < 0, do: "in " <> relative_phrase(abs(seconds))
  defp relative_label(seconds) when seconds < 60, do: "just now"
  defp relative_label(seconds), do: relative_phrase(seconds) <> " ago"

  defp relative_phrase(seconds) when seconds < 3_600, do: relative_unit(seconds, 60, "minute")
  defp relative_phrase(seconds) when seconds < 86_400, do: relative_unit(seconds, 3_600, "hour")

  defp relative_phrase(seconds) when seconds < 604_800,
    do: relative_unit(seconds, 86_400, "day")

  defp relative_phrase(seconds) when seconds < 4_838_400,
    do: relative_unit(seconds, 604_800, "week")

  defp relative_phrase(seconds) when seconds < 31_536_000,
    do: relative_unit(seconds, 2_592_000, "month")

  defp relative_phrase(seconds), do: relative_unit(seconds, 31_536_000, "year")

  defp relative_unit(seconds, unit_seconds, name) do
    count = max(round(seconds / unit_seconds), 1)
    suffix = if count == 1, do: name, else: name <> "s"
    "#{count} #{suffix}"
  end

  defp technical_preview(value) do
    if String.length(value) > 64,
      do: String.slice(value, 0, 44) <> "…" <> String.slice(value, -16, 16),
      else: value
  end

  defp timestamp_parts(nil), do: {"Not captured", nil}
  defp timestamp_parts(""), do: {"Not captured", nil}

  defp timestamp_parts(%DateTime{} = value) do
    utc = DateTime.shift_zone!(value, "Etc/UTC")
    {Calendar.strftime(utc, "%d %b %Y, %H:%M UTC"), DateTime.to_iso8601(value)}
  end

  # All naive database timestamps in this application are captured in UTC.
  defp timestamp_parts(%NaiveDateTime{} = value) do
    timestamp_parts(DateTime.from_naive!(value, "Etc/UTC"))
  end

  defp timestamp_parts(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, parsed, _offset} ->
        {formatted, _exact} = timestamp_parts(parsed)
        {formatted, value}

      _ ->
        {"Unavailable (original: #{value})", nil}
    end
  end

  defp timestamp_parts(_value), do: {"Unavailable", nil}
end
