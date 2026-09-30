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

  attr :label, :string, required: true
  attr :kind, :any, default: :neutral

  def status_badge(assigns) do
    kind = to_string(assigns.kind)
    kind = if kind == "severity", do: String.downcase(assigns.label), else: kind
    kind = if kind in ~w(critical high medium low warning state), do: kind, else: "neutral"
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
  One line of KEV cache freshness: the cache source, its whole-cache advisory count
  and the latest operator refresh result and time.

  Rendered whether or not any badge is present: a never-refreshed cache, an empty
  successful refresh, a failed last refresh and a view whose advisories have no cached
  row all show the source state explicitly. A nil status means the read was skipped
  (for example an invalid-input view that must not query), and that is stated rather
  than invented. The row count is always the whole source, never the rows matched by
  the current view, and a failed refresh never erases the retained cache claim.
  """
  attr :id, :string, required: true
  attr :status, :any, default: nil

  def kev_source_status(assigns) do
    ~H"""
    <p :if={is_nil(@status)} id={@id} class="supporting">
      KEV cache status was not read for this view, so no freshness is claimed here; an
      advisory without a badge may still be exploited.
    </p>
    <p :if={@status} id={@id} class="supporting">
      KEV cache (source "{@status.source}"): {@status.rows} cached {if @status.rows == 1,
        do: "advisory",
        else: "advisories"} across the whole source, not just the rows of this view.
      <%= cond do %>
        <% is_nil(@status.receipt) -> %>
          No refresh has been recorded yet, so no refresh result or time can be shown.
        <% @status.receipt.succeeded -> %>
          Last refresh succeeded
          <.timestamp value={@status.receipt.attempted_at} />{kev_receipt_items(
            @status.receipt.item_count
          )}.
        <% true -> %>
          Last refresh failed <.timestamp value={@status.receipt.attempted_at} />; the
          previously cached advisories are retained, not erased <span :if={@status.receipt.message}>({@status.receipt.message})</span>.
      <% end %>
      Badges mark only advisories with a cached KEV row; a missing badge is never a claim
      that an advisory is unexploited.
    </p>
    """
  end

  # An empty feed report is an honest outcome of a successful refresh, never "clear".
  defp kev_receipt_items(0),
    do: " and reported 0 items — an empty feed report, not a claim that nothing is exploited"

  defp kev_receipt_items(nil), do: " (item count not recorded)"
  defp kev_receipt_items(1), do: " and reported 1 feed item"
  defp kev_receipt_items(count) when is_integer(count), do: " and reported #{count} feed items"
  defp kev_receipt_items(_other), do: ""

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

  attr :id, :string, required: true
  attr :summary, :string, required: true
  attr :class, :any, default: nil
  slot :inner_block, required: true

  @doc """
  Reading definitions, one interaction away from the rows they qualify.

  The summary states the claim a reader must not miss; the body holds the
  definitions and caveats that would otherwise sit between the reader and the
  data. Collapsed content stays in the document, so assistive technology and
  in-page assertions still read it.
  """
  def explain(assigns) do
    ~H"""
    <details id={@id} class={["disclosure", @class]}>
      <summary>{@summary}</summary>
      <div class="stack supporting">{render_slot(@inner_block)}</div>
    </details>
    """
  end

  @doc "A missing display value is not a security conclusion."
  def display_value(value, missing \\ "Not reported")
  def display_value(nil, missing), do: missing
  def display_value("", missing), do: missing
  def display_value(value, _missing), do: to_string(value)

  attr :id, :string, required: true
  attr :form, :any, required: true
  attr :change, :string, default: "filter"
  attr :class, :any, default: nil
  slot :inner_block, required: true
  slot :actions
  slot :summary

  @doc """
  The frame every filter bar shares: controls, then the reset action, then the
  result summary.

  Each page keeps its own form parsing, validation and query — only the frame is
  shared, so a control never changes width or position from one page to the next.
  The summary slot renders as a direct child so the existing
  `.filter-toolbar > .filter-summary` sizing applies, and renders nothing at all
  when its own condition is false.
  """
  def filter_bar(assigns) do
    ~H"""
    <.form id={@id} for={@form} phx-change={@change} class={["filter-toolbar", @class]}>
      {render_slot(@inner_block)}
      <div :if={@actions != []} class="filter-bar-actions">{render_slot(@actions)}</div>
      {render_slot(@summary)}
    </.form>
    """
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
