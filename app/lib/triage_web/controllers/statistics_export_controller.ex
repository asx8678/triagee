defmodule TriageWeb.StatisticsExportController do
  @moduledoc """
  CSV download of the Statistics page: one row per CVE and deployment for the
  chosen team, environment and period (CVEs open now or handled in it).

  Built to open cleanly in Excel: UTF-8 with a byte-order mark, CRLF line ends,
  comma separators with RFC 4180 quoting, ISO dates (YYYY-MM-DD, UTC) and
  whole-number days. A cell Excel would treat as a formula is written as text.
  """
  use TriageWeb, :controller

  alias Triage.Statistics
  alias TriageWeb.WorkspaceComponents

  @header [
    "CVE",
    "Severity",
    "Packages",
    "Team",
    "Environment",
    "Namespace",
    "Image",
    "First observed",
    "First action",
    "First action date",
    "First action by",
    "Days to first action",
    "No longer observed",
    "Days until no longer observed",
    "Handled",
    "How it was handled",
    "Current state",
    "Whitelisted until",
    "Days open",
    "Ticket",
    "Reason"
  ]

  def csv(conn, params) do
    case filters(params) do
      {:ok, filters, period} ->
        now = DateTime.utc_now()
        rows = Statistics.export_rows(filters, period, now)

        conn
        |> put_resp_header("cache-control", "no-store")
        |> send_download({:binary, encode(rows)},
          filename: "triage-statistics-#{Date.to_iso8601(DateTime.to_date(now))}.csv",
          content_type: "text/csv",
          charset: "utf-8"
        )

      :error ->
        conn |> put_status(:bad_request) |> text("Invalid statistics filters.")
    end
  end

  defp filters(params) do
    filters = Map.take(params, ~w(team environment))
    period = Map.get(params, "period", "90d")

    if Enum.all?(filters, fn {_key, value} -> is_binary(value) and byte_size(value) <= 200 end) and
         is_binary(period) and Map.has_key?(Statistics.periods(), period),
       do: {:ok, Map.reject(filters, fn {_key, value} -> value == "" end), period},
       else: :error
  end

  # In @header order.
  defp fields(row) do
    action = row.first_action || %{}

    [
      row.cve,
      row.severity,
      Enum.join(row.packages, "; "),
      WorkspaceComponents.team_name(row.team),
      row.environment,
      row.namespace,
      row.image,
      iso(row.observed_at),
      action[:label],
      iso(action[:at]),
      action[:by],
      row.days_to_first_action,
      iso(row.gone_at),
      row.days_until_gone,
      iso(row.handled_at),
      row.outcome,
      row.current_state,
      iso(row.whitelisted_until),
      row.days_open,
      action[:ticket_url],
      action[:reason]
    ]
  end

  defp encode(rows) do
    lines = [@header | Enum.map(rows, &fields/1)]
    IO.iodata_to_binary(["﻿", Enum.map(lines, &[line(&1), "\r\n"])])
  end

  defp line(fields), do: Enum.map_intersperse(fields, ",", &field/1)

  defp field(nil), do: ""
  defp field(value) when is_integer(value), do: Integer.to_string(value)

  defp field(value) when is_binary(value) do
    value = as_text(value)

    if String.contains?(value, [",", "\"", "\r", "\n"]),
      do: ["\"", String.replace(value, "\"", "\"\""), "\""],
      else: value
  end

  # Excel runs a cell starting with = + - @ as a formula; reasons are free text.
  defp as_text(<<first, _rest::binary>> = value) when first in [?=, ?+, ?-, ?@, ?\t, ?\r],
    do: "'" <> value

  defp as_text(value), do: value

  defp iso(nil), do: nil
  defp iso(value), do: Calendar.strftime(value, "%Y-%m-%d")
end
