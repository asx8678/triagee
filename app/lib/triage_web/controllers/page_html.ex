defmodule TriageWeb.PageHTML do
  @moduledoc """
  This module contains pages rendered by PageController.

  See the `page_html` directory for all templates available.
  """
  use TriageWeb, :html

  embed_templates "page_html/*"

  # Rows the overview shows per bounded table, mirroring PageController.
  @overview_slice 10

  @doc """
  Total rows for a bounded overview list. The controller reads a capped slice
  plus the real unpaged total, so a table that shows only part of the inventory
  never claims to show all of it. When the total could not be read, fall back to
  the loaded rows rather than inventing a number.
  """
  def overview_total(total, _rows) when is_integer(total), do: total
  def overview_total(_unavailable, rows) when is_list(rows), do: length(rows)

  @doc "Caption for the overview critical table, given the real total."
  def critical_caption(total) when total > @overview_slice do
    "Top #{@overview_slice} of #{total} critical CVEs, most affected images first"
  end

  def critical_caption(total) do
    "All #{total} open critical #{if total == 1, do: "CVE", else: "CVEs"}"
  end
end
