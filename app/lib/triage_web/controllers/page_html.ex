defmodule TriageWeb.PageHTML do
  @moduledoc """
  This module contains pages rendered by PageController.

  See the `page_html` directory for all templates available.
  """
  use TriageWeb, :html

  embed_templates "page_html/*"

  # Rows the overview shows per bounded rail, mirroring PageController.
  @rail_slice 5

  @doc """
  Caption for a bounded overview rail, given the unpaged total.

  The controller reads a capped slice plus the real total, so a rail that shows
  only part of the inventory says so. When the total could not be read the rail
  says exactly that instead of printing the size of the slice it happened to
  load as if it were the whole inventory.
  """
  def rail_caption(nil, rows) when is_list(rows) do
    "Showing #{length(rows)} loaded #{if length(rows) == 1, do: "advisory", else: "advisories"}; " <>
      "the unpaged total could not be read"
  end

  def rail_caption(total, _rows) when is_integer(total) and total > @rail_slice do
    "Showing #{@rail_slice} of #{total}"
  end

  def rail_caption(total, _rows) when is_integer(total), do: "Showing all #{total}"

  @doc """
  Total rows for a bounded overview list. When the total could not be read, fall
  back to the loaded rows rather than inventing a number.
  """
  def overview_total(total, _rows) when is_integer(total), do: total
  def overview_total(_unavailable, rows) when is_list(rows), do: length(rows)
end
