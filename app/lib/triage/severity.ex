defmodule Triage.Severity do
  @moduledoc "Scanner severity ordering shared by inventory, risk and presentation."

  @order ~w(CRITICAL HIGH MEDIUM LOW)
  @ranks Map.new(Enum.zip(@order, 4..1//-1))
  @labels Map.new(@ranks, fn {label, rank} -> {rank, label} end)

  @spec order() :: [String.t()]
  def order, do: @order

  # Ranking deliberately does not normalize legacy display values.
  @spec rank(term()) :: 0..4
  def rank(value), do: Map.get(@ranks, value, 0)

  @spec label(term()) :: String.t()
  def label(rank), do: Map.get(@labels, rank, "UNKNOWN")

  @spec normalize(String.t() | nil) :: String.t() | nil
  def normalize(nil), do: nil

  def normalize(value) when is_binary(value) do
    normalized = value |> String.trim() |> String.upcase()
    if normalized in @order, do: normalized
  end

  # Only server-owned literals are interpolated; the finding value stays a
  # fragment parameter. SQL and Elixir cannot acquire different rank tables.
  @spec sql_max_rank() :: String.t()
  def sql_max_rank do
    clauses = Enum.map_join(@order, " ", fn label -> "when '#{label}' then #{rank(label)}" end)
    "max(case ? " <> clauses <> " else 0 end)"
  end
end
