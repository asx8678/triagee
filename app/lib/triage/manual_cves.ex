defmodule Triage.ManualCves do
  @moduledoc "Manually requested NVD lookups and a persistent research list."
  import Ecto.Query
  alias Triage.Intel.{Advisory, Client, Sanitize}
  alias Triage.Repo

  @source "manual:nvd"

  def list do
    Repo.all(
      from a in Advisory,
        where: a.source == @source,
        order_by: [desc: a.fetched_at, asc: a.external_id]
    )
  end

  def fetch(input, transport \\ nil) do
    cve = if is_binary(input), do: input |> String.trim() |> String.upcase(), else: ""

    if byte_size(cve) <= 40 and Sanitize.valid_cve_id?(cve) do
      transport =
        transport || Application.get_env(:triage, :manual_cve_transport) || %{req: &request/1}

      fetch_record(cve, transport)
    else
      {:error, "Enter a CVE ID such as CVE-2024-3094."}
    end
  end

  defp fetch_record(cve, transport) do
    case Client.fetch({:nvd, cve}, transport) do
      {:ok, [%{summary: summary} = row]} when is_binary(summary) and summary != "" ->
        {:ok, row}

      {:ok, []} ->
        {:error, "NVD has no published record for this CVE yet."}

      {:ok, _} ->
        {:error, "NVD has no English description for this CVE yet."}

      {:error, {:http_status, 429}} ->
        {:error, "NVD is rate limiting requests. Please try again shortly."}

      {:error, _} ->
        {:error, "Could not fetch this CVE from NVD. Please try again."}
    end
  end

  def save(%{external_id: cve, summary: summary} = row) do
    if Sanitize.valid_cve_id?(cve) and is_binary(summary) and summary != "" do
      %Advisory{}
      |> Advisory.changeset(
        Map.merge(row, %{
          source: @source,
          fetched_at: DateTime.utc_now() |> DateTime.truncate(:second)
        })
      )
      # Identity for legacy (generation-less) advisory rows is enforced by the
      # partial unique index; a target-less DO NOTHING stays valid after the
      # generation migration replaced the old full unique index.
      |> Repo.insert(on_conflict: :nothing)
    else
      {:error, :invalid_advisory}
    end
  end

  defp request(url) do
    Req.get(url, Triage.HTTP.options(timeout: 20_000, max_bytes: 2_000_000))
  end
end
