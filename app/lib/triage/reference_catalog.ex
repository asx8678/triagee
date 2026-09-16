defmodule Triage.ReferenceCatalog do
  @moduledoc """
  Offline, all-or-nothing validation of downloaded NVD reference data.
  Every normalized row is re-derived from its hash-checked raw NVD receipt.
  Hashes establish local integrity/provenance, not an NVD digital signature.
  """
  alias Triage.CveCatalog
  @max_bytes 40_000_000

  def path, do: Application.app_dir(:triage, "priv/reference/nvd-cves.json")

  def read(path \\ path()) do
    with {:ok, file} <- File.open(path, [:read, :binary]) do
      try do
        case IO.binread(file, @max_bytes + 1) do
          body when is_binary(body) and byte_size(body) <= @max_bytes ->
            with {:ok, catalog} <- Jason.decode(body), do: validate(catalog)

          _ ->
            {:error, :catalog_too_large_or_unreadable}
        end
      after
        File.close(file)
      end
    end
  end

  def validate(
        %{
          "format" => "triage.nvd-reference",
          "version" => 1,
          "fetched_at" => fetched,
          "counts" => counts,
          "advisories" => rows,
          "sources" => sources
        } = catalog
      )
      when is_list(rows) and is_list(sources) and is_binary(fetched) do
    with true <- counts == CveCatalog.counts() and length(rows) == 95 and length(sources) == 4,
         {:ok, _, 0} <- DateTime.from_iso8601(fetched),
         true <- Enum.all?(rows, &is_map/1),
         true <- length(Enum.uniq_by(rows, & &1["cve"])) == 95,
         true <- Enum.frequencies_by(rows, & &1["severity"]) == counts,
         {:ok, derived} <- derive(sources, fetched),
         true <- Enum.sort_by(rows, & &1["cve"]) == Enum.sort_by(derived, & &1["cve"]) do
      {:ok, catalog}
    else
      _ -> {:error, :invalid_catalog}
    end
  end

  def validate(_), do: {:error, :invalid_catalog}

  def write(path, catalog) do
    with {:ok, _} <- validate(catalog) do
      temp = path <> "." <> Ecto.UUID.generate() <> ".tmp"

      try do
        with :ok <- File.mkdir_p(Path.dirname(path)),
             :ok <- File.write(temp, Jason.encode!(catalog, pretty: true) <> "\n", [:exclusive]),
             do: File.rename(temp, path)
      after
        File.rm(temp)
      end
    end
  end

  defp derive(sources, fetched) do
    Enum.reduce_while(CveCatalog.counts(), {:ok, []}, fn {severity, count}, {:ok, rows} ->
      matches =
        Enum.filter(sources, &(is_map(&1) and &1["url"] == CveCatalog.bucket_url(severity)))

      case matches do
        [source] ->
          case derive_source(source, severity, count, fetched) do
            {:ok, selected} -> {:cont, {:ok, rows ++ selected}}
            _ -> {:halt, {:error, :invalid_receipt}}
          end

        _ ->
          {:halt, {:error, :invalid_receipt}}
      end
    end)
  end

  defp derive_source(
         %{"body" => body, "sha256" => hash, "fetched_at" => fetched},
         severity,
         count,
         fetched
       )
       when is_binary(body) and byte_size(body) <= 8_000_000 do
    with true <- Base.encode16(:crypto.hash(:sha256, body), case: :lower) == hash,
         {:ok, %{"vulnerabilities" => entries}} when is_list(entries) <- Jason.decode(body),
         {:ok, rows} <- CveCatalog.select(entries, severity, count),
         true <- Enum.all?(rows, &valid_row?/1) do
      {:ok, rows}
    else
      _ -> {:error, :invalid_receipt}
    end
  end

  defp derive_source(_, _, _, _), do: {:error, :invalid_receipt}

  defp valid_row?(row) do
    safe_text?(row["description"], 20_000) and safe_text?(row["metric_source"], 300) and
      safe_text?(row["cvss_vector"], 200) and
      String.starts_with?(row["cvss_vector"], "CVSS:" <> row["cvss_version"] <> "/") and
      timestamp?(row["published_at"]) and timestamp?(row["last_modified_at"])
  end

  defp safe_text?(text, max) when is_binary(text),
    do:
      String.valid?(text) and String.trim(text) != "" and String.length(text) <= max and
        not Regex.match?(~r/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/, text)

  defp safe_text?(_, _), do: false

  defp timestamp?(text) when is_binary(text) do
    match?({:ok, _}, NaiveDateTime.from_iso8601(text)) or
      match?({:ok, _, _}, DateTime.from_iso8601(text))
  end

  defp timestamp?(_), do: false
end
