defmodule Triage.CveCatalog do
  @moduledoc """
  Explicit download of a bounded public NVD reference catalogue.

  These are real advisory records, NOT scanner evidence of local deployment.
  Severity is taken from a disclosed CVSS v3 metric, never invented to meet a
  quota. A missing bucket fails the entire fetch; no partial replacement occurs.
  Call only from an explicit download task, not application startup or a page GET.
  """
  alias Triage.Intel.Sanitize

  @endpoint "https://services.nvd.nist.gov/rest/json/cves/2.0"
  @counts [{"CRITICAL", 30}, {"HIGH", 40}, {"MEDIUM", 20}, {"LOW", 5}]
  @max_body 8_000_000

  def counts, do: Map.new(@counts)

  @doc "Fetch all four buckets; injected request/pause functions support offline tests."
  def fetch(opts \\ []) do
    request = Keyword.get(opts, :request, &request/1)
    pause = Keyword.get(opts, :pause, &:timer.sleep/1)
    fetched_at = DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601()

    Enum.reduce_while(@counts, {:ok, [], []}, fn {severity, count}, {:ok, rows, sources} ->
      if sources != [], do: pause.(6_000)
      url = bucket_url(severity)

      with {:ok, %{status: 200, body: body}} when is_binary(body) <- request.(url),
           true <- byte_size(body) <= @max_body,
           {:ok, %{"vulnerabilities" => entries}} when is_list(entries) <- Jason.decode(body),
           {:ok, selected} <- select(entries, severity, count) do
        receipt = %{
          "url" => url,
          "fetched_at" => fetched_at,
          "sha256" => Base.encode16(:crypto.hash(:sha256, body), case: :lower),
          "body" => body
        }

        {:cont, {:ok, rows ++ selected, sources ++ [receipt]}}
      else
        _ -> {:halt, {:error, {:bucket_unavailable, severity}}}
      end
    end)
    |> case do
      {:ok, rows, sources} ->
        if length(Enum.uniq_by(rows, & &1["cve"])) == 95 do
          {:ok,
           %{
             "format" => "triage.nvd-reference",
             "version" => 1,
             "fetched_at" => fetched_at,
             "counts" => counts(),
             "selection" => "CVSS v3; NVD publication window 2025-01-01 through 2025-03-31",
             "advisories" => rows,
             "sources" => sources
           }}
        else
          {:error, :duplicate_cves}
        end

      error ->
        error
    end
  end

  def bucket_url(severity) when severity in ~w(CRITICAL HIGH MEDIUM LOW) do
    @endpoint <>
      "?" <>
      URI.encode_query(%{
        "cvssV3Severity" => severity,
        "resultsPerPage" => 200,
        "noRejected" => "",
        "pubStartDate" => "2025-01-01T00:00:00.000",
        "pubEndDate" => "2025-03-31T23:59:59.999"
      })
  end

  @doc "Select only valid records whose chosen public metric actually matches the bucket."
  def select(entries, severity, count) when is_list(entries) do
    selected =
      entries
      |> Enum.map(&normalize/1)
      |> Enum.filter(&(is_map(&1) and &1["severity"] == severity))
      |> Enum.uniq_by(& &1["cve"])
      |> Enum.sort_by(& &1["cve"])
      |> Enum.take(count)

    if length(selected) == count, do: {:ok, selected}, else: {:error, :insufficient_records}
  end

  def select(_entries, _severity, _count), do: {:error, :invalid_entries}

  def normalize(%{"cve" => cve}) when is_map(cve) do
    with true <- Sanitize.valid_cve_id?(cve["id"]),
         false <- cve["vulnStatus"] == "Rejected",
         %{"value" => description} when is_binary(description) <- english(cve),
         true <- String.valid?(description) and String.trim(description) != "",
         %{"cvssData" => metric} = scored when is_map(metric) <- score(cve),
         severity when severity in ~w(CRITICAL HIGH MEDIUM LOW) <- metric["baseSeverity"],
         number when is_number(number) <- metric["baseScore"],
         true <- score_matches?(number, severity),
         version when version in ["3.0", "3.1"] <- metric["version"],
         vector when is_binary(vector) <- metric["vectorString"],
         source when is_binary(source) <- scored["source"],
         published when is_binary(published) <- cve["published"],
         modified when is_binary(modified) <- cve["lastModified"] do
      %{
        "cve" => cve["id"],
        "description" => description,
        "severity" => severity,
        "cvss_score" => number,
        "cvss_version" => version,
        "cvss_vector" => vector,
        "metric_source" => source,
        "published_at" => published,
        "last_modified_at" => modified,
        "url" => "https://nvd.nist.gov/vuln/detail/" <> cve["id"],
        "references" => references(cve),
        "affected_products" => products(cve)
      }
    else
      _ -> nil
    end
  end

  def normalize(_), do: nil

  defp english(cve) do
    case cve["descriptions"] do
      rows when is_list(rows) -> Enum.find(rows, &(is_map(&1) and &1["lang"] == "en"))
      _ -> nil
    end
  end

  defp score(cve) do
    case cve["metrics"] do
      metrics when is_map(metrics) ->
        ["cvssMetricV31", "cvssMetricV30"]
        |> Enum.flat_map(fn key -> if is_list(metrics[key]), do: metrics[key], else: [] end)
        |> Enum.filter(&is_map/1)
        |> Enum.sort_by(fn row ->
          cond do
            row["source"] == "nvd@nist.gov" -> 0
            row["type"] == "Primary" -> 1
            true -> 2
          end
        end)
        |> List.first()

      _ ->
        nil
    end
  end

  defp score_matches?(score, "CRITICAL"), do: score >= 9.0 and score <= 10.0
  defp score_matches?(score, "HIGH"), do: score >= 7.0 and score < 9.0
  defp score_matches?(score, "MEDIUM"), do: score >= 4.0 and score < 7.0
  defp score_matches?(score, "LOW"), do: score > 0 and score < 4.0

  defp references(cve) do
    case cve["references"] do
      rows when is_list(rows) ->
        rows
        |> Enum.filter(&(is_map(&1) and is_binary(&1["url"])))
        |> Enum.map(& &1["url"])
        |> Enum.take(20)

      _ ->
        []
    end
  end

  # Preserve original CPE criteria and bounds rather than inventing an installed
  # package/version or treating a range endpoint as a confirmed fixed version.
  defp products(cve), do: collect_matches(Map.get(cve, "configurations", [])) |> Enum.take(30)
  defp collect_matches(rows) when is_list(rows), do: Enum.flat_map(rows, &collect_matches/1)

  defp collect_matches(row) when is_map(row) do
    own =
      if row["vulnerable"] == true and is_binary(row["criteria"]),
        do: [
          Map.take(
            row,
            ~w(criteria versionStartIncluding versionStartExcluding versionEndIncluding versionEndExcluding)
          )
        ],
        else: []

    own ++
      collect_matches(Map.get(row, "nodes", [])) ++ collect_matches(Map.get(row, "cpeMatch", []))
  end

  defp collect_matches(_), do: []

  defp request(url) do
    {:ok, _} = Application.ensure_all_started(:req)

    Req.get(url,
      redirect: false,
      retry: false,
      decode_body: false,
      connect_options: [timeout: 20_000],
      receive_timeout: 30_000
    )
  end
end
