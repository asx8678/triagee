defmodule Triage.Intel.Client do
  @moduledoc """
  Safe public-intelligence HTTP adapters.

  Every adapter is:
    * HTTPS to an allowlisted host only, credentials never forwarded;
    * redirect-following disabled (3xx is terminal, `Location` never read);
    * bounded: response bytes and total deadline enforced before decode;
    * sanitized: all text reduced to safe plain text before it reaches the db.

  `run/2` takes a transport function `%{req: req_fun}` where `req_fun.(url)
  -> {:ok, %{status, body}} | {:error, reason}`. Default transport is Req with
  safety options; tests inject loopback fakes.
  """

  alias Triage.Intel.Sanitize

  @max_response_bytes 2_000_000
  @deadline_ms 20_000

  @kev_url "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  @nvd_url "https://services.nvd.nist.gov/rest/json/cves/2.0"

  def kev_url, do: @kev_url
  def nvd_url, do: @nvd_url

  @doc """
  Fetch + normalize a source. `kind` selects the parser; allowlisted hosts only.
  Returns `{:ok, rows}` (normalized plain maps) — errors are terminal and
  never silently partial. Text fields are already sanitized.
  """
  def fetch(kind, transport \\ default_transport())

  def fetch(:kev, transport) do
    with {:ok, body} <- get(@kev_url, transport) do
      parse_kev(body)
    end
  end

  def fetch({:nvd, cve_id}, transport) do
    with :ok <- nvd_safe_cve(cve_id),
         {:ok, body} <- get(@nvd_url <> "?cveId=" <> URI.encode(cve_id), transport) do
      parse_nvd(body, cve_id)
    end
  end

  def fetch(other, _transport), do: {:error, {:unknown_source, sanitize_error(other)}}

  ## Transport

  defp default_transport do
    if Triage.Intel.Config.enabled?() do
      %{req: &req_get/1}
    else
      %{req: fn _url -> {:error, :intel_disabled} end}
    end
  end

  defp req_get(url) do
    case URI.parse(url) do
      %URI{scheme: "https", host: host} when host in ["www.cisa.gov", "services.nvd.nist.gov"] ->
        Req.get(url,
          max_redirects: 0,
          retry: false,
          connect_options: [timeout: @deadline_ms],
          receive_timeout: @deadline_ms,
          decode_body: false
        )
        |> case do
          {:ok, %{status: 200, body: body}} ->
            if_byte_size_ok(body)

          {:ok, %{status: status}} when status in 300..399 ->
            # Terminal: never follow Location, never leak it.
            {:error, {:redirect_refused, status}}

          {:ok, %{status: status}} ->
            {:error, {:http_status, status}}

          {:error, reason} ->
            {:error, {:request_failed, sanitize_error(reason)}}
        end

      _ ->
        {:error, {:unallowlisted_url, host_of(url)}}
    end
  rescue
    _ -> {:error, :request_raised}
  catch
    :exit, _ -> {:error, :request_raised}
  end

  defp if_byte_size_ok(body) when is_binary(body) do
    if byte_size(body) <= @max_response_bytes,
      do: {:ok, body},
      else: {:error, {:response_too_large, @max_response_bytes}}
  end

  defp if_byte_size_ok(_other), do: {:error, {:unexpected_body, :other}}

  ## Parsers — all produce sanitized plain maps

  defp parse_kev(body) do
    with {:ok, json} <- decode(body),
         %{} = json,
         vulns when is_list(vulns) <- Map.get(json, "vulnerabilities") do
      rows =
        vulns
        |> Enum.take(50)
        |> Enum.map(fn v ->
          %{
            external_id: Sanitize.text(Map.get(v, "cveID")),
            summary: Sanitize.text(Map.get(v, "shortDescription")),
            published_at: date(Map.get(v, "dateAdded"))
          }
        end)
        |> Enum.reject(fn r -> is_nil(r.external_id) or r.external_id == "" end)

      {:ok, rows}
    else
      _ -> {:error, :kev_parse_failed}
    end
  end

  defp parse_nvd(body, cve_id) do
    with {:ok, json} <- decode(body),
         %{} = json,
         vulns when is_list(vulns) <- Map.get(json, "vulnerabilities") do
      rows =
        Enum.map(vulns, fn %{} = v ->
          cve = Map.get(v, "cve", %{})
          id = Sanitize.text(Map.get(cve, "id"))

          summary =
            cve
            |> Map.get("descriptions", [])
            |> Enum.find(fn d -> Map.get(d, "lang") == "en" end)
            |> Kernel.||(%{})
            |> Map.get("value")
            |> Sanitize.text()

          %{
            external_id: id || Sanitize.text(cve_id),
            summary: summary,
            published_at: date(Map.get(cve, "published"))
          }
        end)

      {:ok, rows}
    else
      _ -> {:error, :nvd_parse_failed}
    end
  end

  defp nvd_safe_cve(id) do
    if Sanitize.valid_cve_id?(id), do: :ok, else: {:error, {:invalid_cve_id, sanitize_error(id)}}
  end

  ## Helpers

  defp decode(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, json} when is_map(json) -> {:ok, json}
      _ -> {:error, :json_decode_failed}
    end
  end

  defp date(nil), do: nil

  defp date(str) when is_binary(str) do
    case Date.from_iso8601(String.slice(str, 0, 10)) do
      {:ok, d} ->
        DateTime.new!(d, ~T[00:00:00], "Etc/UTC")

      _ ->
        case DateTime.from_iso8601(str) do
          {:ok, dt, _} -> dt
          _ -> nil
        end
    end
  end

  defp get(url, %{req: req_fun}) when is_function(req_fun, 1), do: req_fun.(url)
  defp get(_url, _other), do: {:error, :no_transport}

  defp host_of(url) do
    case URI.parse(url) do
      %URI{host: h} when is_binary(h) -> h
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp sanitize_error(err) when is_binary(err),
    do: String.slice(Sanitize.text(err) || "unknown", 0, 120)

  defp sanitize_error(_), do: "non_binary_error"
end
