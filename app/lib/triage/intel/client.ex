defmodule Triage.Intel.Client do
  @moduledoc """
  Safe public-intelligence HTTP adapters.

  Every adapter is:
    * HTTPS to an allowlisted host only, credentials never forwarded;
    * redirect-following disabled (3xx is terminal, `Location` never read);
    * response size checked before decode, with connection and receive timeouts;
    * sanitized: all text reduced to safe plain text before it reaches the db.

  `fetch/2` takes a transport function `%{req: req_fun}` where `req_fun.(url) ->
  {:ok, %{status, body}} | {:ok, body} | {:error, reason}` (the `Req.get/2` shape
  and an already-normalized body are both accepted). Default transport is Req with safety options; tests inject
  loopback fakes.
  """

  require Logger

  alias Triage.Intel.{Config, Sanitize}

  # CISA's feed grows over time. Snapshot the runtime-configured cap once per
  # fetch, for both streaming and final admission. Never truncate a feed into
  # partial success: that would turn missing entries into false reassurance.
  @deadline_ms 20_000

  @kev_url "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  @nvd_url "https://services.nvd.nist.gov/rest/json/cves/2.0"

  def kev_url, do: @kev_url
  def nvd_url, do: @nvd_url

  @doc """
  Fetch + validate a source, returning rows *and* the validation result.

  The KEV catalogue is validated as a catalogue: the feed's declared count must
  be present and equal the entries actually parsed, every entry must parse, no
  external id may repeat, and an empty catalogue is refused — an empty KEV feed
  is a truncated or misrouted response, never a complete one. Missing or
  mismatched counts fail closed as `:kev_declared_count_missing` /
  `:kev_declared_count_mismatch`.

  NVD is validated per CVE, which is a different contract: a genuinely empty
  per-CVE response is a valid "no record" answer and is never a statement that
  the CVE is not exploited. `totalResults`, when present, must still agree with
  what parsed.

  `complete?` is true only when the source's own completeness contract was
  verified; callers must not certify a generation otherwise.
  """
  @spec fetch_generation(term(), term()) :: {:ok, map()} | {:error, term()}
  def fetch_generation(kind, transport \\ :default_transport)

  def fetch_generation(:kev, transport) do
    with {:ok, body} <- get(@kev_url, :kev, transport) do
      parse_kev_generation(body)
    end
  end

  def fetch_generation({:nvd, cve_id}, transport) do
    with :ok <- nvd_safe_cve(cve_id),
         {:ok, body} <- get(@nvd_url <> "?cveId=" <> URI.encode(cve_id), :nvd, transport) do
      parse_nvd_generation(body, cve_id)
    end
  end

  def fetch_generation(other, _transport),
    do: {:error, {:unknown_source, sanitize_error(other)}}

  @doc """
  Fetch + normalize a source, returning only the validated rows.

  Thin compatibility wrapper over `fetch_generation/2` for callers that need
  rows alone; validation is identical, never weaker.
  """
  def fetch(kind, transport \\ :default_transport) do
    with {:ok, %{rows: rows}} <- fetch_generation(kind, transport), do: {:ok, rows}
  end

  ## Transport

  defp default_transport(max) do
    if Config.enabled?() do
      %{req: &req_get(&1, max)}
    else
      %{req: fn _url -> {:error, :intel_disabled} end}
    end
  end

  defp req_get(url, max) do
    case URI.parse(url) do
      %URI{scheme: "https", host: host} when host in ["www.cisa.gov", "services.nvd.nist.gov"] ->
        case Req.get(url, Triage.HTTP.options(timeout: @deadline_ms, max_bytes: max)) do
          {:error, reason} -> {:error, {:request_failed, sanitize_error(reason)}}
          result -> result
        end

      _ ->
        {:error, {:unallowlisted_url, host_of(url)}}
    end
  end

  defp if_byte_size_ok(body, max, source) do
    case Triage.HTTP.bounded_body(body, max) do
      {:ok, body} ->
        {:ok, body}

      {:error, :too_large} ->
        Logger.warning("intel response exceeds byte limit source=#{source} max_bytes=#{max}")
        {:error, {:response_too_large, max}}

      {:error, :invalid_body} ->
        {:error, {:unexpected_body, :other}}
    end
  end

  ## Parsers — all produce sanitized plain maps

  # KEV is a catalogue: validate the catalogue's own completeness claim before
  # any single row is considered. `count` is CISA's declared total, and when it is
  # absent or disagrees with what actually parsed the refresh is unverified and
  # must fail rather than replace a good generation with a partial one.
  defp parse_kev_generation(body) do
    case Jason.decode(body) do
      {:ok, %{"vulnerabilities" => entries} = decoded} when is_list(entries) ->
        rows = Enum.map(entries, &kev_row/1)
        declared = declared_count(decoded)

        cond do
          :error in rows ->
            {:error, :kev_parse_failed}

          length(Enum.uniq_by(rows, & &1.external_id)) != length(rows) ->
            {:error, :kev_parse_failed}

          is_nil(declared) ->
            {:error, :kev_declared_count_missing}

          declared != length(rows) ->
            {:error, :kev_declared_count_mismatch}

          rows == [] ->
            {:error, :kev_empty_feed}

          true ->
            {:ok, generation(rows, declared, decoded)}
        end

      _ ->
        {:error, :kev_parse_failed}
    end
  end

  # NVD is per CVE, so its contract differs: an empty result is a valid answer
  # about one record, not an empty catalogue. `totalResults`, when present, must
  # still agree with what parsed.
  defp parse_nvd_generation(body, cve_id) do
    case Jason.decode(body) do
      {:ok, %{"vulnerabilities" => entries} = decoded} when is_list(entries) ->
        rows = Enum.map(entries, &nvd_row(&1, cve_id))
        declared = total_results(decoded)

        cond do
          :error in rows ->
            {:error, :nvd_parse_failed}

          length(Enum.uniq_by(rows, & &1.external_id)) != length(rows) ->
            {:error, :nvd_parse_failed}

          not is_nil(declared) and declared != length(rows) ->
            {:error, :nvd_declared_count_mismatch}

          true ->
            {:ok, %{generation(rows, declared, decoded) | complete?: not is_nil(declared)}}
        end

      _ ->
        {:error, :nvd_parse_failed}
    end
  end

  defp generation(rows, declared, decoded) do
    %{
      rows: rows,
      declared_count: declared,
      complete?: true,
      catalog_version: catalog_version(decoded),
      metadata: feed_metadata(decoded)
    }
  end

  defp declared_count(%{"count" => count}) when is_integer(count) and count >= 0, do: count
  defp declared_count(_decoded), do: nil

  defp total_results(%{"totalResults" => total}) when is_integer(total) and total >= 0, do: total
  defp total_results(_decoded), do: nil

  defp catalog_version(%{"catalogVersion" => version}) when is_binary(version),
    do: String.slice(Sanitize.text(version) || "", 0, 40)

  defp catalog_version(_decoded), do: nil

  # Only the catalogue's own non-secret provenance metadata is retained, and only
  # sanitized and bounded.
  defp feed_metadata(decoded) do
    for key <- ["title", "catalogVersion", "dateReleased", "count"],
        value = decoded[key],
        not is_nil(value),
        into: %{} do
      {key, sanitize_meta(value)}
    end
  end

  defp sanitize_meta(value) when is_binary(value),
    do: String.slice(Sanitize.text(value) || "", 0, 200)

  defp sanitize_meta(value) when is_integer(value), do: value
  defp sanitize_meta(_other), do: nil

  defp kev_row(%{"cveID" => id} = entry) do
    if Sanitize.valid_cve_id?(id) and
         text_fields?(
           entry,
           ~w(shortDescription dateAdded requiredAction dueDate knownRansomwareCampaignUse)
         ) do
      %{
        external_id: id,
        summary: Sanitize.text(entry["shortDescription"]),
        published_at: date(entry["dateAdded"]),
        required_action: Sanitize.text(entry["requiredAction"]),
        due_date: date(entry["dueDate"]),
        known_ransomware: ransomware_flag(entry["knownRansomwareCampaignUse"])
      }
    else
      :error
    end
  end

  defp kev_row(_other), do: :error

  defp nvd_row(%{"cve" => %{"id" => id} = cve}, expected_id) do
    with true <- id == expected_id and text_fields?(cve, ~w(published)),
         descriptions when is_list(descriptions) <- Map.get(cve, "descriptions", []),
         true <- Enum.all?(descriptions, &description?/1) do
      english = Enum.find(descriptions, %{}, &(&1["lang"] == "en"))

      %{
        external_id: id,
        summary: Sanitize.text(english["value"]),
        published_at: date(cve["published"])
      }
    else
      _ -> :error
    end
  end

  defp nvd_row(_other, _expected_id), do: :error

  defp description?(%{"lang" => lang, "value" => value}),
    do: is_binary(lang) and is_binary(value)

  defp description?(_other), do: false

  defp text_fields?(map, fields),
    do: Enum.all?(fields, fn key -> is_nil(map[key]) or is_binary(map[key]) end)

  defp nvd_safe_cve(id) do
    if Sanitize.valid_cve_id?(id), do: :ok, else: {:error, {:invalid_cve_id, sanitize_error(id)}}
  end

  ## Helpers

  # CISA spells this field "Known" / "Unknown". Anything else — including a missing
  # field — stays nil: unknown is never silently downgraded to a reassuring false.
  defp ransomware_flag(value) when is_binary(value) do
    case value |> String.trim() |> String.downcase() do
      "known" -> true
      "unknown" -> false
      _ -> nil
    end
  end

  defp ransomware_flag(_other), do: nil

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

  # A transport result is interpreted here in exactly one place — status first, then
  # the byte bound — so an injected fake and the real transport are held to the same
  # limits and no non-200 or oversized body can reach a parser. Both documented
  # result shapes are accepted; a non-200 result never carries its body forward.
  defp get(url, source, transport) do
    with {:ok, max} <- Config.max_response_bytes() do
      selected = if transport == :default_transport, do: default_transport(max), else: transport
      do_get(url, selected, max, source)
    end
  end

  defp do_get(url, %{req: req_fun}, max, source) when is_function(req_fun, 1) do
    case req_fun.(url) do
      {:ok, %{status: 200, body: body}} ->
        if_byte_size_ok(body, max, source)

      {:ok, %{status: status}} when is_integer(status) and status in 300..399 ->
        # Terminal: never follow Location, never leak it.
        {:error, {:redirect_refused, status}}

      {:ok, %{status: status}} when is_integer(status) ->
        {:error, {:http_status, status}}

      {:ok, body} ->
        if_byte_size_ok(body, max, source)

      {:error, reason} ->
        {:error, reason}

      _other ->
        {:error, :unexpected_transport_result}
    end
  rescue
    _ -> {:error, :request_raised}
  catch
    :exit, _ -> {:error, :request_raised}
  end

  defp do_get(_url, _other, _max, _source), do: {:error, :no_transport}

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
