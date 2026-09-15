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

  alias Triage.Intel.Sanitize

  # The KEV feed is a single multi-megabyte JSON document that grows as CISA adds
  # entries. The bound stays enforced before decode — but it must not fail a
  # legitimate feed closed, and truncating the feed instead would make "not in
  # the cache" indistinguishable from "not known exploited".
  @max_response_bytes 8_000_000
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
        case Req.get(url,
               redirect: false,
               retry: false,
               connect_options: [timeout: @deadline_ms],
               receive_timeout: @deadline_ms,
               decode_body: false
             ) do
          {:error, reason} -> {:error, {:request_failed, sanitize_error(reason)}}
          result -> result
        end

      _ ->
        {:error, {:unallowlisted_url, host_of(url)}}
    end
  end

  defp if_byte_size_ok(body) when is_binary(body) do
    if byte_size(body) <= @max_response_bytes,
      do: {:ok, body},
      else: {:error, {:response_too_large, @max_response_bytes}}
  end

  defp if_byte_size_ok(_other), do: {:error, {:unexpected_body, :other}}

  ## Parsers — all produce sanitized plain maps

  defp parse_kev(body), do: parse_feed(body, &kev_row/1, :kev_parse_failed)

  defp parse_nvd(body, cve_id),
    do: parse_feed(body, &nvd_row(&1, cve_id), :nvd_parse_failed)

  # Validate the whole feed before allowing a replacement. Invalid or duplicate
  # entries must never be silently dropped into an empty or partial success.
  defp parse_feed(body, parser, error) do
    case Jason.decode(body) do
      {:ok, %{"vulnerabilities" => entries}} when is_list(entries) ->
        rows = Enum.map(entries, parser)

        if :error in rows or length(Enum.uniq_by(rows, & &1.external_id)) != length(rows),
          do: {:error, error},
          else: {:ok, rows}

      _ ->
        {:error, error}
    end
  end

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
  defp get(url, %{req: req_fun}) when is_function(req_fun, 1) do
    case req_fun.(url) do
      {:ok, %{status: 200, body: body}} ->
        if_byte_size_ok(body)

      {:ok, %{status: status}} when is_integer(status) and status in 300..399 ->
        # Terminal: never follow Location, never leak it.
        {:error, {:redirect_refused, status}}

      {:ok, %{status: status}} when is_integer(status) ->
        {:error, {:http_status, status}}

      {:ok, body} ->
        if_byte_size_ok(body)

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
