defmodule Triage.Collection.Config do
  @moduledoc """
  Explicit, validated offline collection configuration.

  There is no default endpoint, no default environment and no default
  credential. The only transport endpoint accepted is the literal test-only
  loopback `http://127.0.0.1`; every other host and every `https` endpoint is
  rejected, so the adapter cannot become a generic live HTTP client. All fields
  are plain, bounded values and `revalidate/1` re-runs the same checks so a
  forged struct cannot bypass `new/1`.

  `max_text_bytes` bounds one individual string; `max_total_bytes` is a
  distinct aggregate budget across all owner/inventory/detail/raw metadata
  accumulated into a single report, and is also the run-scoped aggregate
  response-byte admission budget enforced by the client before any decode. The
  two are never interchanged.
  """

  alias Triage.Collection.Errors.InvalidOptionsError

  @enforce_keys [:endpoint, :environment]
  defstruct endpoint: nil,
            environment: nil,
            engine: "Grype",
            headers: [],
            concurrency: 4,
            max_retries: 2,
            request_timeout_ms: 15_000,
            total_deadline_ms: 60_000,
            max_requests: 500,
            max_records: 50_000,
            max_text_bytes: 1_000_000,
            max_total_bytes: 16_000_000,
            max_response_bytes: 4_000_000,
            max_depth: 32,
            retry_statuses: [408, 425, 429, 500, 502, 503, 504],
            max_payload_depth: 64

  @type t :: %__MODULE__{}

  @fields ~w(
    endpoint environment engine headers concurrency max_retries
    request_timeout_ms total_deadline_ms max_requests max_records
    max_text_bytes max_total_bytes max_response_bytes max_depth
    max_payload_depth retry_statuses
  )a

  @int_fields %{
    concurrency: {1, 64},
    max_retries: {0, 10},
    request_timeout_ms: {1, 120_000},
    total_deadline_ms: {1, 3_600_000},
    max_requests: {1, 100_000},
    max_records: {1, 1_000_000},
    max_text_bytes: {1, 50_000_000},
    max_total_bytes: {1, 200_000_000},
    max_response_bytes: {1, 50_000_000},
    max_depth: {1, 256},
    max_payload_depth: {1, 4096}
  }

  @secret_headers ~w(
    authorization proxy-authorization cookie set-cookie www-authenticate
    x-api-key x-auth-token api-key authentication
  )

  @defaults %{
    endpoint: "http://127.0.0.1",
    environment: "test",
    engine: "Grype",
    headers: [],
    concurrency: 4,
    max_retries: 2,
    request_timeout_ms: 15_000,
    total_deadline_ms: 60_000,
    max_requests: 500,
    max_records: 50_000,
    max_text_bytes: 1_000_000,
    max_total_bytes: 16_000_000,
    max_response_bytes: 4_000_000,
    max_depth: 32,
    retry_statuses: [408, 425, 429, 500, 502, 503, 504],
    max_payload_depth: 64
  }

  @doc "Validates plain map/keyword options into a `Config`, or returns an error."
  @spec new(term()) :: {:ok, t()} | {:error, InvalidOptionsError.t()}
  def new(opts) do
    with {:ok, opts} <- normalize_options(opts),
         {:ok, opts} <- normalize_keys(opts),
         :ok <- reject_unknown_keys(opts),
         {:ok, endpoint} <- validate_endpoint(Map.get(opts, :endpoint)),
         {:ok, environment} <- validate_text(Map.get(opts, :environment), :environment),
         {:ok, engine} <- validate_text(Map.get(opts, :engine, "Grype"), :engine),
         {:ok, headers} <- validate_headers(Map.get(opts, :headers, [])),
         {:ok, ints} <- validate_ints(opts),
         {:ok, retry_statuses} <- validate_retry_statuses(opts) do
      cfg =
        %__MODULE__{
          endpoint: endpoint,
          environment: environment,
          engine: engine,
          headers: headers
        }
        |> Map.merge(ints)
        |> Map.put(:retry_statuses, retry_statuses)

      {:ok, cfg}
    end
  end

  @doc "Revalidates an existing struct so forged structs cannot bypass `new/1`."
  @spec revalidate(term()) :: {:ok, t()} | {:error, InvalidOptionsError.t()}
  def revalidate(%__MODULE__{} = config), do: config |> Map.from_struct() |> new()
  def revalidate(_other), do: {:error, invalid("config must be a validated Config struct")}

  @doc "True only for the literal test-only loopback endpoint."
  @spec endpoint_allowed?(term()) :: boolean()
  def endpoint_allowed?(endpoint), do: match?({:ok, _}, validate_endpoint(endpoint))

  defp normalize_options(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      {:ok, opts}
    else
      {:error, invalid("options must be a keyword list or map")}
    end
  end

  defp normalize_options(opts) when is_map(opts), do: {:ok, Map.to_list(opts)}
  defp normalize_options(_other), do: {:error, invalid("options must be a keyword list or map")}

  defp normalize_keys(opts) do
    Enum.reduce_while(opts, {:ok, %{}}, fn
      {key, value}, {:ok, acc} when is_atom(key) ->
        {:cont, {:ok, Map.put(acc, key, value)}}

      {key, value}, {:ok, acc} when is_binary(key) ->
        try do
          {:cont, {:ok, Map.put(acc, String.to_existing_atom(key), value)}}
        rescue
          ArgumentError -> {:halt, {:error, invalid("unknown configuration key")}}
        end

      _other, _acc ->
        {:halt, {:error, invalid("configuration keys must be atoms or known strings")}}
    end)
  end

  defp reject_unknown_keys(opts) do
    case Enum.find(Map.keys(opts), &(&1 not in @fields)) do
      nil -> :ok
      key -> {:error, invalid("unknown configuration key #{inspect(key)}")}
    end
  end

  defp validate_endpoint(nil),
    do: {:error, invalid("endpoint is required; there is no default endpoint")}

  defp validate_endpoint(endpoint) when not is_binary(endpoint),
    do: {:error, invalid("endpoint must be a string URL")}

  defp validate_endpoint(endpoint) do
    uri = URI.parse(endpoint)

    cond do
      Enum.any?(["\n", "\r", " ", "@"], &String.contains?(endpoint, &1)) ->
        {:error, invalid("endpoint must not contain credentials or whitespace")}

      uri.scheme != "http" ->
        {:error, invalid("only the test-only loopback http endpoint is allowed")}

      uri.host != "127.0.0.1" ->
        {:error, invalid("endpoint host must be the literal loopback 127.0.0.1")}

      uri.userinfo != nil ->
        {:error, invalid("endpoint must not contain credentials")}

      uri.query != nil or uri.fragment != nil ->
        {:error, invalid("endpoint must not contain a query or fragment")}

      true ->
        {:ok, endpoint}
    end
  end

  defp validate_text(value, field) when is_binary(value) do
    cond do
      not String.valid?(value) ->
        {:error, invalid("#{field} must be valid UTF-8")}

      String.trim(value) == "" ->
        {:error, invalid("#{field} must not be blank")}

      String.length(value) > 120 ->
        {:error, invalid("#{field} must be at most 120 characters")}

      Regex.match?(~r/[\x00-\x1F\x7F]/, value) ->
        {:error, invalid("#{field} must not contain control characters")}

      true ->
        {:ok, value}
    end
  end

  defp validate_text(_value, field), do: {:error, invalid("#{field} must be a string")}

  defp validate_headers(headers) when is_list(headers) do
    if length(headers) > 32 do
      {:error, invalid("at most 32 headers are allowed")}
    else
      Enum.reduce_while(headers, {:ok, []}, fn
        {name, value}, {:ok, acc} when is_binary(name) and is_binary(value) ->
          down = String.downcase(name)

          cond do
            String.trim(name) == "" ->
              {:halt, {:error, invalid("header name must not be blank")}}

            down in @secret_headers ->
              {:halt, {:error, invalid("credential headers are not supported")}}

            not String.valid?(value) ->
              {:halt, {:error, invalid("header value must be valid UTF-8")}}

            Regex.match?(~r/[\x00-\x1F\x7F]/, name) or Regex.match?(~r/[\r\n]/, value) ->
              {:halt, {:error, invalid("header name/value must not contain control characters")}}

            true ->
              {:cont, {:ok, [{name, value} | acc]}}
          end

        _other, _acc ->
          {:halt, {:error, invalid("headers must be a list of {name, value} string pairs")}}
      end)
      |> case do
        {:ok, list} -> {:ok, Enum.reverse(list)}
        error -> error
      end
    end
  end

  defp validate_headers(_other), do: {:error, invalid("headers must be a list")}

  defp validate_ints(opts) do
    Enum.reduce_while(@int_fields, {:ok, %{}}, fn {key, {min, max}}, {:ok, acc} ->
      value = Map.get(opts, key, Map.fetch!(@defaults, key))

      if is_integer(value) and value >= min and value <= max do
        {:cont, {:ok, Map.put(acc, key, value)}}
      else
        {:halt, {:error, invalid("#{key} must be an integer between #{min} and #{max}")}}
      end
    end)
  end

  defp validate_retry_statuses(opts) do
    value = Map.get(opts, :retry_statuses, Map.fetch!(@defaults, :retry_statuses))

    if is_list(value) and value != [] and
         Enum.all?(value, &(is_integer(&1) and &1 >= 100 and &1 <= 599)) do
      {:ok, Enum.uniq(value)}
    else
      {:error, invalid("retry_statuses must be a nonempty list of HTTP status integers")}
    end
  end

  defp invalid(message), do: %InvalidOptionsError{message: message}
end
