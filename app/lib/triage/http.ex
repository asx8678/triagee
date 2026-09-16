defmodule Triage.HTTP do
  @moduledoc """
  Shared Req safety policy for collection and public-intelligence adapters.

  Endpoint allowlists, credentials and error vocabularies belong to each adapter.
  This module only supplies redirect/retry/time/byte limits; it never performs a
  request. Real streams stop at the byte cap, and injected transport bodies must
  pass the same bound before decoding.
  """

  @doc """
  The request options every adapter passes to Req: redirects, retries and body
  decoding are off, the timeouts are bounded, and the response is streamed into
  a byte-capped accumulator.

  Takes `:timeout` and `:max_bytes` as keywords, and rejects a non-positive
  value rather than silently clamping it.
  """
  @spec options(keyword()) :: keyword()
  def options(opts) when is_list(opts) do
    timeout = positive!(Keyword.fetch!(opts, :timeout), :timeout)
    max_bytes = positive!(Keyword.fetch!(opts, :max_bytes), :max_bytes)

    [
      redirect: false,
      retry: false,
      max_retries: 0,
      decode_body: false,
      connect_options: [timeout: timeout],
      receive_timeout: timeout,
      request_timeout: timeout,
      into: into(max_bytes)
    ]
  end

  defp positive!(value, _name) when is_integer(value) and value > 0, do: value

  defp positive!(value, name),
    do: raise(ArgumentError, "#{name} must be a positive integer, got: #{inspect(value)}")

  @spec bounded_body(term(), pos_integer()) ::
          {:ok, binary()} | {:error, :too_large | :invalid_body}
  def bounded_body(:triage_response_too_large, _max), do: {:error, :too_large}

  def bounded_body(body, max) when is_binary(body) do
    if byte_size(body) <= max, do: {:ok, body}, else: {:error, :too_large}
  end

  def bounded_body(_body, _max), do: {:error, :invalid_body}

  defp into(max) do
    fn
      {:data, data}, {request, response} ->
        body = response.body || ""

        if byte_size(body) + byte_size(data) > max do
          # Retain neither the overflowing chunk nor a partial success body.
          {:halt, {request, %{response | body: :triage_response_too_large}}}
        else
          {:cont, {request, %{response | body: body <> data}}}
        end

      _event, state ->
        {:cont, state}
    end
  end
end
