defmodule TriageWeb.SocketSerializer do
  @moduledoc """
  WebSocket/longpoll message serializer guarding the vendored LiveView route
  decoder against malformed query strings carried inside socket payloads.

  Wraps `Phoenix.Socket.V2.JSONSerializer`: encoding, fastlaning and decoding
  are delegated unchanged, but after a successful decode any map payload with
  a binary `"url"` (both the `phx_join` and `live_patch` events carry one) is
  checked by attempting `Plug.Conn.Query.decode/1` on its query component —
  exactly the decode `Phoenix.LiveView`'s route helper performs *before* any
  app `handle_params` or `TriageWeb.FindingFilters` guard can act. A query
  that Plug itself would crash on (for example invalid UTF-8 bytes such as
  `%FF`, which `URI.decode_www_form/1` silently accepts while
  `Plug.Conn.Query.decode/1` raises `Plug.Conn.InvalidQueryError`) is
  rewritten to the app's existing visible-invalid contract
  `filters=malformed`, preserving scheme, host, port, path and fragment.
  Every other message passes through byte-identical.
  """

  @behaviour Phoenix.Socket.Serializer

  alias Phoenix.Socket.Message
  alias Phoenix.Socket.V2.JSONSerializer, as: V2

  @invalid_query "filters=malformed"

  @impl true
  def decode!(raw_message, opts) do
    case V2.decode!(raw_message, opts) do
      %Message{payload: %{"url" => url} = payload} = message when is_binary(url) ->
        %Message{message | payload: Map.put(payload, "url", sanitize_url(url))}

      message ->
        message
    end
  end

  @impl true
  def encode!(message), do: V2.encode!(message)

  @impl true
  def fastlane!(broadcast), do: V2.fastlane!(broadcast)

  # Never raises for input V2 itself accepted: `URI.parse/1` on a binary never
  # raises, and only the query component of a URL that actually has one is
  # probed. Any decode failure (broad rescue: any query Plug itself would
  # crash on, not just invalid UTF-8) rewrites only the query, leaving the
  # rest of the URI untouched.
  defp sanitize_url(url) do
    uri = URI.parse(url)

    if uri.query == nil do
      url
    else
      case decode_query(uri.query) do
        {:ok, _params} -> url
        :error -> URI.to_string(%URI{uri | query: @invalid_query})
      end
    end
  end

  defp decode_query(query) do
    {:ok, Plug.Conn.Query.decode(query)}
  rescue
    _ -> :error
  end
end
