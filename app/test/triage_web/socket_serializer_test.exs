defmodule TriageWeb.SocketSerializerTest do
  @moduledoc """
  Regressions for the socket serializer guard that rewrites `url` payloads
  whose query `Plug.Conn.Query.decode/1` would crash on (e.g. invalid UTF-8
  bytes such as `%FF`) into the app's existing visible-invalid
  `filters=malformed` contract, before the vendored LiveView route decoder —
  which runs ahead of every app `handle_params` guard — sees them.
  """

  use ExUnit.Case, async: true

  alias Phoenix.Socket.Broadcast
  alias Phoenix.Socket.Message
  alias Phoenix.Socket.Reply
  alias Phoenix.Socket.V2.JSONSerializer, as: V2
  alias TriageWeb.FindingFilters
  alias TriageWeb.SocketSerializer

  @text_opts [opcode: :text]

  # Real V2 text frames: [join_ref, ref, topic, event, payload]
  defp frame(topic, event, payload, join_ref \\ "1", ref \\ "2") do
    Jason.encode!([join_ref, ref, topic, event, payload])
  end

  describe "decode!/2 rewrites malformed queries into the invalid-filters contract" do
    test "live_patch url with an invalid UTF-8 query keeps scheme, host, port and path" do
      raw =
        frame("lv:phx-1", "live_patch", %{
          "type" => "push",
          "url" => "http://host:1/findings/6844?owner=%FF&q=x"
        })

      assert %Message{topic: "lv:phx-1", event: "live_patch", ref: "2", join_ref: "1"} =
               message = SocketSerializer.decode!(raw, @text_opts)

      assert message.payload == %{
               "type" => "push",
               "url" => "http://host:1/findings/6844?filters=malformed"
             }
    end

    test "live_patch url preserves the fragment when rewriting" do
      raw =
        frame("lv:phx-1", "live_patch", %{
          "url" => "http://host:1/findings/6844?owner=%FF&q=x#section"
        })

      message = SocketSerializer.decode!(raw, @text_opts)
      assert message.payload["url"] == "http://host:1/findings/6844?filters=malformed#section"
    end

    test "phx_join url with a malformed query is rewritten the same way" do
      raw =
        frame("lv:phx-F", "phx_join", %{
          "url" => "http://host:1/findings/6844?owner=%FF",
          "session" => "token",
          "static" => "token",
          "_mounts" => "0"
        })

      message = SocketSerializer.decode!(raw, @text_opts)

      assert message.payload["url"] == "http://host:1/findings/6844?filters=malformed"
      assert message.payload["session"] == "token"
      assert message.payload["static"] == "token"
      assert message.payload["_mounts"] == "0"
    end

    test "relative urls with malformed queries are rewritten too" do
      raw = frame("lv:phx-1", "live_patch", %{"url" => "/findings/6844?environment=%FE%FF"})
      message = SocketSerializer.decode!(raw, @text_opts)
      assert message.payload["url"] == "/findings/6844?filters=malformed"
    end
  end

  describe "decode!/2 passes well-formed input through exactly unchanged" do
    test "valid urls with valid queries are byte-identical" do
      url = "http://host:1/findings/6844?owner=alpha&q=busybox&suppressed=1"
      raw = frame("lv:phx-1", "live_patch", %{"url" => url})

      message = SocketSerializer.decode!(raw, @text_opts)
      assert message == V2.decode!(raw, @text_opts)
      assert message.payload["url"] == url
    end

    test "urls without any query keep their fragment untouched" do
      url = "http://host:1/findings/6844#anchor"
      raw = frame("lv:phx-F", "phx_join", %{"url" => url})

      message = SocketSerializer.decode!(raw, @text_opts)
      assert message.payload["url"] == url
    end

    test "messages without a url key are untouched" do
      raw = frame("lv:phx-1", "event", %{"value" => "x?owner=%FF"})

      message = SocketSerializer.decode!(raw, @text_opts)
      assert message == V2.decode!(raw, @text_opts)
    end

    test "non-binary url values are untouched" do
      payload = %{"url" => %{"nested" => "value"}, "other" => [1, 2]}
      raw = frame("lv:phx-1", "live_patch", payload)

      message = SocketSerializer.decode!(raw, @text_opts)
      assert message.payload == payload
    end

    test "binary push frames decode untouched" do
      join_ref = "1"
      ref = "2"
      topic = "lv:phx-1"
      event = "live_patch"
      data = <<0, 1, 255, 254>>

      bin =
        <<0, byte_size(join_ref), byte_size(ref), byte_size(topic), byte_size(event),
          join_ref::binary, ref::binary, topic::binary, event::binary, data::binary>>

      assert %Message{payload: {:binary, ^data}, topic: ^topic, event: ^event} =
               SocketSerializer.decode!(bin, opcode: :binary)
    end
  end

  describe "encode!/1 and fastlane!/1 delegate to the V2 serializer" do
    test "messages and replies round-trip through the V2 frame format" do
      message = %Message{
        join_ref: "1",
        ref: "2",
        topic: "lv:phx-1",
        event: "live_patch",
        payload: %{"url" => "http://host:1/findings/6844?owner=alpha"}
      }

      assert SocketSerializer.encode!(message) == V2.encode!(message)

      {:socket_push, :text, iodata} = SocketSerializer.encode!(message)
      assert V2.decode!(iodata, @text_opts) == message

      reply = %Reply{
        join_ref: "1",
        ref: "2",
        topic: "lv:phx-1",
        status: :ok,
        payload: %{response: %{}}
      }

      assert SocketSerializer.encode!(reply) == V2.encode!(reply)
    end

    test "broadcasts fastlane through the V2 encoder" do
      broadcast = %Broadcast{topic: "lv:phx-1", event: "event", payload: %{"key" => "value"}}
      assert SocketSerializer.fastlane!(broadcast) == V2.fastlane!(broadcast)

      binary_broadcast = %Broadcast{
        topic: "lv:phx-1",
        event: "event",
        payload: {:binary, <<1, 2>>}
      }

      assert SocketSerializer.fastlane!(binary_broadcast) == V2.fastlane!(binary_broadcast)
    end
  end

  describe "endpoint wiring" do
    test "the guard is negotiated for both websocket and longpoll transports" do
      assert {"/live", Phoenix.LiveView.Socket, opts} =
               Enum.find(TriageWeb.Endpoint.__sockets__(), fn {path, _module, _opts} ->
                 path == "/live"
               end)

      websocket = Keyword.fetch!(opts, :websocket)
      longpoll = Keyword.fetch!(opts, :longpoll)

      for transport_opts <- [websocket, longpoll] do
        # V1 must not be offered: the guard wraps only the V2 wire format, so
        # any vsn 1.0.0 client is refused at serializer negotiation instead
        # of mounting an unguarded decoder path.
        assert Keyword.fetch!(transport_opts, :serializer) ==
                 [{TriageWeb.SocketSerializer, "~> 2.0.0"}]
      end
    end
  end

  describe "the rewritten query reaches the app's existing visible-invalid contract" do
    test "filters=malformed decodes cleanly and FindingFilters rejects it" do
      # The guard replaces a hostile query with exactly this string, so it
      # must remain one Plug accepts and FindingFilters marks invalid.
      assert Plug.Conn.Query.decode("filters=malformed") == %{"filters" => "malformed"}

      parsed = FindingFilters.parse(Plug.Conn.Query.decode("filters=malformed"))

      assert parsed.invalid != []
      assert parsed.owner == nil
      assert parsed.environment == nil
      assert parsed.q == nil
      assert parsed.include_suppressed == false
    end
  end
end
