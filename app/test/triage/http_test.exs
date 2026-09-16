defmodule Triage.HTTPTest do
  use ExUnit.Case, async: true

  alias Triage.HTTP

  test "keyword limits are required positive integers" do
    assert_raise KeyError, fn -> HTTP.options(timeout: 1) end
    assert_raise KeyError, fn -> HTTP.options(max_bytes: 1) end

    for bad <- [nil, 0, -1, 1.5, "4", :infinity] do
      assert_raise ArgumentError, fn -> HTTP.options(timeout: bad, max_bytes: 1) end
      assert_raise ArgumentError, fn -> HTTP.options(timeout: 1, max_bytes: bad) end
    end
  end

  test "shared options disable redirects, retries and decoding and bound timeouts" do
    opts = HTTP.options(timeout: 250, max_bytes: 4)
    assert opts[:redirect] == false
    assert opts[:retry] == false
    assert opts[:decode_body] == false
    assert opts[:max_retries] == 0
    assert opts[:connect_options] == [timeout: 250]
    assert opts[:receive_timeout] == 250
    assert opts[:request_timeout] == 250
  end

  test "stream accepts the exact cap, then halts without retaining excess bytes" do
    into = HTTP.options(timeout: 250, max_bytes: 4)[:into]
    initial = {Req.Request.new(), Req.Response.new(body: "")}
    assert {:cont, state} = into.({:data, "ab"}, initial)
    assert {:cont, state} = into.({:data, "cd"}, state)
    assert {:ok, "abcd"} = HTTP.bounded_body(elem(state, 1).body, 4)
    assert {:halt, {_request, response}} = into.({:data, "secret"}, state)
    assert {:error, :too_large} = HTTP.bounded_body(response.body, 4)
    refute inspect(response.body) =~ "secret"
  end

  test "non-data events and untrusted injected bodies cannot bypass the bound" do
    into = HTTP.options(timeout: 250, max_bytes: 4)[:into]
    initial = {Req.Request.new(), Req.Response.new(body: nil)}
    assert {:cont, ^initial} = into.({:trailers, []}, initial)
    assert {:cont, {_request, response}} = into.({:data, "abcd"}, initial)
    assert {:ok, "abcd"} = HTTP.bounded_body(response.body, 4)
    assert {:error, :too_large} = HTTP.bounded_body("abcde", 4)
    assert {:ok, ""} = HTTP.bounded_body("", 4)
    for body <- [nil, %{}, 42], do: assert(HTTP.bounded_body(body, 4) == {:error, :invalid_body})
  end
end
