defmodule Triage.Collection.ConfigTest do
  use ExUnit.Case, async: true

  alias Triage.Collection
  alias Triage.Collection.Config
  alias Triage.Collection.Errors.{DisabledError, InvalidOptionsError}

  @loopback "http://127.0.0.1:1234/graphql"

  test "there is no default endpoint and no inferred environment" do
    assert {:error, %InvalidOptionsError{}} = Config.new([])
    assert {:error, %InvalidOptionsError{}} = Config.new(%{})
    assert {:error, %InvalidOptionsError{}} = Config.new(endpoint: @loopback)
  end

  test "only the literal test-only loopback endpoint is accepted" do
    assert {:error, %InvalidOptionsError{}} =
             Config.new(endpoint: "http://example.com/graphql", environment: "test")

    assert {:error, %InvalidOptionsError{}} =
             Config.new(endpoint: "ftp://127.0.0.1/graphql", environment: "test")

    assert {:error, %InvalidOptionsError{}} =
             Config.new(endpoint: "http://localhost:1234/graphql", environment: "test")

    assert {:error, %InvalidOptionsError{}} =
             Config.new(endpoint: "http://[::1]:1234/graphql", environment: "test")

    assert {:error, %InvalidOptionsError{}} =
             Config.new(endpoint: "https://security.example.com/graphql", environment: "prod")

    assert {:ok, %Config{}} = Config.new(endpoint: @loopback, environment: "test")
  end

  test "endpoint credentials, whitespace and query strings are rejected" do
    assert {:error, %InvalidOptionsError{}} =
             Config.new(endpoint: "http://user:pass@127.0.0.1/graphql", environment: "test")

    assert {:error, %InvalidOptionsError{}} =
             Config.new(endpoint: "http://127.0.0.1/graphql?x=1", environment: "test")
  end

  test "plain inputs are required; malformed shapes and unknown keys are controlled errors" do
    assert {:error, %InvalidOptionsError{}} = Config.new([:broken])
    assert {:error, %InvalidOptionsError{}} = Config.new("nope")

    assert {:error, %InvalidOptionsError{}} =
             Config.new(endpoint: @loopback, environment: "test", no_such_key: 1)

    assert {:error, %InvalidOptionsError{}} =
             Config.new(%{"string_key" => 1, endpoint: @loopback, environment: "test"})
  end

  test "bounded integers are enforced and non-integers are rejected" do
    base = [endpoint: @loopback, environment: "test"]
    assert {:error, %InvalidOptionsError{}} = Config.new(base ++ [concurrency: 0])
    assert {:error, %InvalidOptionsError{}} = Config.new(base ++ [concurrency: 10_000])
    assert {:error, %InvalidOptionsError{}} = Config.new(base ++ [concurrency: "3"])
    assert {:error, %InvalidOptionsError{}} = Config.new(base ++ [max_retries: -1])
    assert {:ok, %Config{}} = Config.new(base ++ [concurrency: 3, max_retries: 1])
  end

  test "header injection and credential headers are rejected" do
    base = [endpoint: @loopback, environment: "test"]
    assert {:error, %InvalidOptionsError{}} = Config.new(base ++ [headers: [{"x", "a\r\nb"}]])

    assert {:error, %InvalidOptionsError{}} =
             Config.new(base ++ [headers: [{"Authorization", "Bearer secret"}]])

    assert {:error, %InvalidOptionsError{}} = Config.new(base ++ [headers: [{"cookie", "a=b"}]])
    assert {:error, %InvalidOptionsError{}} = Config.new(base ++ [headers: [{"x-api-key", "k"}]])
    assert {:ok, %Config{}} = Config.new(base ++ [headers: [{"x-test", "ok"}]])
  end

  test "revalidate/1 re-runs the checks so forged structs cannot bypass new/1" do
    assert {:ok, %Config{}} =
             Config.revalidate(%Config{endpoint: @loopback, environment: "test"})

    assert {:error, %InvalidOptionsError{}} =
             Config.revalidate(%Config{
               endpoint: "https://evil.invalid/graphql",
               environment: "test"
             })

    assert {:error, %InvalidOptionsError{}} =
             Config.revalidate(%Config{endpoint: @loopback, environment: nil})

    assert {:error, %InvalidOptionsError{}} =
             Config.revalidate(%Config{endpoint: @loopback, environment: "test", max_records: -1})
  end

  test "the default entry is disabled and performs no network access" do
    assert {:error, %DisabledError{}} = Collection.run([])
    assert {:error, %DisabledError{}} = Collection.run(config: nil)
    assert {:error, %InvalidOptionsError{}} = Collection.run(%{})
  end

  test "an explicit config without a transport stays disabled" do
    opts = [config: [endpoint: @loopback, environment: "test"]]
    assert {:error, %DisabledError{}} = Collection.run(opts)
  end

  test "a malformed or arbitrary transport is rejected before any network access" do
    base = [config: [endpoint: @loopback, environment: "test"]]

    assert {:error, %InvalidOptionsError{}} =
             Collection.run(base ++ [transport: :not_a_transport])

    assert {:error, %InvalidOptionsError{}} =
             Collection.run(base ++ [transport: {Triage.Collection.Normalize, %{}}])

    assert {:error, %InvalidOptionsError{}} =
             Collection.run(base ++ [transport: {Triage.Collection.Transport.Req, %{}}])
  end
end
