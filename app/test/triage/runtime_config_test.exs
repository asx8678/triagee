unless Process.whereis(ExUnit.Server), do: ExUnit.start()

defmodule Triage.RuntimeConfigTest do
  use ExUnit.Case, async: false

  @runtime Path.expand("../../config/runtime.exs", __DIR__)
  @config Path.expand("../../config/config.exs", __DIR__)
  @controlled_env ~w(TRIAGE_BIND PORT DATABASE_URL SECRET_KEY_BASE PHX_HOST PHX_SERVER)
  @prod_env %{
    "DATABASE_URL" => "ecto://runtime.invalid/triage",
    "SECRET_KEY_BASE" => String.duplicate("x", 64)
  }

  defp read_runtime(env, overrides \\ %{}) do
    child_env = Enum.map(@controlled_env, &{&1, nil})
    encoded_overrides = overrides |> :erlang.term_to_binary() |> Base.encode64()

    code = """
    [path, env_name, encoded_overrides] = System.argv()
    overrides = encoded_overrides |> Base.decode64!() |> :erlang.binary_to_term([:safe])
    Enum.each(overrides, fn {key, value} -> System.put_env(key, value) end)

    env = case env_name do
      "dev" -> :dev
      "test" -> :test
      "prod" -> :prod
    end

    config = Config.Reader.read!(path, env: env)
    endpoint = config |> Keyword.fetch!(:triage) |> Keyword.fetch!(TriageWeb.Endpoint)
    http = Keyword.fetch!(endpoint, :http)
    projection = {Keyword.fetch!(http, :ip), Keyword.fetch!(http, :port), get_in(endpoint, [:url, :host])}
    IO.write(Base.encode64(:erlang.term_to_binary(projection)))
    """

    {output, status} =
      System.cmd(
        System.find_executable("elixir"),
        ["-e", code, "--", @runtime, Atom.to_string(env), encoded_overrides],
        env: child_env,
        stderr_to_stdout: true
      )

    if status == 0 do
      {:ok, output |> Base.decode64!() |> :erlang.binary_to_term([:safe])}
    else
      {:error, output}
    end
  end

  defp read_prod_force_ssl do
    code = """
    [path] = System.argv()
    config = Config.Reader.read!(path, env: :prod)
    endpoint = config |> Keyword.fetch!(:triage) |> Keyword.fetch!(TriageWeb.Endpoint)
    hosts = endpoint |> Keyword.fetch!(:force_ssl) |> get_in([:exclude, :hosts])
    IO.write(Base.encode64(:erlang.term_to_binary(hosts)))
    """

    {output, status} =
      System.cmd(
        System.find_executable("elixir"),
        ["-e", code, "--", @config],
        env: Enum.map(@controlled_env, &{&1, nil}),
        stderr_to_stdout: true
      )

    if status == 0 do
      {:ok, output |> Base.decode64!() |> :erlang.binary_to_term([:safe])}
    else
      {:error, output}
    end
  end

  test "development and production default to IPv4 loopback port 4000" do
    assert {:ok, {{127, 0, 0, 1}, 4000, nil}} = read_runtime(:dev)
    assert {:ok, {{127, 0, 0, 1}, 4000, "example.com"}} = read_runtime(:prod, @prod_env)
  end

  test "test defaults to its non-development port" do
    assert {:ok, {{127, 0, 0, 1}, 4002, nil}} = read_runtime(:test)
  end

  test "accepts only literal IPv4 and IPv6 loopback binds in every environment" do
    for env <- [:dev, :test, :prod] do
      required = if env == :prod, do: @prod_env, else: %{}

      assert {:ok, {{127, 0, 0, 1}, _, _}} =
               read_runtime(env, Map.put(required, "TRIAGE_BIND", "127.0.0.1"))

      assert {:ok, {{0, 0, 0, 0, 0, 0, 0, 1}, _, _}} =
               read_runtime(env, Map.put(required, "TRIAGE_BIND", "::1"))

      for rejected <- ["0.0.0.0", "::", "localhost", "127.0.0.2", " 127.0.0.1"] do
        assert {:error, output} = read_runtime(env, Map.put(required, "TRIAGE_BIND", rejected))
        assert output =~ "TRIAGE_BIND must be exactly 127.0.0.1 or ::1"
      end
    end
  end

  test "accepts decimal ports in range, including ephemeral zero" do
    for {text, expected} <- [{"0", 0}, {"4000", 4000}, {"65535", 65_535}] do
      assert {:ok, {_, ^expected, _}} = read_runtime(:test, %{"PORT" => text})
    end
  end

  test "rejects malformed and out-of-range ports" do
    for rejected <- ["", "-1", "65536", "4000x", "4.0", " 4000", "+4000"] do
      assert {:error, output} = read_runtime(:test, %{"PORT" => rejected})
      assert output =~ "PORT must be a decimal integer from 0 through 65535"
    end
  end

  test "production fails when database URL or secret is absent or empty" do
    for database_url <- [nil, ""] do
      overrides =
        if database_url == nil,
          do: %{"SECRET_KEY_BASE" => @prod_env["SECRET_KEY_BASE"]},
          else: %{
            "DATABASE_URL" => database_url,
            "SECRET_KEY_BASE" => @prod_env["SECRET_KEY_BASE"]
          }

      assert {:error, output} = read_runtime(:prod, overrides)
      assert output =~ "environment variable DATABASE_URL is missing"
    end

    for secret <- [nil, ""] do
      overrides =
        if secret == nil,
          do: %{"DATABASE_URL" => @prod_env["DATABASE_URL"]},
          else: %{"DATABASE_URL" => @prod_env["DATABASE_URL"], "SECRET_KEY_BASE" => secret}

      assert {:error, output} = read_runtime(:prod, overrides)
      assert output =~ "environment variable SECRET_KEY_BASE is missing"
    end
  end

  test "PHX_HOST changes URL generation but cannot change the bind" do
    assert {:ok, {{127, 0, 0, 1}, 4000, "public.example"}} =
             read_runtime(:prod, Map.put(@prod_env, "PHX_HOST", "public.example"))
  end

  test "production SSL redirect excludes only local host literals" do
    assert {:ok, hosts} = read_prod_force_ssl()
    assert hosts == ["localhost", "127.0.0.1", "::1", "[::1]"]
    refute "public.example" in hosts
  end

  test "configured ephemeral listener actually binds only to loopback" do
    assert {:ok, {ip, 0, nil}} = read_runtime(:test, %{"PORT" => "0"})

    assert {:ok, socket} =
             :gen_tcp.listen(0, [:binary, active: false, ip: ip, reuseaddr: true])

    on_exit(fn -> :gen_tcp.close(socket) end)
    assert {:ok, {{127, 0, 0, 1}, selected_port}} = :inet.sockname(socket)
    assert selected_port > 0
  end
end
