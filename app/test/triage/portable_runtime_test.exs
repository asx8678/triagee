defmodule Triage.PortableRuntimeTest do
  use ExUnit.Case, async: true

  @runtime Path.expand("../../config/runtime.exs", __DIR__)

  defp runtime(args, overrides \\ %{}) do
    code = """
    config = Config.Reader.read!(#{inspect(@runtime)}, env: :prod)
    endpoint = config |> Keyword.fetch!(:triage) |> Keyword.fetch!(TriageWeb.Endpoint)
    IO.write(inspect({endpoint[:server], endpoint[:http][:ip]}))
    """

    env = %{
      "__BURRITO" => "1",
      "DATABASE_URL" => nil,
      "SECRET_KEY_BASE" => nil,
      "PHX_SERVER" => "true",
      "TRIAGE_BIND" => "127.0.0.1",
      "PORT" => "0",
      "TRIAGE_DEMO_MODE" => "false",
      "TRIAGE_REPORTING_API_ENABLED" => "false",
      "TRIAGE_ANALYSIS_ENABLED" => "false",
      "TRIAGE_CLASSIFIER_ENABLED" => "false",
      "TRIAGE_CLASSIFIER_AUTOMATIC" => "false",
      "TRIAGE_AZURE_TEAMS_JSON" => nil
    }

    # Match Burrito's embedded OTP launch. The elixir CLI would prepend its
    # own -e/-- arguments to :init.get_plain_arguments(), unlike Burrito.
    eval = """
    application:ensure_all_started(elixir),
    try 'Elixir.Code':eval_string(base64:decode("#{Base.encode64(code)}")) of
      _ -> halt(0)
    catch _:Reason -> io:format("~tp", [Reason]), halt(1)
    end.
    """

    System.cmd(
      System.find_executable("erl"),
      [
        "-noshell",
        "-pa",
        to_string(:code.lib_dir(:elixir, :ebin)),
        "-eval",
        eval,
        "-extra",
        "--no-halt",
        "--"
      ] ++
        args,
      env: Map.to_list(Map.merge(env, overrides)),
      stderr_to_stdout: true
    )
  end

  test "help, version, secret and invalid commands need no database and cannot listen" do
    for args <- [
          ["--help"],
          ["-h"],
          ["help"],
          ["--version"],
          ["version"],
          ["secret"],
          ["unknown"]
        ] do
      assert {"{false, {127, 0, 0, 1}}", 0} = runtime(args)
    end
  end

  test "server and database commands retain mandatory production credentials" do
    for args <- [[], ["start"], ["migrate"], ["account"]] do
      {output, status} = runtime(args)
      assert status != 0
      assert output =~ "DATABASE_URL is missing"
      {output, status} = runtime(args, %{"DATABASE_URL" => "ecto://localhost/unused"})
      assert status != 0
      assert output =~ "SECRET_KEY_BASE is missing"
    end
  end

  test "only start enables the endpoint, even with PHX_SERVER set" do
    env = %{
      "DATABASE_URL" => "ecto://localhost/unused",
      "SECRET_KEY_BASE" => String.duplicate("x", 64)
    }

    for args <- [[], ["start"]], do: assert({"{true, {127, 0, 0, 1}}", 0} = runtime(args, env))

    for args <- [["migrate"], ["account"]],
        do: assert({"{false, {127, 0, 0, 1}}", 0} = runtime(args, env))
  end

  test "Burrito cannot bypass the loopback boundary" do
    {output, status} = runtime(["--help"], %{"TRIAGE_BIND" => "0.0.0.0"})
    assert status != 0
    assert output =~ "TRIAGE_BIND must be exactly"
  end

  test "ordinary releases still require production credentials, even for help-like arguments" do
    {output, status} = runtime(["--help"], %{"__BURRITO" => nil})
    assert status != 0
    assert output =~ "DATABASE_URL is missing"
  end
end
