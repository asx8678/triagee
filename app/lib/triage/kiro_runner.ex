defmodule Triage.KiroRunner do
  @moduledoc "Bounded headless Kiro transport. No shell, tools, MCP, repository context or inherited application secrets."
  @max_output 65_536
  @safe_env ~w(HOME USER LOGNAME PATH TMPDIR LANG LC_ALL TERM)

  def agent_path, do: Application.app_dir(:triage, "priv/kiro/triage-classifier.json")

  def agent_hash,
    do: :crypto.hash(:sha256, File.read!(agent_path())) |> Base.encode16(case: :lower)

  def run(cli, prompt, options \\ []) do
    caller = self()

    Task.Supervisor.async_nolink(Triage.KiroTasks, fn -> execute(caller, cli, prompt, options) end)
    |> Task.await(:infinity)
  catch
    :exit, _ -> {:error, :cli_unavailable}
  end

  defp execute(caller, cli, prompt, options) do
    monitor = Process.monitor(caller)
    directory = Path.join(System.tmp_dir!(), "triage-kiro-#{Ecto.UUID.generate()}")

    try do
      File.mkdir_p!(Path.join(directory, ".kiro/agents"))
      File.chmod!(directory, 0o700)
      File.cp!(agent_path(), Path.join(directory, ".kiro/agents/triage-classifier.json"))

      port =
        Port.open({:spawn_executable, String.to_charlist(cli)}, [
          :binary,
          :exit_status,
          :use_stdio,
          :stderr_to_stdout,
          {:cd, String.to_charlist(directory)},
          {:env, environment(options)},
          {:args, arguments(prompt, options)}
        ])

      deadline =
        System.monotonic_time(:millisecond) +
          min(Keyword.get(options, :timeout_ms, 120_000), 120_000)

      try do
        collect(port, monitor, "", deadline)
      after
        stop(port)
      end
    rescue
      _ -> {:error, :cli_unavailable}
    after
      Process.demonitor(monitor, [:flush])
      File.rm_rf(directory)
    end
  end

  def arguments(prompt, options) do
    args = [
      "chat",
      "--no-interactive",
      "--trust-tools=",
      "--agent",
      "triage-classifier",
      "--wrap",
      "never",
      "--effort",
      "low"
    ]

    args = if options[:model] in [nil, ""], do: args, else: args ++ ["--model", options[:model]]
    args ++ [prompt]
  end

  defp environment(options) do
    test_keys =
      if options[:test_env],
        do: ~w(TRIAGE_FAKE_RUNNER_MODE TRIAGE_FAKE_RUNNER_LOG TRIAGE_FAKE_RUNNER_CAPTURE),
        else: []

    Enum.map(System.get_env(), fn {key, value} ->
      {String.to_charlist(key),
       if(key in (@safe_env ++ test_keys), do: String.to_charlist(value), else: false)}
    end)
  end

  defp collect(port, monitor, output, deadline) do
    remaining = max(0, deadline - System.monotonic_time(:millisecond))

    receive do
      {^port, {:data, data}} when byte_size(output) + byte_size(data) <= @max_output ->
        collect(port, monitor, output <> data, deadline)

      {^port, {:data, _}} ->
        {:error, :output_too_large}

      {^port, {:exit_status, 0}} ->
        {:ok, String.trim(output)}

      {^port, {:exit_status, _}} ->
        {:error, :cli_failed}

      {:DOWN, ^monitor, :process, _, _} ->
        {:error, :caller_stopped}
    after
      remaining -> {:error, :timeout}
    end
  end

  # Stop descendants before closing the port, also when the owning job dies.
  defp stop(port) do
    case Port.info(port, :os_pid) do
      {:os_pid, pid} ->
        kill_tree(Integer.to_string(pid))
        Port.close(port)

      _ ->
        :ok
    end
  catch
    :error, _ -> :ok
  end

  defp kill_tree(pid) do
    if pgrep = System.find_executable("pgrep") do
      {children, _} = System.cmd(pgrep, ["-P", pid], stderr_to_stdout: true)

      children
      |> String.split()
      |> Enum.filter(&Regex.match?(~r/^\d+$/, &1))
      |> Enum.each(&kill_tree/1)
    end

    if kill = System.find_executable("kill"),
      do: System.cmd(kill, ["-KILL", pid], stderr_to_stdout: true)

    :ok
  end
end
