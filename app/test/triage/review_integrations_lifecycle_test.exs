defmodule Triage.ReviewIntegrationsLifecycleTest do
  @moduledoc """
  Real subprocess lifecycle checks for the AI wrapper port: cancellation must
  terminate the administrator-provided program and its children, not just the
  Erlang side of the port.
  """
  use ExUnit.Case, async: false
  alias Triage.ReviewIntegrations

  setup do
    previous = Application.fetch_env(:triage, ReviewIntegrations)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:triage, ReviewIntegrations, value)
        :error -> Application.delete_env(:triage, ReviewIntegrations)
      end
    end)

    :ok
  end

  test "output overflow terminates the wrapper and its children" do
    marker =
      configure!("overflow", """
      sleep 120 &
      printf '%s %s\n' "$$" "$!" > "$0.pids"
      head -c 70000 /dev/zero
      sleep 120
      """)

    assert {:error, "Internal AI output exceeded the limit."} = ReviewIntegrations.assess(%{})

    [wrapper, child] = marker |> File.read!() |> String.split()
    assert_dead!(wrapper)
    assert_dead!(child)
  end

  test "the deadline terminates a hung wrapper and its children" do
    marker =
      configure!(
        "timeout",
        """
        sleep 120 &
        printf '%s %s\n' "$$" "$!" > "$0.pids"
        sleep 120
        """,
        # Allow the shell and its children to start under full-suite load.
        # This still cancels a 120-second sleep well before normal completion.
        ai_deadline_ms: 1_500
      )

    assert {:error, "Internal AI timed out; no recommendation was accepted."} =
             ReviewIntegrations.assess(%{})

    [wrapper, child] = marker |> File.read!() |> String.split()
    assert_dead!(wrapper)
    assert_dead!(child)
  end

  test "a failing wrapper reports failure without accepting a recommendation" do
    _marker = configure!("fail", "exit 3")

    assert {:error, "Internal AI failed; no recommendation was accepted."} =
             ReviewIntegrations.assess(%{})
  end

  # The wrapper script writes its own pid and its background child's pid to
  # "$0.pids" so the test can verify the tree is really gone. SIGTERM makes a
  # zombie possible for a moment, so poll briefly rather than flake.
  defp configure!(name, body, over \\ []) do
    path =
      Path.join(System.tmp_dir!(), "triage-ai-test-#{name}-#{System.unique_integer([:positive])}")

    File.write!(path, "#!/bin/sh\n" <> body)
    File.chmod!(path, 0o755)

    on_exit(fn ->
      File.rm(path)
      File.rm(path <> ".pids")
    end)

    Application.put_env(:triage, ReviewIntegrations, Keyword.put(over, :ai_executable, path))
    path <> ".pids"
  end

  defp assert_dead!(pid, attempts \\ 40)

  defp assert_dead!(_pid, 0), do: flunk("wrapper process was still alive after cancellation")

  defp assert_dead!(pid, attempts) do
    if alive?(pid) do
      # Bounded OS-process polling; no Erlang process to monitor here.
      Process.sleep(50)
      assert_dead!(pid, attempts - 1)
    else
      :ok
    end
  end

  defp alive?(pid) do
    case System.cmd(ps(), ["-o", "stat=", "-p", pid], stderr_to_stdout: true) do
      {output, 0} ->
        state = String.trim(output)
        state != "" and not String.starts_with?(state, "Z")

      _other ->
        false
    end
  end

  defp ps, do: System.find_executable("ps") || "/bin/ps"
end
