defmodule Triage.Replay.CLI do
  @moduledoc """
  Synchronous, trusted-local-only JSON replay command helper.

  `main/1` returns `{exit_code, json}` without printing, halting, starting
  applications, connecting to services, or writing files. Input is at most
  1,000,000 bytes; output is at most 65,536 bytes. Exit codes are 0 (complete
  or help), 2 (incomplete), and 1 (invalid input or execution failure).

  The final path component must not be a symlink. Parent-directory symlinks
  are permitted. A pre-open lstat rejects nonregular files; the opened raw
  descriptor is checked again and read for at most limit + 1 bytes. This is
  not a sandbox against concurrent hostile filesystem replacement: callers
  must control the file and its containing directories throughout the call.
  """

  @max_input_bytes 1_000_000
  @max_output_bytes 65_536

  @spec main([String.t()]) :: {0 | 1 | 2, binary()}
  def main(argv) do
    case argv do
      ["--help"] ->
        {0,
         ~s({"format":"triage.replay.help","version":1,"usage":"mix triage.replay --file PATH","max_input_bytes":1000000,"exit_codes":{"complete":0,"incomplete":2,"invalid":1}})}

      ["--file", path] when is_binary(path) and byte_size(path) > 0 ->
        if String.starts_with?(path, "-") or String.contains?(path, <<0>>) do
          error(:invalid_arguments)
        else
          replay_file(path)
        end

      _ ->
        error(:invalid_arguments)
    end
  rescue
    _ -> error(:execution_failed)
  catch
    _, _ -> error(:execution_failed)
  end

  defp replay_file(path) do
    with {:ok, %{type: :regular, size: size}} when size <= @max_input_bytes <-
           File.lstat(path),
         {:ok, file} <- :file.open(path, [:read, :binary, :raw]) do
      try do
        read_descriptor(file)
      after
        :file.close(file)
      end
    else
      {:ok, %{type: :regular}} -> error(:input_too_large)
      _ -> error(:invalid_file)
    end
  end

  defp read_descriptor(file) do
    # File.stat/1 takes a path, not an IO device. OTP's descriptor-aware API
    # returns a file_info record, converted using Elixir's public API.
    with {:ok, info} <- :file.read_file_info(file),
         %{type: :regular, size: size} when size <= @max_input_bytes <-
           File.Stat.from_record(info) do
      case :file.read(file, @max_input_bytes + 1) do
        {:ok, json} when byte_size(json) <= @max_input_bytes -> replay(json)
        {:ok, _} -> error(:input_too_large)
        :eof -> replay("")
        _ -> error(:invalid_file)
      end
    else
      %{type: :regular} -> error(:input_too_large)
      _ -> error(:invalid_file)
    end
  end

  defp replay(json) do
    case Triage.Replay.run(json) do
      {:ok, %{"complete" => complete} = summary} when is_boolean(complete) ->
        case Jason.encode(summary) do
          {:ok, encoded} when byte_size(encoded) <= @max_output_bytes ->
            {if(complete, do: 0, else: 2), encoded}

          _ ->
            error(:execution_failed)
        end

      {:error, _reason} ->
        error(:invalid_replay)

      _ ->
        error(:execution_failed)
    end
  end

  # Deliberately do not serialize arbitrary replay, OS, or exception reasons.
  defp error(:invalid_arguments), do: {1, ~s({"error":"invalid_arguments"})}
  defp error(:invalid_file), do: {1, ~s({"error":"invalid_file"})}
  defp error(:input_too_large), do: {1, ~s({"error":"input_too_large"})}
  defp error(:invalid_replay), do: {1, ~s({"error":"invalid_replay"})}
  defp error(:execution_failed), do: {1, ~s({"error":"execution_failed"})}
end
