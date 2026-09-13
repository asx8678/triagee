defmodule Triage.Replay.CLITest do
  use ExUnit.Case, async: true

  alias Triage.Replay.CLI

  @empty %{
    "format" => "triage.replay",
    "version" => 1,
    "origin" => "synthetic",
    "environment" => "test",
    "engine" => "trivy",
    "owners" => [],
    "inventories" => [],
    "details" => []
  }

  setup do
    root =
      Path.join(System.tmp_dir!(), "pr7-cli-#{System.unique_integer([:positive, :monotonic])}")

    File.mkdir!(root)
    on_exit(fn -> File.rm_rf!(root) end)
    {:ok, root: root}
  end

  test "complete synthetic replay returns a bounded safe summary", %{root: root} do
    path = fixture(root, Jason.encode!(@empty))
    assert {0, json} = CLI.main(["--file", path])
    assert byte_size(json) <= 65_536
    summary = Jason.decode!(json)
    assert summary["format"] == "triage.replay.result"
    assert summary["version"] == 1
    assert summary["origin"] == "synthetic"
    assert summary["complete"] == true
    assert summary["actionable"] == false
    assert summary["inventory_changed"] == false
    assert summary["historical_provenance"] == false
    assert is_map(summary["counts"])
    assert summary["input_sha256"] =~ ~r/\A[0-9a-f]{64}\z/
    refute String.contains?(json, root)
    assert {0, ^json} = CLI.main(["--file", path])
    assert File.ls!(root) == ["input.json"]
  end

  test "missing owner inventory is incomplete, not successful", %{root: root} do
    input = Map.put(@empty, "owners", ["synthetic-owner-private"])
    path = fixture(root, Jason.encode!(input))
    assert {2, json} = CLI.main(["--file", path])
    assert %{"complete" => false, "actionable" => false} = Jason.decode!(json)
    refute String.contains?(json, "synthetic-owner-private")
  end

  test "help is static JSON and only accepted alone" do
    assert {0, json} = CLI.main(["--help"])
    assert %{"format" => "triage.replay.help"} = Jason.decode!(json)

    for args <- [
          [],
          ["--file"],
          ["--file", ""],
          ["--file", "--help"],
          ["--file", "a", "--file", "b"],
          ["--file=a"],
          ["--help", "--help"],
          ["--help", "--file", "a"],
          ["--file", "a", "extra"],
          ["--file", "a", "--endpoint", "https://secret.invalid"],
          ["--endpoint", "https://secret.invalid"],
          ["--file", "a", "--save"],
          ["--history"],
          ["--file", <<0>>],
          ["--", "a"]
        ] do
      assert {1, ~s({"error":"invalid_arguments"})} = CLI.main(args)
    end
  end

  test "invalid JSON and input contents never appear in errors", %{root: root} do
    for body <- ["", "source-id-secret", ~s({"secret":"raw-secret"}), "null"] do
      path = fixture(root, body)
      assert {1, ~s({"error":"invalid_replay"})} = CLI.main(["--file", path])
    end
  end

  test "missing paths, directories, symlinks and devices are rejected", %{root: root} do
    target = fixture(root, Jason.encode!(@empty))
    link = Path.join(root, "link.json")
    File.ln_s!(target, link)

    for path <- [Path.join(root, "missing-secret"), root, link, "/dev/null"] do
      assert {1, ~s({"error":"invalid_file"})} = CLI.main(["--file", path])
    end
  end

  test "input read ceiling includes the exact boundary", %{root: root} do
    json = Jason.encode!(@empty)
    exact = json <> String.duplicate(" ", 1_000_000 - byte_size(json))
    path = fixture(root, exact)
    assert {0, _} = CLI.main(["--file", path])
    File.write!(path, exact <> " ")
    assert {1, ~s({"error":"input_too_large"})} = CLI.main(["--file", path])
  end

  defp fixture(root, body) do
    path = Path.join(root, "input.json")
    File.write!(path, body)
    path
  end
end
