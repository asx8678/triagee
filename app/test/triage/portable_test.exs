defmodule Triage.PortableTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureIO
  alias Triage.Portable

  test "only explicit supported commands can start the server or change data" do
    assert Portable.command([]) == :start

    for command <- ~w(start migrate account secret) do
      assert Portable.command([command]) == String.to_existing_atom(command)
    end

    for args <- [["eval", "anything"], ["migrate", "--force"], ["account", "password"], ["stop"]] do
      assert Portable.command(args) == :invalid
    end
  end

  test "help and version aliases are stable" do
    for flag <- ~w(help --help -h), do: assert(Portable.command([flag]) == :help)
    for flag <- ~w(version --version), do: assert(Portable.command([flag]) == :version)
    assert capture_io(fn -> assert Portable.run(:help) == 0 end) =~ "PostgreSQL"
    assert capture_io(fn -> assert Portable.run(:version) == 0 end) =~ "Triage "
  end

  test "invalid commands fail without echoing input" do
    command = Portable.command(["accidental-secret"])
    output = capture_io(:stderr, fn -> assert Portable.run(command) == 64 end)
    assert output =~ "Usage:"
    refute output =~ "accidental-secret"
  end

  test "secret generation is random and suitable for SECRET_KEY_BASE" do
    generate = fn -> capture_io(fn -> assert Portable.run(:secret) == 0 end) |> String.trim() end
    first = generate.()
    assert byte_size(Base.decode64!(first)) == 64
    refute first == generate.()
  end

  test "ordinary releases stay the default and portable targets cover Linux and macOS" do
    config = Mix.Project.config()
    assert config[:default_release] == :triage
    assert config[:releases][:triage] == []
    targets = config[:releases][:triage_burrito][:burrito][:targets]

    assert targets == [
             linux_x86_64: [os: :linux, cpu: :x86_64],
             linux_arm64: [os: :linux, cpu: :aarch64],
             macos_x86_64: [os: :darwin, cpu: :x86_64],
             macos_arm64: [os: :darwin, cpu: :aarch64]
           ]
  end
end
