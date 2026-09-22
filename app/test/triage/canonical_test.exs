defmodule Triage.CanonicalTest do
  use ExUnit.Case, async: true
  alias Triage.Canonical

  defmodule Probe do
    defstruct [:x]
  end

  @evidence_keys ~w(id image_id owner environment namespace active)
  @finding_keys ~w(id package_name package_version severity fix description resolved_at reopen_count first_seen suppressed)

  test "scalars encode unambiguously and self-delimit" do
    assert Canonical.canonical(nil) == "n"
    assert Canonical.canonical(true) == "t"
    assert Canonical.canonical(false) == "f"
    assert Canonical.canonical(:id) == "a2:id"
    assert Canonical.canonical("id") == "s2:id"
    assert Canonical.canonical(1) == "i1:1"
    assert Canonical.canonical(-123) == "i4:-123"
    assert Canonical.canonical(1) != Canonical.canonical(11)
    # Floats are rare in hashed values but must not crash the encoder.
    assert Canonical.hash(1.5) == Canonical.hash(1.5)
    assert Canonical.hash(1.5) != Canonical.hash(2.5)
  end

  test "collections, maps and structs encode in a fixed order" do
    assert Canonical.canonical([1, "x"]) == "l[i1:1,s1:x]"
    assert Canonical.canonical({:ok, 1}) == "p[a2:ok,i1:1]"
    assert Canonical.canonical(%{}) == "m{}"
    assert Canonical.canonical(%{b: 2, a: 1}) == "m{a1:a=i1:1,a1:b=i1:2}"
    assert Canonical.canonical(%Probe{x: 1}) =~ "Elixir.Triage.CanonicalTest.Probe"
    refute Canonical.hash(%{:"a,b" => 1}) == Canonical.hash(%{:a => "b"})
  end

  test "timestamps always carry six fractional digits" do
    assert Canonical.canonical(~U[2026-09-22T03:58:21Z]) == "w2026-09-22T03:58:21.000000Z"
    assert Canonical.canonical(~U[2026-09-22T03:58:21.079321Z]) == "w2026-09-22T03:58:21.079321Z"
    assert Canonical.canonical(~N[2026-09-22T03:58:21]) == "v2026-09-22T03:58:21.000000"
    assert Canonical.canonical(~D[2026-09-22]) == "d2026-09-22"

    assert Canonical.hash(~U[2026-09-22T03:58:21Z]) ==
             Canonical.hash(~U[2026-09-22T03:58:21.000000Z])
  end

  test "the version domains the digest" do
    refute Canonical.hash("x") == Base.encode16(:crypto.hash(:sha256, "x"), case: :lower)
  end

  test "workspace evidence hash is identical across VM atom creation orders" do
    ebin = :code.which(Triage.Workspace) |> List.to_string() |> Path.dirname()

    forward = subprocess_hash(ebin, "forward")
    reverse = subprocess_hash(ebin, "reverse")

    # Under the old term_to_binary encoding these two fresh VMs disagreed.
    assert forward == reverse
    assert forward == Triage.Workspace.hash(sample_evidence())
  end

  defp subprocess_hash(ebin, mode) do
    code = """
    [mode] = System.argv()
    keys = #{inspect(@evidence_keys ++ @finding_keys)}
    keys = if mode == "reverse", do: Enum.reverse(keys), else: keys
    Enum.each(keys, &String.to_atom/1)
    atom = fn name -> String.to_existing_atom(name) end
    placement =
      Map.new(
        [{"id", 11}, {"image_id", 7}, {"owner", "audit"}, {"environment", "prod"}, {"namespace", "default"}, {"active", true}],
        fn {key, value} -> {atom.(key), value} end
      )
    finding =
      Map.new(
        [{"id", 42}, {"package_name", "lib"}, {"package_version", "1.0"}, {"severity", "HIGH"},
         {"fix", nil}, {"description", "synthetic"}, {"resolved_at", nil}, {"reopen_count", 0},
         {"first_seen", ~U[2026-09-22T03:58:21Z]}, {"suppressed", false}],
        fn {key, value} -> {atom.(key), value} end
      )
    evidence = {placement, "sha256:synthetic", [finding]}
    workspace = Module.concat(["Triage", "Workspace"])
    IO.write(apply(workspace, :hash, [evidence]))
    """

    case System.cmd(System.find_executable("elixir"), ["-pa", ebin, "-e", code, "--", mode],
           stderr_to_stdout: true
         ) do
      {output, 0} -> String.trim(output)
      {output, status} -> flunk("hash subprocess exited #{status}: #{output}")
    end
  end

  defp sample_evidence do
    placement = %{
      id: 11,
      image_id: 7,
      owner: "audit",
      environment: "prod",
      namespace: "default",
      active: true
    }

    finding = %{
      id: 42,
      package_name: "lib",
      package_version: "1.0",
      severity: "HIGH",
      fix: nil,
      description: "synthetic",
      resolved_at: nil,
      reopen_count: 0,
      first_seen: ~U[2026-09-22T03:58:21Z],
      suppressed: false
    }

    {placement, "sha256:synthetic", [finding]}
  end
end
