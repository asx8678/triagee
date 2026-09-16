defmodule Triage.LintPolicyTest do
  use ExUnit.Case, async: true

  alias Credo.Check.Consistency.TabsOrSpaces
  alias Credo.Check.Refactor.{Apply, CyclomaticComplexity, Nesting}
  alias Credo.ConfigFile

  test "project overrides preserve unrelated default checks" do
    # Exercise Credo's real merge semantics: `enabled` would silently replace
    # the defaults, whereas `extra` keeps them and overrides only named checks.
    defaults = %ConfigFile{checks: %{enabled: [{TabsOrSpaces, []}, {Nesting, []}]}}
    merged = ConfigFile.merge_checks(defaults, %ConfigFile{checks: project_checks()})
    assert Keyword.fetch!(merged.enabled, TabsOrSpaces) == []
    assert Keyword.has_key?(merged.enabled, Apply)
    assert Keyword.has_key?(merged.enabled, CyclomaticComplexity)
    assert Keyword.has_key?(merged.enabled, Nesting)
  end

  test "complexity waivers enumerate existing files rather than future directories" do
    checks = project_checks()
    refute Map.has_key?(checks, :enabled)

    for check <- [Apply, Nesting, CyclomaticComplexity] do
      params = Keyword.fetch!(checks.extra, check)
      paths = Keyword.fetch!(Keyword.fetch!(params, :files), :excluded)
      assert paths != []

      for path <- paths do
        assert is_binary(path)
        refute String.contains?(path, ["*", "?"])
        assert File.regular?(Path.expand("../../#{path}", __DIR__))
      end
    end
  end

  defp project_checks do
    {config, _binding} = Code.eval_file(Path.expand("../../.credo.exs", __DIR__))
    Enum.find(config.configs, &(&1.name == "default")).checks
  end
end
