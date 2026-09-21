defmodule TriageWeb.WorkspacePathTest do
  use ExUnit.Case, async: true
  alias TriageWeb.WorkspaceLive

  test "URL generation ignores nested, list, nil and non-string client filters" do
    path =
      WorkspaceLive.workspace_path(%{
        "page" => "inventory",
        "team" => %{"nested" => "x"},
        "q" => ["x"],
        "mode" => 123,
        "environment" => nil,
        "offset" => "0",
        "unknown" => "ignored"
      })

    assert URI.decode_query(URI.parse(path).query) == %{"page" => "inventory", "offset" => "0"}
  end
end
