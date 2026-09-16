defmodule Triage.IntelConfigTest do
  @moduledoc """
  The intel source allowlist is a restriction, not a display of intent:
  `enabled: true` alone authorizes no adapter, and every source must be named.
  """
  use ExUnit.Case, async: false

  alias Triage.Intel.Config

  setup do
    previous = Application.get_env(:triage, :intel)

    on_exit(fn ->
      if previous do
        Application.put_env(:triage, :intel, previous)
      else
        Application.delete_env(:triage, :intel)
      end
    end)

    :ok
  end

  test "runtime response cap defaults to 8MB and accepts only positive integers" do
    Application.delete_env(:triage, :intel)
    assert Config.max_response_bytes() == {:ok, 8_000_000}
    Application.put_env(:triage, :intel, max_response_bytes: 16_000_000)
    assert Config.max_response_bytes() == {:ok, 16_000_000}

    for bad <- [nil, false, 0, -1, 1.5, "8", :infinity] do
      Application.put_env(:triage, :intel, max_response_bytes: bad)
      assert Config.max_response_bytes() == {:error, {:invalid_config, :max_response_bytes}}
    end

    for bad <- [nil, %{}, [:bad]] do
      Application.put_env(:triage, :intel, bad)
      assert Config.max_response_bytes() == {:error, {:invalid_config, :max_response_bytes}}
    end
  end

  test "a source is allowed only when intel is enabled and that source is named" do
    Application.put_env(:triage, :intel, enabled: false, sources: [:kev, :nvd])
    refute Config.source_allowed?(:kev)
    refute Config.source_allowed?(:nvd)

    Application.put_env(:triage, :intel, enabled: true, sources: [])
    refute Config.source_allowed?(:kev)

    Application.put_env(:triage, :intel, enabled: true, sources: [:kev])
    assert Config.source_allowed?(:kev)
    refute Config.source_allowed?(:nvd)

    Application.put_env(:triage, :intel, enabled: true, sources: [:kev, :nvd])
    assert Config.source_allowed?(:nvd)
  end

  test "unknown or malformed sources are never allowed" do
    Application.put_env(:triage, :intel, enabled: true, sources: [:kev, :nvd])

    refute Config.source_allowed?(:news)
    refute Config.source_allowed?("kev")
    refute Config.source_allowed?(nil)
  end

  test "the shipped default authorizes nothing" do
    Application.delete_env(:triage, :intel)

    refute Config.enabled?()
    assert Config.enabled_sources() == []
    refute Config.source_allowed?(:kev)
    refute Config.source_allowed?(:nvd)
  end
end
