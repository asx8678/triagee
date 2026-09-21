defmodule TriageWeb.LegacyUICase do
  @moduledoc """
  Explicit opt-in for retained legacy UI regression tests, not public-route tests.

  Reuses ConnCase's sandbox/connection setup without changing its default endpoint.
  Workspace, cutover, authentication, session and asset tests use ConnCase directly.
  Both this helper and its router/adapter are compiled only from test/support.
  """
  defmacro __using__(opts) do
    quote do
      use TriageWeb.ConnCase, unquote(opts)
      @endpoint TriageWeb.LegacyUIEndpoint
      @moduletag :legacy_ui
    end
  end
end
