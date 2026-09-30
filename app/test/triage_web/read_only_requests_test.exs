defmodule TriageWeb.ReadOnlyRequestsTest do
  @moduledoc """
  Boundary test for the read-only requirement of the intelligence plan: ordinary GET
  requests must never reach the network and must never write to the database.

  Network access is asserted structurally, not by observation. With the default
  configuration the intel client's own default transport is
  `fn _url -> {:error, :intel_disabled} end`, so a request-time fetch is impossible
  rather than merely unobserved. Writes are asserted by a whole-database row-count
  fingerprint taken before and after rendering the read routes.
  """
  use TriageWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Triage.{Intel, Repo, Seeds}

  @moduletag authenticated: :viewer

  # Every workspace page, plus a CVE detail. News is excluded: it fetches public
  # sources, and only for reviewers, never for this viewer.
  @live_routes [
    "/",
    "/?page=findings",
    "/?page=review&item=CVE-2026-60002",
    "/?page=inventory",
    "/?page=overview",
    "/?page=exceptions",
    "/?page=daily",
    "/timeline"
  ]

  setup do
    Triage.DataCase.reset_inventory!()
    :ok = Seeds.seed()
    :ok
  end

  test "the default intel transport cannot reach the network" do
    refute Intel.Config.enabled?()
    assert Intel.Config.enabled_sources() == []
    assert Intel.Client.fetch(:kev) == {:error, :intel_disabled}
    assert Intel.Client.fetch({:nvd, "CVE-2026-57236"}) == {:error, :intel_disabled}
  end

  test "every read route leaves every table unchanged", %{conn: conn} do
    before = table_fingerprint()

    assert conn |> get(~p"/") |> html_response(200)

    for path <- @live_routes do
      assert {:ok, _view, _html} = live(conn, path)
    end

    after_fingerprint = table_fingerprint()

    assert after_fingerprint == before

    # A refresh always records a receipt, so an unchanged receipt count is direct
    # evidence that no refresh ran while these requests were served.
    assert after_fingerprint["intel_refresh_receipts"] == before["intel_refresh_receipts"]
  end

  defp table_fingerprint do
    %{rows: rows} = Repo.query!("select tablename from pg_tables where schemaname = 'public'")

    rows
    |> List.flatten()
    |> Enum.reject(&(&1 == "schema_migrations"))
    |> Map.new(fn table -> {table, count_rows(table)} end)
  end

  defp count_rows(table) do
    %{rows: [[count]]} = Repo.query!("select count(*) from \"#{table}\"")
    count
  end
end
